"""HAR-1: the standard agent loop, with the loop in code: propose a step, check it, run it guarded, record it, repeat.

    loop = AgentLoop(tools=[ToolSpec("lookup_order", lookup, "reads", output="trusted"),
                            ToolSpec("issue_refund", refund, "acts", control={"to": "email"})],
                     proposer=model, planner=model, budget=Budget(steps=20, cost=2.0, seconds=600))
    loop.register(engine, "support")             # a durable workflow: resumable, every step journaled
    run_id = engine.start("support", {"request": "Refund order A-1 to dana@example.com", "requester": "dana"})
    engine.run(run_id)

The model proposes each step as a typed reading (Step: a tool and its arguments, or done with an answer). Code decides:
a malformed proposal is no step (it counts against the budget, fail safe); a tool not declared is refused; every call,
reads included, goes through the Guard gate (shio.guard: the blind plan from the request, provenance of every control
value), so an unplanned act is denied and a held one waits for a person (durably). Results are recorded into the
Guard's ledger, so later calls are judged against what tools really returned. The loop stops when the model says done,
or at its budget: a step cap, a cost cap (per proposal and per tool call), a time cap, or a stop(history) function.

The final answer goes through the Guard's reply check: names and addresses it contains that only untrusted text held
are reported, not hidden. There is no .shio syntax for this loop yet (SPEC.md has none); it is Python over the
existing guard and the durable engine, so it adds no path around either.
"""
import dataclasses
import functools
import json
from typing import Optional

from pydantic import BaseModel, Field, ValidationError

from ..durable.engine import GateRefused, Policy


class Scripted:
    """A resume-safe scripted model for tests, demos and templates: the next step is steps[len(history)], read from
    the prompt, so a fresh process continues the script where the journal left off (an iterator would restart)."""

    def __init__(self, steps, name="scripted"):
        self.steps, self.name = list(steps), name

    def identity(self):
        return {"kind": "scripted", "name": self.name, "steps": len(self.steps)}

    def propose(self, req):
        try:
            n = len(json.loads(req).get("history", []))
        except (ValueError, AttributeError):
            n = 0
        step = self.steps[min(n, len(self.steps) - 1)]
        return step if isinstance(step, str) else json.dumps(step)


class Step(BaseModel):
    """One proposed step: call `tool` with `args`, or finish with `answer`."""
    tool: Optional[str] = None
    args: dict = Field(default_factory=dict)
    done: bool = False
    answer: Optional[str] = None
    why: Optional[str] = None


@dataclasses.dataclass
class ToolSpec:
    name: str
    fn: object
    kind: str = "reads"                      # reads | acts
    description: str = ""
    output: str = "untrusted"                # what its results are: untrusted unless the system's own record
    control: dict = None                     # Guard control arguments {arg: kind}
    content: tuple = ()
    opens_address: bool = False
    cost: float = 0.0
    policy: Policy = None                    # DUR-6; default: reads retry, acts don't

    def __post_init__(self):
        if self.kind not in ("reads", "acts"):
            raise ValueError(f"{self.name}: kind must be reads or acts")

    def guard_tool(self):
        from .. import guard
        return guard.Tool(self.name, description=self.description, side_effect=self.kind == "acts",
                          output=self.output, control=self.control or {}, content=list(self.content),
                          opens_address=self.opens_address)


@dataclasses.dataclass(frozen=True)
class Budget:
    steps: int = 20
    cost: float = None
    seconds: float = None
    proposal_cost: float = 0.0


class GuardGate:
    """The engine's gate over a Guard session: decide(tool, args, approval) -> (outcome, why, meta); record(...)."""

    def __init__(self, session, unattended=False, allow=None, approvers=("operator",), deadline_seconds=None):
        self.session, self.unattended, self.allow = session, unattended, allow
        self.approvers, self.deadline = set(approvers), deadline_seconds

    def decide(self, tool, args, approval=None):
        d = self.session.check(tool, args)
        side_effect = self.session.guard.tools.get(tool) is not None and self.session.guard.tools[tool].side_effect
        if d.outcome == "run" and self.unattended and side_effect and not (self.allow and self.allow(tool, args)):
            # HAR-7: an unattended run holds every act unless a rule allows it
            if approval:
                return "run", f"approved by {approval['by']} (unattended run)", {}
            return "hold", "unattended run: acts need a rule or a person", {"approvers": self.approvers,
                                                                            "deadline_seconds": self.deadline}
        if d.outcome == "hold":
            if approval:
                try:
                    a = self.session.approve(d.id, approval["by"], approval.get("note", ""))
                except PermissionError as e:
                    return "hold", str(e), {"hold_id": d.id, "approvers": self.approvers}
                return a.outcome, a.why, {}
            return "hold", d.why, {"hold_id": d.id, "approvers": self.approvers, "deadline_seconds": self.deadline}
        return d.outcome, d.why, {}

    def record(self, tool, args, result):
        self.session.record(tool, args, result)


class AgentLoop:
    def __init__(self, tools, proposer, planner=None, budget=Budget(), stop=None, unattended=False, allow=None,
                 approvers=("operator",), system="", deadline_seconds=None):
        self.tools = {t.name: t for t in tools}
        self.proposer, self.planner = proposer, planner or proposer
        self.budget, self.stop, self.system = budget, stop, system
        self.unattended, self.allow, self.approvers, self.deadline = unattended, allow, approvers, deadline_seconds

    def register(self, engine, name):
        def workflow(ctx, inp):
            return self.run(ctx, inp)
        workflow.__qualname__ = f"AgentLoop:{name}"
        from ..durable.engine import workflow_sha
        engine.register(workflow, name, version=self.version())
        return workflow

    def version(self):
        """The loop's identity for DUR-8: its tools, budget and the code of this module."""
        import hashlib
        import inspect
        src = inspect.getsource(AgentLoop) + json.dumps(
            {n: [t.kind, t.output, t.control, list(t.content)] for n, t in sorted(self.tools.items())},
            sort_keys=True) + repr(self.budget)
        return hashlib.sha256(src.encode()).hexdigest()

    def _prompt(self, request, history):
        menu = "\n".join(f"- {t.name} ({t.kind}): {t.description}" for t in self.tools.values())
        return json.dumps({"system": self.system, "request": request, "tools": menu, "history": history,
                           "answer_with": "JSON: {\"tool\": name, \"args\": {...}} or {\"done\": true, \"answer\": ...}"},
                          default=str)

    def run(self, ctx, inp):
        from .. import guard
        planner = ctx.model(self.planner, "planner")
        g = guard.Guard([t.guard_tool() for t in self.tools.values()], planner)
        session = g.start(inp["request"], records=inp.get("records", ()), requester=inp.get("requester"))
        gate = GuardGate(session, self.unattended, self.allow, self.approvers, self.deadline)
        history, cost = [], 0.0
        t0 = ctx.now()
        for i in range(self.budget.steps):
            if self.budget.seconds is not None and ctx.now() - t0 > self.budget.seconds:
                return {"status": "stopped", "why": "time budget", "steps": i, "history": history}
            if self.budget.cost is not None and cost + self.budget.proposal_cost > self.budget.cost:
                return {"status": "stopped", "why": "cost budget", "steps": i, "history": history}
            raw = ctx.read("propose", self.proposer.propose, self._prompt(inp["request"], history))
            cost += self.budget.proposal_cost
            try:
                step = Step.model_validate_json(raw) if isinstance(raw, str) else Step.model_validate(raw)
            except (ValidationError, ValueError):
                history.append({"step": i, "refused": "the proposal was not a valid step (no reading: nothing ran)"})
                continue
            if step.done:
                flagged = session.reply(step.answer or "")
                return {"status": "done", "answer": step.answer, "steps": i + 1, "history": history,
                        "untrusted_entities": flagged}
            spec = self.tools.get(step.tool)
            if spec is None:
                history.append({"step": i, "tool": step.tool, "refused": "not a declared tool"})
                continue
            if self.budget.cost is not None and cost + spec.cost > self.budget.cost:
                return {"status": "stopped", "why": "cost budget", "steps": i, "history": history}
            fn = functools.partial(spec.fn, _session=session) if getattr(spec, "needs_session", False) else spec.fn
            try:
                result = ctx.act(spec.name, step.args, fn, gate=gate,
                                 policy=spec.policy or (Policy.read() if spec.kind == "reads" else Policy()))
                cost += spec.cost
                history.append({"step": i, "tool": spec.name, "args": step.args, "result": result})
            except GateRefused as e:
                history.append({"step": i, "tool": spec.name, "args": step.args, "refused": e.why})
            if self.stop and self.stop(history):
                return {"status": "stopped", "why": "stop condition", "steps": i + 1, "history": history}
        return {"status": "stopped", "why": "step budget", "steps": self.budget.steps, "history": history}
