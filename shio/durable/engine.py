"""The durable engine (DUR-2 to DUR-8): runs that survive a crash, a restart or a three-day wait for an approver, with no
model call or side effect repeated.

    eng = Engine(Journal("runs.db"), records="records/")
    @eng.workflow("refunds")
    def refunds(ctx, inp):
        plan = ctx.read("plan", model.propose, inp["request"])          # journaled: replayed, never re-asked
        ctx.wait(seconds=120)                                             # a timer that survives restarts
        return ctx.act("issue_refund", {"order": "A-1"}, issue_refund, gate=gate)   # gated, idempotent
    run_id = eng.start("refunds", {"request": "..."})
    eng.run(run_id)       # -> "completed" | "waiting" | "held" | "failed"; call again (any process) to resume

How it works: event sourcing. A workflow is ordinary deterministic Python; every non-deterministic thing it does goes
through the context: ctx.read (a model call or any read), ctx.act (a tool call through the gate), ctx.wait (a timer),
ctx.now (the clock). Each is journaled before and after. Resuming re-executes the workflow from the top: everything
already journaled is answered from the journal, and execution continues at the first unfinished step.

Side effects (DUR-3): a guarded call gets an idempotency key from the run, the step and the arguments, passed to the
tool if it accepts `idempotency_key`. The journal marks it started and completed. A call started but never completed
(a crash between the payment and its record) is held for a person, never silently retried: they say whether it
happened (resolve(..., "completed", result)) or not ("not_done", which allows exactly one more attempt).

The gate: every ctx.act asks the gate first (run, hold or deny). On replay the gate is asked again for steps already
done, so a stateful gate such as a Guard session rebuilds its state (its plan and what each tool returned) exactly; a
replayed decision that differs from the journaled one stops the run (non-determinism), never continues it.

Approvals (DUR-4): a held call suspends the run with status held; approve() or reject() (from any process, the CLI or
a gateway) appends the person's decision and makes the run runnable again. A hold may carry a deadline after which it
is denied. Timers (DUR-5): ctx.wait stores its fire time in the journal; the run waits (status waiting, wake_at) and
the timer fires exactly once. Retries (DUR-6): reads retry with backoff; acts follow their declared policy, default no
retry, and a failing act is held with its error recorded. Versioning (DUR-8): a run pins its workflow's sha256 and only
continues on that version; moving it is an explicit migrate() entry. When a run completes, a signed ledger record is
derived from the journal (DUR-1), and derive_record() reproduces it exactly.
"""
import dataclasses
import hashlib
import inspect
import json
import time
import uuid

from ..ledger import _same_person, sha256
from .journal import JournalError

RUN_FORMAT = "shio-run/1"


class Suspend(BaseException):
    """Raised inside a workflow to stop it until something happens. BaseException so `except Exception` in workflow
    code can't swallow it."""

    def __init__(self, status, wake_at=None, note=None):
        super().__init__(note or status)
        self.status, self.wake_at, self.note = status, wake_at, note


class Crash(BaseException):
    """Fault injection: simulates the process dying at a step boundary (tests only)."""


class GateRefused(Exception):
    """A tool call the gate denied, or a person rejected. The workflow may catch it and carry on."""

    def __init__(self, tool, why):
        super().__init__(f"{tool}: {why}")
        self.tool, self.why = tool, why


class NonDeterminism(JournalError):
    pass


class VersionMismatch(JournalError):
    pass


@dataclasses.dataclass(frozen=True)
class Policy:
    """DUR-6, per tool or read: retries with exponential backoff, a timeout (seconds) per attempt."""
    retries: int = 0
    backoff: float = 0.5
    timeout: float = None

    @classmethod
    def read(cls):
        return cls(retries=3, backoff=0.2)


def _sha_of(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def workflow_sha(fn):
    try:
        src = inspect.getsource(fn)
    except (OSError, TypeError):
        src = getattr(fn, "__qualname__", repr(fn))
    return hashlib.sha256(src.encode()).hexdigest()


class Context:
    def __init__(self, engine, run, events, owner):
        self.engine, self.run_id, self.owner = engine, run["id"], owner
        self.input = run["input"]
        self.workflow = run["workflow"]
        self.op = 0
        self.by_op = {}
        for e in events:
            if e["op"] is not None:
                self.by_op.setdefault(e["op"], []).append(e)
        self.strict = False                  # replay only: needing a new event is a determinism failure

    # ---------------- plumbing ----------------
    def _next(self, name):
        self.op += 1
        evs = self.by_op.get(self.op, [])
        if evs and evs[0]["name"] != name:
            raise NonDeterminism(f"step {self.op}: the journal has {evs[0]['name']!r} here, the code asked for {name!r}")
        return self.op

    def _ev(self, op, kind):
        return next((e for e in self.by_op.get(op, []) if e["kind"] == kind), None)

    def _append(self, kind, op, name, key=None, payload=None):
        if self.strict:
            raise NonDeterminism(f"replay of step {op} ({name}) needed a new {kind} event: the run doesn't replay "
                                 f"from its journal")
        e = self.engine.journal.append(self.run_id, kind, op, name, key, payload, owner=self.owner)
        self.by_op.setdefault(op, []).append(e)
        self.engine._fault(kind, op, self)
        return e

    # ---------------- the clock ----------------
    def now(self):
        op = self._next("clock")
        e = self._ev(op, "clock")
        if e:
            return e["payload"]["t"]
        t = self.engine.clock()
        self._append("clock", op, "clock", payload={"t": t})
        return t

    # ---------------- reads ----------------
    def read(self, name, fn, *args, policy=None, **kwargs):
        """A non-deterministic call whose result is journaled: a model reading, a fetch. Replayed, never repeated."""
        op = self._next(name)
        done = self._ev(op, "read_completed")
        if done:
            return done["payload"]["value"]
        if not self._ev(op, "read_started"):
            self._append("read_started", op, name, payload={"args_sha256": _sha_of([args, kwargs])})
        value = self.engine._attempt(fn, args, kwargs, policy or Policy.read())
        self._append("read_completed", op, name, payload={"value": value})
        return value

    def model(self, inner, name=None):
        """A model backend whose answers are journaled (propose(req) -> text)."""
        return _JournaledModel(self, inner, name or getattr(inner, "name", type(inner).__name__))

    # ---------------- acts ----------------
    def act(self, tool, args, fn, gate=None, policy=None):
        """A tool call through the gate, idempotent. -> the tool's result. Raises GateRefused on deny or rejection."""
        args = dict(args or {})
        op = self._next(tool)
        key = _sha_of([self.run_id, op, tool, args])
        approved, rejected = self._ev(op, "approved"), self._ev(op, "rejected")
        completed, started = self._ev(op, "act_completed"), self._ev(op, "act_started")
        gated = self._ev(op, "gated")
        # ask the gate (again, on replay) so its state is rebuilt; compare with what was journaled
        decision = gate.decide(tool, args, approval=approved["payload"] if approved else None) if gate else \
            ("run", "no gate")
        outcome, why = decision[0], decision[1]
        meta = decision[2] if len(decision) > 2 else {}
        if gated is None:
            self._append("gated", op, tool, key, {"outcome": outcome, "why": why, "approval": bool(approved)})
        elif gated["payload"]["outcome"] != outcome and not (approved and outcome == "run"):
            raise NonDeterminism(f"step {op} ({tool}): the gate said {gated['payload']['outcome']} before and "
                                 f"{outcome} now")
        if completed:
            if gate:
                gate.record(tool, args, completed["payload"]["result"])
            return completed["payload"]["result"]
        if rejected:
            self._once(op, "act_denied", tool, key, {"why": f"rejected by {rejected['payload']['by']}"})
            raise GateRefused(tool, f"rejected by {rejected['payload']['by']}")
        if outcome == "deny":
            self._once(op, "act_denied", tool, key, {"why": why})
            raise GateRefused(tool, why)
        if outcome == "hold" and not approved:
            held = self._ev(op, "held")
            if held is None:
                deadline = meta.get("deadline_seconds")
                self._append("held", op, tool, key, {"why": why, "hold_id": meta.get("hold_id") or key[:12],
                                                     "args": args, "approvers": sorted(meta.get("approvers", [])),
                                                     "deadline": self.engine.clock() + deadline if deadline else None,
                                                     "requester": self.input.get("requester") if isinstance(
                                                         self.input, dict) else None})
                held = self._ev(op, "held")
            dl = held["payload"].get("deadline")
            if dl and self.engine.clock() > dl:
                self._once(op, "act_denied", tool, key, {"why": "the approval deadline passed"})
                raise GateRefused(tool, "the approval deadline passed: denied")
            raise Suspend("held", wake_at=dl, note=f"{tool} held: {why}")
        if started and not completed:
            resolved = self._ev(op, "act_resolved")
            if resolved is None:
                if not self._ev(op, "unknown_outcome"):
                    self._append("unknown_outcome", op, tool, key, {"why": "the call started but its completion was "
                                                                            "never recorded: did it happen?"})
                raise Suspend("held", note=f"{tool}: outcome unknown after a crash; a person must resolve it")
            if resolved["payload"]["outcome"] == "completed":
                result = resolved["payload"].get("result")
                self._append("act_completed", op, tool, key, {"result": result, "resolved_by": resolved["payload"]["by"]})
                if gate:
                    gate.record(tool, args, result)
                return result
            # "not_done": a person confirmed it didn't happen; exactly one more attempt is allowed
            if self._ev(op, "act_retry"):
                raise Suspend("held", note=f"{tool}: already retried once after a crash; a person must resolve it")
            self._append("act_retry", op, tool, key, {"by": resolved["payload"]["by"]})
        elif not started:
            self._append("act_started", op, tool, key, {"args_sha256": _sha_of(args)})
        try:
            kwargs = dict(args)
            if "idempotency_key" in inspect.signature(fn).parameters:
                kwargs["idempotency_key"] = key
            result = self.engine._attempt(fn, (), kwargs, policy or Policy())
        except PermissionError as e:
            # the tool refused before acting (its own scope check): a denial, not an unknown outcome. Tools must raise
            # PermissionError only when nothing happened.
            self._append("act_denied", op, tool, key, {"why": f"refused by the tool: {e}"[:500]})
            raise GateRefused(tool, f"refused by the tool: {e}") from None
        except Exception as e:
            self._append("act_failed", op, tool, key, {"error": f"{type(e).__name__}: {e}"[:500]})
            self._append("unknown_outcome", op, tool, key, {"why": f"the call failed ({type(e).__name__}); acts are "
                                                                    f"not retried automatically"})
            raise Suspend("held", note=f"{tool} failed: {type(e).__name__}") from None
        self._append("act_completed", op, tool, key, {"result": result})
        if gate:
            gate.record(tool, args, result)
        return result

    def _once(self, op, kind, name, key, payload):
        if not self._ev(op, kind):
            self._append(kind, op, name, key, payload)

    # ---------------- timers ----------------
    def wait(self, seconds=None, until=None):
        """DUR-5: wait a duration or until a time (epoch seconds). Survives restarts; fires once."""
        op = self._next("wait")
        if self._ev(op, "timer_fired"):
            return
        st = self._ev(op, "timer_set")
        if st is None:
            fire_at = until if until is not None else self.engine.clock() + float(seconds)
            st = self._append("timer_set", op, "wait", payload={"fire_at": fire_at})
        fire_at = st["payload"]["fire_at"]
        if self.engine.clock() >= fire_at:
            self._append("timer_fired", op, "wait", payload={"fire_at": fire_at})
            return
        raise Suspend("waiting", wake_at=fire_at, note=f"timer until {fire_at}")

    # ---------------- children (HAR-6) ----------------
    def child(self, name, workflow, inp):
        """Start a child run (once) and wait for it. -> its result, as data for the parent."""
        op = self._next(f"child:{name}")
        started = self._ev(op, "child_started")
        if started is None:
            cid = f"{self.run_id}.{op}"
            self.engine.start(workflow, inp, run_id=cid, parent=self.run_id)
            started = self._append("child_started", op, f"child:{name}", payload={"run_id": cid})
        cid = started["payload"]["run_id"]
        done = self._ev(op, "child_completed")
        if done:
            return done["payload"]["result"]
        r = self.engine.journal.run(cid)
        if r["status"] in ("runnable", "waiting"):
            self.engine.run(cid)
            r = self.engine.journal.run(cid)
        if r["status"] == "completed":
            from ..harness.delegate import record_sha
            rec = record_sha(self.engine, cid)
            out = self.engine.result(cid)
            self._append("child_completed", op, f"child:{name}", payload={"run_id": cid, "result": out,
                                                                         "record_sha256": rec})
            return out
        if r["status"] == "failed":
            raise GateRefused(f"child:{name}", f"child run {cid} failed")
        raise Suspend("waiting" if r["status"] == "waiting" else "held", wake_at=r["wake_at"],
                      note=f"child run {cid} is {r['status']}")


class _JournaledModel:
    def __init__(self, ctx, inner, name):
        self.ctx, self.inner, self.name = ctx, inner, name

    def identity(self):
        ident = self.inner.identity() if hasattr(self.inner, "identity") else {"kind": "model", "name": self.name}
        return {**ident, "journaled": True}

    def propose(self, req):
        return self.ctx.read(f"model:{self.name}", self.inner.propose, req)


class Engine:
    def __init__(self, journal, records=None, signer=None, clock=time.time, sleep=time.sleep):
        self.journal, self.records, self.signer, self.clock, self.sleep = journal, records, signer, clock, sleep
        self.workflows = {}
        self.faults = None

    # ---------------- registry ----------------
    def workflow(self, name=None, version=None):
        def deco(fn):
            self.register(fn, name or fn.__name__, version)
            return fn
        return deco

    def register(self, fn, name, version=None):
        self.workflows[name] = (fn, version or workflow_sha(fn))

    # ---------------- runs ----------------
    def start(self, name, inp, run_id=None, parent=None):
        if name not in self.workflows:
            raise JournalError(f"no workflow {name!r}")
        rid = run_id or f"run-{uuid.uuid4().hex[:12]}"
        self.journal.create(rid, name, self.workflows[name][1], inp)
        if parent:
            self.journal.append(rid, "parent", payload={"run_id": parent})
        return rid

    def run(self, run_id, owner=None, ttl=60.0):
        """Run (or resume) until it completes, waits or holds. -> status."""
        owner = owner or f"local-{uuid.uuid4().hex[:6]}"
        got = self.journal.acquire(owner, ttl, run_id=run_id, now=self.clock())
        if got is None:
            r = self.journal.run(run_id)
            return r["status"]
        try:
            return self._run(run_id, owner)
        finally:
            self.journal.release(run_id, owner)

    def _run(self, run_id, owner):
        run = self.journal.run(run_id)
        fn, sha = self.workflows.get(run["workflow"], (None, None))
        if fn is None:
            raise JournalError(f"{run_id}: workflow {run['workflow']!r} is not registered in this process")
        if sha != run["program_sha256"]:
            raise VersionMismatch(f"{run_id} is pinned to {run['workflow']} {run['program_sha256'][:12]}; this "
                                  f"process has {sha[:12]}. Finish it on the old version, or migrate it explicitly")
        ctx = Context(self, run, self.journal.events(run_id), owner)
        try:
            result = fn(ctx, run["input"])
        except Suspend as s:
            self.journal.set_status(run_id, s.status, s.wake_at, s.note, owner=owner)
            return s.status
        except (Crash, NonDeterminism):
            raise
        except Exception as e:
            self.journal.append(run_id, "run_failed", payload={"error": f"{type(e).__name__}: {e}"[:500]}, owner=owner)
            self.journal.set_status(run_id, "failed", note=f"{type(e).__name__}: {e}"[:200], owner=owner)
            return "failed"
        self.journal.append(run_id, "run_completed", payload={"result": result}, owner=owner)
        self.journal.set_status(run_id, "completed", owner=owner)
        self._write_record(run_id)
        return "completed"

    def _attempt(self, fn, args, kwargs, policy):
        import concurrent.futures
        last = None
        for i in range(policy.retries + 1):
            try:
                if policy.timeout:
                    with concurrent.futures.ThreadPoolExecutor(1) as ex:
                        return ex.submit(fn, *args, **kwargs).result(timeout=policy.timeout)
                return fn(*args, **kwargs)
            except Exception as e:
                last = e
                if i < policy.retries:
                    self.sleep(policy.backoff * (2 ** i))
        raise last

    def _fault(self, kind, op, ctx):
        if self.faults:
            self.faults(kind, op, ctx)

    # ---------------- people (DUR-4) ----------------
    def held(self, run_id):
        out = []
        evs = self.journal.events(run_id)
        answered = {(e["op"], e["key"]) for e in evs if e["kind"] in ("approved", "rejected", "act_resolved")}
        for e in evs:
            if e["kind"] in ("held", "unknown_outcome") and (e["op"], e["key"]) not in answered:
                out.append({"op": e["op"], "tool": e["name"], "key": e["key"], "kind": e["kind"], **(e["payload"] or {})})
        return out

    def _find_held(self, run_id, hold):
        for h in self.held(run_id):
            if hold in (h.get("hold_id"), h["key"], h["key"][:12]) and h["kind"] == "held":
                return h
        raise JournalError(f"{run_id}: no held call {hold}")

    def approve(self, run_id, hold, by, role, channel="cli", note=""):
        h = self._find_held(run_id, hold)
        if h.get("approvers") and role not in h["approvers"]:
            raise PermissionError(f"needs approval by {', '.join(h['approvers'])}, not {role}")
        if h.get("requester") and _same_person(by, h["requester"]):
            raise PermissionError(f"{by} asked for this run, so can't approve its held calls (four eyes)")
        self.journal.append(run_id, "approved", h["op"], h["tool"], h["key"],
                            {"by": by, "role": role, "channel": channel, "note": note, "call_key": h["key"]})
        self.journal.set_status(run_id, "runnable")

    def reject(self, run_id, hold, by, role, channel="cli", note=""):
        h = self._find_held(run_id, hold)
        self.journal.append(run_id, "rejected", h["op"], h["tool"], h["key"],
                            {"by": by, "role": role, "channel": channel, "note": note})
        self.journal.set_status(run_id, "runnable")

    def resolve(self, run_id, key, outcome, by, result=None, note=""):
        """A person settles a call whose outcome is unknown: "completed" (it happened; give its result) or
        "not_done" (it didn't; one more attempt is allowed)."""
        if outcome not in ("completed", "not_done"):
            raise ValueError("outcome must be completed or not_done")
        h = next((x for x in self.held(run_id) if x["kind"] == "unknown_outcome" and key in (x["key"], x["key"][:12])),
                 None)
        if h is None:
            raise JournalError(f"{run_id}: no call with an unknown outcome under {key}")
        self.journal.append(run_id, "act_resolved", h["op"], h["tool"], h["key"],
                            {"outcome": outcome, "by": by, "result": result, "note": note})
        self.journal.set_status(run_id, "runnable")

    def migrate(self, run_id, by, reason, workflow=None):
        """DUR-8: move a run to the workflow version registered now, as an explicit, recorded step."""
        run = self.journal.run(run_id)
        name = workflow or run["workflow"]
        new = self.workflows[name][1]
        self.journal.append(run_id, "migrated", payload={"from": run["program_sha256"], "to": new, "by": by,
                                                         "reason": reason})
        self.journal.set_program(run_id, new)

    def replay(self, run_id):
        """Re-execute a finished run from its journal alone: no model call, no tool call, no new event. -> its result
        (equal to the journaled one), or NonDeterminism."""
        run = self.journal.run(run_id)
        fn, sha = self.workflows[run["workflow"]]
        if sha != run["program_sha256"]:
            raise VersionMismatch("replay with a changed program is impact analysis (shio impact), not replay")
        ctx = Context(self, run, self.journal.events(run_id), owner=None)
        ctx.strict = True
        out = fn(ctx, run["input"])
        if sha256(out) != sha256(self.result(run_id)):
            raise NonDeterminism(f"{run_id}: replay gave a different result")
        return out

    # ---------------- results and records ----------------
    def result(self, run_id):
        e = next((x for x in reversed(self.journal.events(run_id)) if x["kind"] == "run_completed"), None)
        return e["payload"]["result"] if e else None

    def derive_record(self, run_id):
        """The run's ledger record, derived from its journal: the same journal always gives the same record."""
        run = self.journal.run(run_id)
        evs = self.journal.events(run_id)
        end = next((i for i, e in enumerate(evs) if e["kind"] == "run_completed"), None)
        if end is not None:
            evs = evs[:end + 1]                       # what came after completion (the ledger note) isn't the run
        steps = [{"op": e["op"], "kind": e["kind"], "name": e["name"], "key": e["key"],
                  "payload_sha256": sha256(e["payload"]) if e["payload"] is not None else None,
                  **({"outcome": e["payload"]["outcome"]} if e["kind"] == "gated" else {}),
                  **({"by": e["payload"]["by"], "channel": e["payload"].get("channel")}
                     if e["kind"] in ("approved", "rejected", "act_resolved") else {})}
                 for e in evs if e["kind"] not in ("run_completed",)]
        done = next((e for e in evs if e["kind"] == "run_completed"), None)
        started = evs[0]["time"] if evs else None
        return {"record_type": "harness_run", "run_format": RUN_FORMAT, "agent": run["workflow"], "run_id": run_id,
                "program": {"sha256": run["program_sha256"]}, "input_sha256": sha256(run["input"]),
                "started": started, "ended": done["time"] if done else None, "steps": steps,
                "outcome": {"status": "COMPLETED" if done else run["status"].upper(),
                            "result_sha256": sha256(done["payload"]["result"]) if done else None},
                "journal_head": evs[-1]["sha256"] if evs else None, "checks": [], "readings": [], "children": []}

    def _write_record(self, run_id):
        if not self.records:
            return None
        from ..ledger import write
        path = write(self.derive_record(run_id), self.records, run_id, use_vault=False, signer=self.signer)
        self.journal.append(run_id, "ledger_written", payload={"file": str(path.name)})
        return path

    def records_for(self, run_id):
        e = next((x for x in self.journal.events(run_id) if x["kind"] == "ledger_written"), None)
        return e["payload"]["file"] if e else None


class Worker:
    """DUR-7: takes runnable runs (and waiting runs whose timer is due) from the journal, one lease at a time."""

    def __init__(self, engine, name=None, ttl=30.0):
        self.engine, self.name, self.ttl = engine, name or f"worker-{uuid.uuid4().hex[:6]}", ttl

    def run_once(self):
        rid = self.engine.journal.acquire(self.name, self.ttl, now=self.engine.clock())
        if rid is None:
            return None
        try:
            return rid, self.engine._run(rid, self.name)
        finally:
            self.engine.journal.release(rid, self.name)

    def drain(self, limit=1000):
        out = []
        for _ in range(limit):
            r = self.run_once()
            if r is None:
                break
            out.append(r)
        return out
