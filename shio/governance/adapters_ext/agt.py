"""Microsoft Agent Governance Toolkit (AGT) as a Shio Guard policy backend (D31, D32).

AGT (github.com/microsoft/agent-governance-toolkit, MIT) is a deterministic policy engine for agent actions: YAML
policies of rules, each a condition over the action and its arguments with an effect (allow, deny, warn, log,
require_approval). Shio Guard uses it in three places, without giving up any of its own rules:

  AgtBackend      the engine behind Shio's PolicyBackend interface (like CedarBackend and OpaBackend): decide()
                  returns a frozen AgtDecision; allowed() is the yes/no. Fail safe: a policy that won't load is
                  refused when the backend is built, and an engine error at decision time is a denial, never a pass.
  AgtGate         AGT's policy on any agent's tool calls, Shio or not, layered after Shio Guard's provenance gate
                  when a Guard session is given (defence in depth: either one can stop a call). Every decision is a
                  signed, hash-chained entry in a Shio ledger (SignedChain "agt-gate"), so the console and evidence
                  bundles see AGT's decisions next to Shio's. require_approval becomes a person's approval bound to
                  the exact call (its digest), with maker-checker: the agent's requester can't approve its own call.
  AgtPolicyCheck  the same decision as a check adapter (trust class check): pinned, reviewed, with fixtures, so it
                  can stand in a `check` and an agent card names the engine and its version.

  import_audit(audit_log)  AGT's own audit log (agentmesh.governance.AuditLog), its hash chain verified, as plain
                           dicts for the console and for evidence.

AGT conditions see the same context AGT's own govern() builds: {"action": {"type": <tool>}, <arg>: {"value": v}}
for a plain argument and <arg>: {...} for a dict, so a policy written for AGT works unchanged here.

Install: pip install "shio-lang[agt]" (AGT needs Python 3.11 or later). Limits: AGT evaluates in the same process
as the agent (its README says so too); its rate limits, execution rings, trust scoring and SRE features are not
used here; and require_approval is resolved by Shio's approver, not AGT's approval handlers.
"""
import dataclasses
import hashlib
import json
import os
import re
import time
from pathlib import Path

from ..adapters import CheckAdapter, Dependency, Manifest, TrustClass
from ..cedar import PolicyBackend
from ..chain import SignedChain
from ...ledger import _same_person

AGT_DIST, AGT_VERSION = "agent-governance-toolkit-core", "5.0.0"
EFFECTS = ("allow", "deny", "warn", "log", "require_approval")


class AgtUnavailable(ImportError):
    pass


class AgtDenied(PermissionError):
    """A tool call that AGT's policy (or the Guard in front of it) did not allow. .decision says why."""

    def __init__(self, action, decision):
        self.action, self.decision = action, decision
        super().__init__(f"{action}: {decision.explain()}")


def _engine_module():
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from agentmesh.governance import policy as agt_policy
        return agt_policy
    except ImportError as e:
        raise AgtUnavailable("the Microsoft Agent Governance Toolkit is not installed: pip install "
                             "\"shio-lang[agt]\" (it needs Python 3.11 or later)") from e


def installed_version():
    try:
        from importlib.metadata import version
        return version(AGT_DIST)
    except Exception:
        return None


@dataclasses.dataclass(frozen=True)
class AgtDecision:
    """One AGT decision, normalised. Frozen: a decision is evidence, so nothing edits it after the fact."""
    allowed: bool
    effect: str                     # allow | deny | warn | log | require_approval | error
    rule: str = None
    policy: str = None
    reason: str = ""
    approvers: tuple = ()
    engine_ms: float = None
    layer: str = "agt"              # which layer decided: "agt", or "guard" when Shio Guard stopped it first

    @classmethod
    def from_agt(cls, d):
        effect = d.action if d.action in EFFECTS else "deny"
        # AGT already reports require_approval as not allowed; keep it that way until a person approves
        return cls(allowed=bool(d.allowed) and effect != "require_approval", effect=effect, rule=d.matched_rule,
                   policy=d.policy_name, reason=d.reason or "", approvers=tuple(d.approvers or ()),
                   engine_ms=d.evaluation_ms)

    @classmethod
    def error(cls, err):
        return cls(False, "error", reason=f"policy engine error ({type(err).__name__}): denied")

    def explain(self):
        if self.allowed:
            return f"allowed{f' by {self.rule}' if self.rule else ''}"
        if self.effect == "require_approval":
            return f"needs approval by {', '.join(self.approvers) or 'a person'} (rule {self.rule})"
        return f"{'stopped by Shio Guard' if self.layer == 'guard' else 'denied'}" \
               f"{f' by {self.rule}' if self.rule else ''}: {self.reason}"

    def to_dict(self):
        d = dataclasses.asdict(self)
        d["approvers"] = list(self.approvers)
        return d


def context_for(action, kwargs):
    """The evaluation context AGT's govern() would build for a call: plain values are wrapped as {"value": v}."""
    ctx = {"action": dict(action) if isinstance(action, dict) else {"type": str(action)}}
    for k, v in kwargs.items():
        if k != "action":
            ctx[k] = v if isinstance(v, dict) else {"value": v}
    return ctx


class AgtBackend(PolicyBackend):
    """AGT's PolicyEngine behind Shio's PolicyBackend. policies: a YAML file path, a YAML string, or a list of
    either. A policy that names no agents applies to every agent (as AGT's govern() does).

    strict (the default) adds Shio's fail-safe rule on top of AGT, which can only tighten a decision:
      at load      a rule whose condition AGT's evaluator can't parse is refused (AGT would treat it as never
                   matching, so a deny rule written that way would silently never deny);
      at decision  when AGT allows a call, each deny / require_approval rule is evaluated again in three-valued
                   logic. AGT reads a missing number as 0 and a non-number as "no match", so `amount.value > 500`
                   would let a refund with no amount through; here a rule that can't be ruled out denies.
    """

    def __init__(self, policies, conflict_strategy="deny_overrides", agent_id="*", strict=True):
        mod = _engine_module()
        self.strict, self._strict = strict, []
        self.engine = mod.PolicyEngine(conflict_strategy=conflict_strategy)
        self.agent_id, self.conflict_strategy = agent_id, conflict_strategy
        self.policies, digest = [], hashlib.sha256()
        for src in policies if isinstance(policies, (list, tuple)) else [policies]:
            text = Path(src).read_text() if _is_file(src) else str(src)
            try:
                pol = mod.Policy.from_yaml(text, base_dir=str(Path(src).parent) if _is_file(src) else "")
            except Exception as e:                     # a policy that doesn't load is refused, not ignored
                raise ValueError(f"AGT policy {str(src)[:60]!r} does not load: {e}") from e
            if not pol.agent and not pol.agents:
                pol.agents = ["*"]
            if strict:                                 # every restrictive rule must be one AGT can match
                for r in pol.rules:
                    try:
                        compiled = Condition.compile(r.condition)
                    except ValueError as e:
                        raise ValueError(f"AGT policy {pol.name}, rule {r.name}: {e}. AGT would never match it, "
                                         f"so it could never stop a call; write it with ==, !=, in [...], a number "
                                         f"comparison or a field name, joined by and / or") from e
                    if r.action in RESTRICTIVE and r.enabled:
                        self._strict.append((pol, r, compiled))
            self.engine.load_policy(pol)
            self.policies.append(pol)
            digest.update(text.encode())
        self.sha256 = digest.hexdigest()

    def decide(self, action, context=None, agent=None, stage="pre_tool"):
        ctx = context if context is not None and "action" in context else context_for(action, context or {})
        agent = agent or self.agent_id
        try:
            ctx = json.loads(json.dumps(ctx, default=str))
            d = AgtDecision.from_agt(self.engine.evaluate(agent, ctx, stage=stage))
        except Exception as e:                          # fail safe: an engine failure is a denial
            return AgtDecision.error(e)
        if d.allowed:                                   # Shio only ever tightens AGT's decision, never loosens it
            for pol, rule, cond in self._strict:
                if rule.stage == stage and pol.applies_to(agent) and cond.evaluate(ctx) is None:
                    return AgtDecision(False, rule.action, rule=rule.name, policy=pol.name, approvers=tuple(rule.approvers),
                                       reason=f"fail-safe: {', '.join(cond.unknown(ctx))} missing or unreadable, so "
                                              f"rule {rule.name} ({rule.action}) can't be ruled out",
                                       engine_ms=d.engine_ms, layer="shio-strict")
        return d

    def allowed(self, principal, action, resource, context):
        return self.decide(action, context, agent=_agent_id(principal)).allowed

    def describe(self):
        return {"engine": "microsoft-agt", "version": installed_version(), "sha256": self.sha256,
                "conflict_strategy": self.conflict_strategy,
                "policies": [{"name": p.name, "version": p.version, "default": p.default_action,
                              "rules": [{"name": r.name, "effect": r.action, "stage": r.stage, "condition": r.condition,
                                         "approvers": list(r.approvers), "enabled": r.enabled} for r in p.rules]}
                             for p in self.policies]}


RESTRICTIVE = ("deny", "require_approval")


class Condition:
    """An AGT rule condition compiled once into disjunctive form, Or[And[atom]], split exactly as AGT splits it
    (" or " first, then " and "), and evaluated in three-valued logic: True, False, or None (unknown)."""
    ATOMS = (("eq", re.compile(r"^(\w+(?:\.\w+)*)\s*==\s*['\"]([^'\"]+)['\"]$")),
             ("ne", re.compile(r"^(\w+(?:\.\w+)*)\s*!=\s*['\"]([^'\"]+)['\"]$")),
             ("in", re.compile(r"^(\w+(?:\.\w+)*)\s+in\s+\[([^\]]*)\]$")),
             ("cmp", re.compile(r"^(\w+(?:\.\w+)*)\s*(>=|<=|>|<)\s*(\d+(?:\.\d+)?)$")),
             ("bool", re.compile(r"^(\w+(?:\.\w+)*)$")))
    CMP = {">": float.__gt__, "<": float.__lt__, ">=": float.__ge__, "<=": float.__le__}

    def __init__(self, clauses):
        self.clauses = clauses          # [[(kind, path, arg), ...], ...]: or of ands

    @classmethod
    def compile(cls, text):
        clauses = []
        for part in text.split(" or "):
            atoms = []
            for a in part.strip().split(" and "):
                a = a.strip()
                for kind, rx in cls.ATOMS:
                    m = rx.match(a)
                    if m:
                        g = m.groups()
                        arg = [x.strip().strip("'\"") for x in g[1].split(",") if x.strip()] if kind == "in" else \
                            (g[1], float(g[2])) if kind == "cmp" else g[1] if kind in ("eq", "ne") else None
                        atoms.append((kind, g[0], arg))
                        break
                else:
                    raise ValueError(f"condition part {a!r} is not one AGT's evaluator understands")
            clauses.append(atoms)
        return cls(clauses)

    @staticmethod
    def _get(ctx, path):
        cur = ctx
        for part in path.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur

    def _atom(self, kind, path, arg, ctx):
        v = self._get(ctx, path)
        if v is None:
            return None
        if kind == "eq":
            return v == arg
        if kind == "ne":
            return v != arg
        if kind == "in":
            return v in arg
        if kind == "cmp":
            if isinstance(v, bool):
                return None
            try:
                return self.CMP[arg[0]](float(v), arg[1])
            except (TypeError, ValueError):
                return None
        return bool(v)

    def evaluate(self, ctx):
        any_unknown = False
        for atoms in self.clauses:
            vals = [self._atom(*a, ctx) for a in atoms]
            if False in vals:
                continue
            if None in vals:
                any_unknown = True
                continue
            return True
        return None if any_unknown else False

    def unknown(self, ctx):
        return sorted({p for atoms in self.clauses for k, p, a in atoms if self._atom(k, p, a, ctx) is None})


def _is_file(src):
    s = str(src)
    return "\n" not in s and len(s) < 4096 and os.path.isfile(s)


def _agent_id(principal):
    """Cedar-style principal Agent::"helpdesk" -> helpdesk; anything else as given."""
    s = str(principal or "*")
    return s.split("::", 1)[1].strip('"') if "::" in s else s


def call_digest(action, kwargs):
    return hashlib.sha256(json.dumps({"action": action, "args": kwargs}, sort_keys=True, default=str)
                          .encode()).hexdigest()


@dataclasses.dataclass(frozen=True)
class ApprovalRequest:
    action: str
    args: dict
    digest: str
    rule: str
    approvers: tuple
    agent: str
    requester: str


class AgtGate:
    """Enforce AGT policies on any agent's tool calls, with every decision in a signed Shio ledger.

        gate = AgtGate("policy.yaml", ledger="records/gates", agent="helpdesk", requester="intake-bot",
                       approver=lambda req: (True, "M. Chen", "checked the order"))
        refund = gate.wrap(issue_refund)            # raises AgtDenied when the policy (or Guard) says no

    guard: an optional Shio Guard session; its provenance check runs first and AGT's policy second.
    approver: called for require_approval with an ApprovalRequest; returns (approved, by, note). None: refused.
    """

    def __init__(self, policies, ledger=None, agent="*", requester=None, approver=None, guard=None, signer=None,
                 conflict_strategy="deny_overrides", clock=time.time):
        self.clock = clock
        self.backend = policies if isinstance(policies, AgtBackend) else AgtBackend(policies, conflict_strategy)
        self.chain = SignedChain(ledger, "agt-gate") if ledger else None
        self.agent, self.requester, self.approver, self.guard, self.signer = agent, requester, approver, guard, signer
        self.log = []

    def _record(self, action, kwargs, decision, approval=None):
        entry = {"engine": "microsoft-agt", "engine_version": installed_version(), "policy_sha256": self.backend.sha256,
                 "agent": self.agent, "requester": self.requester, "action": action,
                 "call_sha256": call_digest(action, kwargs), "args": sorted(kwargs),   # names only: values may be PHI
                 "decision": decision.to_dict(), "approval": approval, "time": self.clock()}
        if self.chain is not None:
            entry = self.chain.append("gate_decision", entry, self.signer)
        self.log.append(entry)
        return entry

    def decide(self, action, kwargs):
        if self.guard is not None:
            g = self.guard.check(action, kwargs)
            if g.outcome != "run":
                d = AgtDecision(False, "deny", rule=f"shio-guard:{g.outcome}", reason=g.why, layer="guard")
                self._record(action, kwargs, d)
                return d
        d = self.backend.decide(action, context_for(action, kwargs), agent=self.agent)
        approval = None
        if d.effect == "require_approval":
            d, approval = self._approve(action, kwargs, d)
        self._record(action, kwargs, d, approval)
        return d

    def _approve(self, action, kwargs, d):
        req = ApprovalRequest(action, dict(kwargs), call_digest(action, kwargs), d.rule, d.approvers, self.agent,
                              self.requester)
        if self.approver is None:
            return d, {"approved": False, "by": None, "note": "no approver configured"}
        try:
            approved, by, note = self.approver(req)
        except Exception as e:                          # an approver that fails is a refusal
            return d, {"approved": False, "by": None, "note": f"approver failed ({type(e).__name__})"}
        if not str(by or "").strip():
            return d, {"approved": False, "by": None, "note": "an approval needs the approver's name"}
        if self.requester and _same_person(by, self.requester):
            return d, {"approved": False, "by": by, "note": "maker-checker: the requester can't approve its own call"}
        record = {"approved": bool(approved), "by": by, "note": note, "call_sha256": req.digest}
        if approved:
            d = dataclasses.replace(d, allowed=True, reason=f"approved by {by}: {note}")
        return d, record

    def wrap(self, fn, action=None):
        name = action or fn.__name__

        def gated(*args, **kwargs):
            d = self.decide(name, kwargs)
            if not d.allowed:
                raise AgtDenied(name, d)
            return fn(*args, **kwargs)
        gated.__name__, gated.__doc__ = getattr(fn, "__name__", name), fn.__doc__
        return gated

    def call(self, name, kwargs, fn):
        return self.wrap(fn, name)(**kwargs)


DEMO_POLICY = """apiVersion: governance.toolkit/v1
name: shio-agt-fixture
default_action: allow
rules:
  - name: block-destructive
    condition: "action.type in ['drop_table', 'delete_records', 'truncate']"
    action: deny
    description: Destructive operations are never run by an agent
  - name: refund-cap
    condition: "action.type == 'issue_refund' and amount.value > 500"
    action: deny
    description: Refunds over 500 need a person, not an agent
  - name: send-needs-approval
    condition: "action.type == 'send_email'"
    action: require_approval
    approvers: [support-lead]
    description: Outbound email is approved by a person
"""


class AgtPolicyCheck(CheckAdapter):
    """AGT's decision as a check: decide(action, args) passes when the policy allows the call outright."""
    manifest = Manifest("microsoft-agt-policy", "1.0.0", TrustClass.CHECK, "MIT",
                        "Microsoft Agent Governance Toolkit policy engine as a deterministic check",
                        (Dependency(AGT_DIST, f"=={AGT_VERSION}", "MIT"),), extra="agt",
                        reviewed_by="shio maintainers (core)")
    fixtures = ((("lookup_order", {"order": "A-1"}), True), (("issue_refund", {"amount": 40}), True),
                (("issue_refund", {"amount": 900}), False), (("drop_table", {"table": "users"}), False),
                (("send_email", {"to": "x@example.com"}), False))

    def __init__(self, policies=None, agent="*"):
        self.backend = policies if isinstance(policies, AgtBackend) else AgtBackend(policies or DEMO_POLICY)
        self.agent = agent

    def decide(self, action, args):
        d = self.backend.decide(action, context_for(action, args), agent=self.agent)
        return d.allowed, d.explain()


def import_audit(audit_log):
    """AGT's AuditLog -> (verified, [entries as dicts]). Its own hash chain is checked first."""
    ok, problem = audit_log.verify_integrity()
    entries = [e.model_dump(mode="json") for e in audit_log.query()]
    return {"verified": bool(ok), "problem": problem, "entries": entries}


def gate_entries(folder):
    """The AGT gate's ledger in a folder -> (verified, problems, entries). Used by the monitor."""
    chain = SignedChain(folder, "agt-gate")
    ok, problems = chain.verify()
    return ok, problems, chain.entries()
