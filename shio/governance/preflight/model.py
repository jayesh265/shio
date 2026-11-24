"""The pre-model gate's vocabulary: stages, outcomes, data classes, purposes, the request and the decision.

Outcomes form a total order by strictness, ALLOW < REDACT < ROUTE < HOLD < DENY, and combining control results is the
join of that order (the maximum) plus the union of what each control asked for (fields to drop, identifiers to
tokenise, approvers, attestations used). The join is commutative, associative and idempotent, so the decision does
not depend on the order the controls ran in, and a stricter result can never be lost: "the strictest result wins".
"""
import dataclasses
import enum
import hashlib
import json
from types import MappingProxyType


class Stage(str, enum.Enum):
    P = "P"          # before the model call
    O = "O"          # on the model's output
    A = "A"          # before an action
    R = "R"          # in records and storage
    X = "X"          # organisational attestation


class Outcome(enum.IntEnum):
    ALLOW = 0
    REDACT = 1
    ROUTE = 2
    HOLD = 3
    DENY = 4

    @property
    def label(self):
        return {0: "allow", 1: "redact", 2: "route", 3: "hold", 4: "deny"}[self.value]

    @classmethod
    def parse(cls, text):
        """'deny', 'Hold', 'route or deny' (-> ROUTE: the gate denies if no approved profile exists)."""
        t = str(text).strip().lower().split(" or ")[0]
        return {"allow": cls.ALLOW, "redact": cls.REDACT, "route": cls.ROUTE, "hold": cls.HOLD, "deny": cls.DENY}[t]


class DataClass(str, enum.Enum):
    PHI = "phi"
    PART2 = "part2"                      # substance use disorder records, 42 CFR Part 2
    PSYCHOTHERAPY = "psychotherapy"      # psychotherapy notes, 45 CFR 164.501
    REPRODUCTIVE = "reproductive"
    GENETIC = "genetic"
    MINORS = "minors"
    TRIAL = "trial"                      # research and clinical trial data
    UNLABELLED = "unlabelled"            # free text nobody labelled: treated as PHI

    @property
    def health(self):
        return True


SENSITIVE = frozenset({DataClass.PART2, DataClass.PSYCHOTHERAPY, DataClass.REPRODUCTIVE, DataClass.GENETIC,
                       DataClass.MINORS})
PURPOSES = ("treatment", "payment", "operations", "research", "public health", "marketing", "other")
TPO = frozenset({"treatment", "payment", "operations"})
HIPAA_ROLES = ("covered entity", "business associate", "subcontractor", "none")
SOURCES = ("user", "tool", "document", "retrieved", "model_output")


def _freeze(x):
    if isinstance(x, dict):
        return MappingProxyType({k: _freeze(v) for k, v in x.items()})
    if isinstance(x, (list, tuple)):
        return tuple(_freeze(v) for v in x)
    return x


def _thaw(x):
    if isinstance(x, MappingProxyType) or isinstance(x, dict):
        return {k: _thaw(v) for k, v in x.items()}
    if isinstance(x, tuple):
        return [_thaw(v) for v in x]
    return x


def digest(obj):
    return hashlib.sha256(json.dumps(_thaw(obj), sort_keys=True, default=str, separators=(",", ":"))
                          .encode()).hexdigest()


@dataclasses.dataclass(frozen=True)
class Request:
    """One model call, as the agent asks for it. Immutable: the gate never edits a request, it derives the payload it
    sends from it. `source` says where the content came from: tool results, documents, retrieved context and earlier
    model output go through the same gate as the user's input."""
    caller: str                          # a unique identity (SEC-08: no shared service accounts)
    role: str                            # the caller's role, for role-based access (PRV-07)
    purpose: str                         # one of PURPOSES (PRV-01)
    destination: str                     # the model profile asked for
    fields: object = dataclasses.field(default_factory=dict)   # structured payload: {field: value}
    text: str = ""                       # free text sent to the model
    source: str = "user"
    labels: frozenset = frozenset()      # data classes the caller already knows the payload carries
    subject: str = None                  # whose data (for consent, restriction and opt-out lookups)
    authorization: str = None            # an authorization record id (PRV-02, PRV-03)
    pathway: str = None                  # research pathway (PRV-12)
    study: str = None                    # study id (RES-01)
    whole_record: bool = False           # asks for the entire record (PRV-06)
    justification: str = None
    jurisdictions: frozenset = frozenset()   # overrides the context's when the data subject is elsewhere
    lawful_basis: str = None             # GDPR Article 6 (EU-01)
    art9_condition: str = None           # GDPR Article 9 (EU-01)
    use: str = None                      # finer use (underwriting, employment, legal proceedings, ...)

    def __post_init__(self):
        object.__setattr__(self, "fields", _freeze(dict(self.fields or {})))
        object.__setattr__(self, "labels", frozenset(DataClass(x) for x in self.labels))
        object.__setattr__(self, "jurisdictions", frozenset(self.jurisdictions))

    @property
    def sha256(self):
        d = {f.name: getattr(self, f.name) for f in dataclasses.fields(self)}
        return digest({**d, "fields": _thaw(self.fields), "labels": sorted(x.value for x in self.labels),
                       "jurisdictions": sorted(self.jurisdictions)})


@dataclasses.dataclass(frozen=True)
class Effect:
    """What a control asks the gate to do besides decide: drop fields, tokenise identifiers, ask approvers."""
    drop_fields: frozenset = frozenset()
    tokenise: bool = False
    approvers: frozenset = frozenset()
    warnings: tuple = ()

    def join(self, other):
        return Effect(self.drop_fields | other.drop_fields, self.tokenise or other.tokenise,
                      self.approvers | other.approvers, self.warnings + other.warnings)


@dataclasses.dataclass(frozen=True)
class Result:
    """One control's result on one request."""
    control: str                         # pack:control, e.g. med.hipaa.privacy:PRV-01
    outcome: Outcome
    reason: str = ""
    effect: Effect = Effect()
    attestations: tuple = ()             # attestation ids this control relied on
    advisory: bool = False               # the pack runs in advisory mode: recorded, not enforced

    @property
    def enforced(self):
        return Outcome.ALLOW if self.advisory else self.outcome

    def to_dict(self):
        return {"control": self.control, "outcome": self.outcome.label, "reason": self.reason,
                "advisory": self.advisory, "attestations": list(self.attestations),
                "drop_fields": sorted(self.effect.drop_fields), "tokenise": self.effect.tokenise,
                "approvers": sorted(self.effect.approvers), "warnings": list(self.effect.warnings)}


def join(results):
    """The strictest outcome and every effect asked for. Order-independent by construction."""
    outcome, effect = Outcome.ALLOW, Effect()
    for r in results:
        outcome = max(outcome, r.enforced)
        if not r.advisory:
            effect = effect.join(r.effect)
    return outcome, effect


@dataclasses.dataclass(frozen=True)
class Decision:
    """The gate's answer. `payload` is what may be sent (after redaction or tokenisation); it is never recorded."""
    outcome: Outcome
    request_sha256: str
    destination: str                     # the profile the call goes to (after any route)
    results: tuple
    reasons: tuple
    classes: frozenset
    payload: object = None               # {"fields": ..., "text": ...} for ALLOW / REDACT / ROUTE; None otherwise
    payload_sha256: str = None
    hold_id: str = None
    approvers: frozenset = frozenset()
    record: object = None                # the signed record entry, once written
    evaluated: tuple = ()                # every control that applied to this request (for EVID-1)

    @property
    def sendable(self):
        return self.outcome in (Outcome.ALLOW, Outcome.REDACT, Outcome.ROUTE)

    def explain(self):
        head = {Outcome.ALLOW: "allowed", Outcome.REDACT: "redacted, then allowed",
                Outcome.ROUTE: f"routed to {self.destination}", Outcome.HOLD: "held for approval",
                Outcome.DENY: "denied"}[self.outcome]
        return head + (": " + "; ".join(self.reasons) if self.reasons else "")


class GateDenied(PermissionError):
    """A typed refusal: the call was denied or is held. .decision says why."""

    def __init__(self, decision):
        self.decision = decision
        super().__init__(decision.explain())
