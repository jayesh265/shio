"""The gate's declared inputs: the compliance context, the model profiles, and the registries it looks things up in.

All three are files in the repository, versioned with the agent and hashed into its card. They are loaded strictly:
a missing field the packs need, an unknown value, or a date that doesn't parse is a load error naming the file and
the field. Nothing is guessed. (The spec names them compliance.shio and models.shio; until that syntax is in SPEC.md
they are JSON with the same fields: compliance.json, models.json, registries.json.)

Profiles are claims, not proof. What code can't verify about a provider (that the agreement says what the profile
says) is covered by attestations, and the coverage matrix labels it attested.
"""
import dataclasses
import datetime as dt
import json
from pathlib import Path
from types import MappingProxyType

from .model import HIPAA_ROLES, PURPOSES, DataClass, digest

JURISDICTIONS = ("US", "EU", "UK", "IN", "other")          # plus US states as "US-CA", "US-TX", ...
DEVICE_STATUS = ("not a device", "device", "device with change plan")
RISK_TIERS = ("minimal", "limited", "high")
ROLES = ("privacy_officer", "security_officer", "clinical_safety_lead", "irb_liaison", "data_protection_officer",
         "investigator", "finance_manager", "support_lead", "pharmacist", "governance_reviewer")


class ContextError(ValueError):
    pass


def _need(d, key, where):
    if key not in d or d[key] in (None, "", []):
        raise ContextError(f"{where}: missing \"{key}\" (the packs need it; nothing is guessed)")
    return d[key]


def _one_of(value, allowed, where, key):
    if value not in allowed:
        raise ContextError(f"{where}: {key} {value!r} must be one of {', '.join(map(str, allowed))}")
    return value


def _date(value, where, key):
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        raise ContextError(f"{where}: {key} must be a date (YYYY-MM-DD), not {value!r}") from None


def _jurisdiction(j, where):
    if j in JURISDICTIONS or (str(j).startswith("US-") and len(j) == 5):
        return j
    raise ContextError(f"{where}: jurisdiction {j!r} must be one of {', '.join(JURISDICTIONS)} or US-<state>")


@dataclasses.dataclass(frozen=True)
class ComplianceContext:
    """Who the organisation is and what this agent is for (compliance.json)."""
    organisation: str
    hipaa_role: str
    purposes: frozenset
    jurisdictions: frozenset
    data_classes: frozenset
    device_status: str
    risk_tier: str
    retention: MappingProxyType
    responsible_roles: MappingProxyType      # role -> named person
    enforce_advisory: frozenset = frozenset()   # packs in advisory mode the organisation chose to enforce early
    min_recall: float = 0.95
    sha256: str = None

    @classmethod
    def from_dict(cls, d, where="compliance.json"):
        purposes = frozenset(_one_of(p, PURPOSES, where, "purpose") for p in _need(d, "purposes", where))
        return cls(
            organisation=_need(d, "organisation", where),
            hipaa_role=_one_of(_need(d, "hipaa_role", where), HIPAA_ROLES, where, "hipaa_role"),
            purposes=purposes,
            jurisdictions=frozenset(_jurisdiction(j, where) for j in _need(d, "jurisdictions", where)),
            data_classes=frozenset(DataClass(c) for c in _need(d, "data_classes", where)),
            device_status=_one_of(_need(d, "device_status", where), DEVICE_STATUS, where, "device_status"),
            risk_tier=_one_of(_need(d, "risk_tier", where), RISK_TIERS, where, "risk_tier"),
            retention=MappingProxyType(dict(_need(d, "retention", where))),
            responsible_roles=MappingProxyType({_one_of(r, ROLES, where, "responsible role"): who
                                                for r, who in _need(d, "responsible_roles", where).items()}),
            enforce_advisory=frozenset(d.get("enforce_advisory", [])),
            min_recall=float(d.get("min_recall", 0.95)),
            sha256=digest(d))

    @property
    def hipaa(self):
        return self.hipaa_role in ("covered entity", "business associate", "subcontractor")


@dataclasses.dataclass(frozen=True)
class Agreement:
    kind: str                                # baa | dpa | qso | part2-flowdown | ...
    reference: str
    signatory: str
    scope: frozenset                         # the services it covers
    start: dt.date
    expiry: dt.date

    def current(self, today):
        return self.start <= today <= self.expiry

    def days_left(self, today):
        return (self.expiry - today).days


@dataclasses.dataclass(frozen=True)
class Subprocessor:
    name: str
    agreement: Agreement = None


@dataclasses.dataclass(frozen=True)
class ModelProfile:
    """What is true of one destination the gate may send to (one entry of models.json)."""
    name: str
    endpoint: str
    version: str
    service: str                             # the provider's product the agreement must name
    region: str
    retention_days: int
    logging: str
    training_on_inputs: bool
    allowed_classes: frozenset
    agreements: tuple = ()
    subprocessors: tuple = ()
    certifications: tuple = ()
    preference: int = 100                    # lower is preferred when routing

    def agreement(self, *kinds):
        return next((a for a in self.agreements if a.kind in kinds), None)

    @classmethod
    def from_dict(cls, name, d, where="models.json"):
        w = f"{where}: {name}"

        def agreement(a, aw):
            return Agreement(_need(a, "kind", aw), _need(a, "reference", aw), _need(a, "signatory", aw),
                             frozenset(_need(a, "scope", aw)), _date(_need(a, "start", aw), aw, "start"),
                             _date(_need(a, "expiry", aw), aw, "expiry"))
        if "training_on_inputs" not in d:
            raise ContextError(f"{w}: missing \"training_on_inputs\" (it must be stated, true or false)")
        return cls(name=name, endpoint=_need(d, "endpoint", w), version=str(_need(d, "version", w)),
                   service=_need(d, "service", w), region=_need(d, "region", w),
                   retention_days=int(d.get("retention_days", 0)), logging=d.get("logging", "unknown"),
                   training_on_inputs=bool(d["training_on_inputs"]),
                   allowed_classes=frozenset(DataClass(c) for c in d.get("allowed_classes", [])),
                   agreements=tuple(agreement(a, f"{w} agreement {i}") for i, a in enumerate(d.get("agreements", []))),
                   subprocessors=tuple(Subprocessor(s["name"], agreement(s["agreement"], f"{w} subprocessor "
                                                                                     f"{s['name']}")
                                                    if s.get("agreement") else None)
                                       for s in d.get("subprocessors", [])),
                   certifications=tuple(d.get("certifications", [])), preference=int(d.get("preference", 100)))


@dataclasses.dataclass(frozen=True)
class Profiles:
    by_name: MappingProxyType
    sha256: str

    @classmethod
    def from_dict(cls, d, where="models.json"):
        return cls(MappingProxyType({n: ModelProfile.from_dict(n, p, where) for n, p in _need(d, "models", where)
                                    .items()}), digest(d))

    def get(self, name):
        return self.by_name.get(name)

    def alternatives(self, exclude):
        return sorted((p for n, p in self.by_name.items() if n != exclude), key=lambda p: (p.preference, p.name))


@dataclasses.dataclass(frozen=True)
class Registries:
    """What the gate looks up per request (registries.json): purpose field allow-lists, authorizations, role access,
    restrictions and opt-outs, studies, consents, data use agreements. Plain data; each control reads its part."""
    data: MappingProxyType
    sha256: str

    @classmethod
    def from_dict(cls, d):
        return cls(MappingProxyType(json.loads(json.dumps(d))), digest(d))

    def part(self, name):
        return self.data.get(name) or {}


def _read(path):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        raise ContextError(f"{path}: not found") from None
    except ValueError as e:
        raise ContextError(f"{path}: not valid JSON ({e})") from None


def load(folder):
    """compliance.json, models.json and registries.json from a folder -> (context, profiles, registries)."""
    folder = Path(folder)
    return (ComplianceContext.from_dict(_read(folder / "compliance.json"), str(folder / "compliance.json")),
            Profiles.from_dict(_read(folder / "models.json"), str(folder / "models.json")),
            Registries.from_dict(_read(folder / "registries.json") if (folder / "registries.json").exists() else {}))
