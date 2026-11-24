"""The gate's enforced controls: deterministic code, one class per pack control, each with its own fixtures.

A control looks at one request in one environment and returns None (nothing to object to) or a Result whose outcome
is the control's on-fail (Deny, Hold, Redact or Route). It must not mutate anything. A control that raises is turned
into Deny by the gate (fail closed), so a control never has to defend against its own bugs to stay safe.

Every control ships with fixtures: at least one passing, one failing and one adversarial case, each a request (plus
optional edits to the fixture world) and the outcome the whole gate must reach. The mutation test runs each failing
fixture again with the control switched off and requires a weaker outcome: if the request is still stopped, the
control was never the thing stopping it.

Attestation controls are not written here: the gate builds one for each `attestation` proof in a loaded pack.
"""
import abc
import dataclasses
import datetime as dt
from urllib.parse import urlparse

from .model import SENSITIVE, TPO, DataClass, Effect, Outcome, Result, Stage

EEA = frozenset({"EU", "EEA", "IS", "LI", "NO"})


@dataclasses.dataclass(frozen=True)
class Env:
    """Everything a control may read for one request. Built by the gate; controls treat it as read-only."""
    context: object
    profile: object                  # the destination's ModelProfile
    profiles: object
    registries: object
    attestations: object
    today: dt.date
    classes: frozenset
    unlabelled: tuple = ()

    def reg(self, name):
        return self.registries.part(name)

    @property
    def phi(self):
        return DataClass.PHI in self.classes


@dataclasses.dataclass(frozen=True)
class Fixture:
    kind: str                        # pass | fail | adversarial
    id: str
    request: dict                    # Request fields over the fixture base request
    expect: Outcome                  # the gate's outcome with every control on
    context: object = None           # optional edits to the fixture world (functions over the dicts)
    models: object = None
    registries: object = None


BASE_REQUEST = {"caller": "dr.mensah", "role": "clinician", "purpose": "treatment", "destination": "clinical-llm",
                "fields": {"reason": "declining kidney function", "results": "eGFR 38"}, "subject": "P-100"}


class GateControl(abc.ABC):
    pack: str
    id: str
    title: str
    stage = Stage.P
    on_fail = Outcome.DENY
    advisory = False                 # reg.india: recorded, not enforced, unless the context enforces the pack early
    fixtures = ()

    @property
    def key(self):
        return f"{self.pack}:{self.id}"

    def applies(self, req, env):
        return True

    @abc.abstractmethod
    def check(self, req, env):
        """-> None, or (reason) / (reason, Effect) when the control objects."""

    def evaluate(self, req, env):
        if not self.applies(req, env):
            return None
        found = self.check(req, env)
        if not found:
            return None
        reason, effect = (found, Effect()) if isinstance(found, str) else found
        advisory = self.advisory and self.pack not in env.context.enforce_advisory
        return Result(self.key, self.on_fail, reason, effect, advisory=advisory)


def pack_active(pack, req, env):
    """Whether a pack applies to this request: the switch the spec's context fields and data classes turn on."""
    j = req.jurisdictions or env.context.jurisdictions
    if pack.startswith("med.hipaa"):
        return env.context.hipaa and env.phi
    if pack == "med.sensitive":
        return bool(SENSITIVE & env.classes)
    if pack == "med.research":
        return req.purpose == "research" or bool(req.study)
    if pack == "reg.eu":
        return "EU" in j
    if pack == "reg.india":
        return "IN" in j
    return env.phi or bool(env.classes)            # assurance and security packs: any health data


ADVISORY_PACKS = frozenset({"reg.india"})


def _hipaa_phi(req, env):
    return env.context.hipaa and env.phi


def _date(s):
    return dt.date.fromisoformat(str(s))


def allowed_fields(req, env):
    return set((env.reg("purposes").get(req.purpose) or {}).get("fields", []))


def QSO(m):
    """Fixture edit: give the clinical profile a qualified service organisation agreement."""
    m["models"]["clinical-llm"]["agreements"].append({"kind": "qso", "reference": "QSO-1", "signatory": "x",
                                                      "scope": ["Vendor A Health API"], "start": "2026-01-01",
                                                      "expiry": "2027-12-31"})


def ALLOW_CLASS(*classes):
    def edit(m):
        m["models"]["clinical-llm"]["allowed_classes"] += list(classes)
    return edit


# ================= med.hipaa.privacy =================
class PRV01(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-01", "Every request declares a permitted purpose"
    fixtures = (Fixture("pass", "treatment", {}, Outcome.ALLOW),
                Fixture("fail", "undeclared", {"purpose": ""}, Outcome.DENY),
                Fixture("adversarial", "purpose-not-in-context", {"purpose": "public health"}, Outcome.DENY),
                Fixture("adversarial", "case-games", {"purpose": "Treatment "}, Outcome.DENY))

    def check(self, req, env):
        if req.purpose not in env.context.purposes or req.purpose not in env.reg("purposes"):
            return f"purpose {req.purpose!r} is not one this agent declares (registry: {', '.join(sorted(env.context.purposes))})"


class PRV02(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-02", "Purposes that need written authorization have one"
    on_fail = Outcome.HOLD
    fixtures = (Fixture("pass", "marketing-authorized", {"purpose": "marketing", "authorization": "AUTH-1",
                                                         "fields": {"campaign": "flu clinic"}}, Outcome.ALLOW),
                Fixture("fail", "marketing-no-auth", {"purpose": "marketing", "fields": {"campaign": "x"}}, Outcome.HOLD),
                Fixture("adversarial", "auth-for-someone-else", {"purpose": "marketing", "authorization": "AUTH-1",
                                                                 "subject": "P-999", "fields": {"campaign": "x"}},
                        Outcome.HOLD))

    def applies(self, req, env):
        return _hipaa_phi(req, env) or req.purpose in env.reg("authorization_required")

    def check(self, req, env):
        if req.purpose not in env.reg("authorization_required"):
            return None
        a = env.reg("authorizations").get(req.authorization or "")
        if not a or a.get("subject") != req.subject or a.get("purpose") != req.purpose:
            return (f"purpose {req.purpose} needs a written authorization for this person and purpose",
                    Effect(approvers=frozenset({"privacy_officer"})))


class PRV03(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-03", "An authorization relied on is valid"
    fixtures = (Fixture("pass", "valid", {"purpose": "marketing", "authorization": "AUTH-1",
                                          "fields": {"campaign": "x"}}, Outcome.ALLOW),
                Fixture("fail", "revoked", {"purpose": "marketing", "authorization": "AUTH-1",
                                            "fields": {"campaign": "x"}}, Outcome.DENY,
                        registries=lambda r: r["authorizations"]["AUTH-1"].update(revoked=True)),
                Fixture("adversarial", "expired", {"purpose": "marketing", "authorization": "AUTH-1",
                                                   "fields": {"campaign": "x"}}, Outcome.DENY,
                        registries=lambda r: r["authorizations"]["AUTH-1"].update(expiry="2026-11-23")),
                Fixture("adversarial", "no-revocation-statement", {"purpose": "marketing", "authorization": "AUTH-1",
                                                                   "fields": {"campaign": "x"}}, Outcome.DENY,
                        registries=lambda r: r["authorizations"]["AUTH-1"].pop("revocation_statement")))

    def applies(self, req, env):
        return bool(req.authorization)

    def check(self, req, env):
        a = env.reg("authorizations").get(req.authorization)
        if a is None:
            return f"authorization {req.authorization} is not on file"
        missing = [k for k in ("signed", "dated", "information", "recipient", "purpose", "expiry",
                               "revocation_statement") if not a.get(k)]
        if missing:
            return f"authorization {req.authorization} is missing {', '.join(missing)}"
        if a.get("revoked"):
            return f"authorization {req.authorization} was revoked"
        if _date(a["expiry"]) < env.today:
            return f"authorization {req.authorization} expired on {a['expiry']}"


class PRV04(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-04", "Minimum necessary: only the purpose's fields are sent"
    on_fail = Outcome.REDACT
    fixtures = (Fixture("pass", "allowed-fields", {}, Outcome.ALLOW),
                Fixture("fail", "extra-field", {"fields": {"reason": "x", "ssn_field": "123-45-6789"}}, Outcome.REDACT),
                Fixture("adversarial", "billing-in-treatment", {"fields": {"reason": "x", "claim": "C-1"}},
                        Outcome.REDACT))

    def applies(self, req, env):
        return env.context.hipaa

    def check(self, req, env):
        allowed = set((env.reg("purposes").get(req.purpose) or {}).get("fields", []))
        extra = frozenset(f for f in req.fields if f not in allowed)
        if extra:
            return f"fields {', '.join(sorted(extra))} are not needed for {req.purpose}: dropped", Effect(drop_fields=extra)


class PRV06(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-06", "Whole-record requests carry a written justification"
    on_fail = Outcome.HOLD
    fixtures = (Fixture("pass", "justified", {"whole_record": True, "justification": "transfer of care summary"},
                        Outcome.ALLOW),
                Fixture("fail", "unjustified", {"whole_record": True}, Outcome.HOLD),
                Fixture("adversarial", "blank-justification", {"whole_record": True, "justification": "   "},
                        Outcome.HOLD))

    def applies(self, req, env):
        return req.whole_record

    def check(self, req, env):
        if not (req.justification or "").strip():
            return "the whole record was asked for without a written justification", \
                Effect(approvers=frozenset({"privacy_officer"}))


class PRV07(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-07", "Role-based access to PHI categories"
    fixtures = (Fixture("pass", "clinician", {}, Outcome.ALLOW),
                Fixture("fail", "billing-reads-clinical", {"role": "billing"}, Outcome.DENY),
                Fixture("adversarial", "unknown-role", {"role": "intern"}, Outcome.DENY))

    def applies(self, req, env):
        return _hipaa_phi(req, env)

    def check(self, req, env):
        can = set(env.reg("roles").get(req.role, []))
        if not can:
            return f"role {req.role!r} has no PHI access"
        cats, sent = env.reg("field_categories"), allowed_fields(req, env)    # dropped fields are never read
        denied = sorted({cats.get(f, "uncategorised") for f in req.fields if f in sent} - can)
        if denied:
            return f"role {req.role} may not read {', '.join(denied)}"


class PRV08(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-08", "PHI goes only to a destination with an agreement in force"
    on_fail = Outcome.ROUTE
    fixtures = (Fixture("pass", "baa-destination", {}, Outcome.ALLOW),
                Fixture("fail", "no-agreement", {"destination": "general-llm"}, Outcome.ROUTE),
                Fixture("adversarial", "training-on-inputs", {}, Outcome.DENY,
                        models=lambda m: [p.update(training_on_inputs=True) for p in m["models"].values()]))

    def applies(self, req, env):
        return _hipaa_phi(req, env)

    def check(self, req, env):
        p = env.profile
        if p.training_on_inputs:
            return f"{p.name} trains on its inputs, so it may not receive health data"
        if p.agreement("baa") is None:               # its term is BAA-05's job
            return f"{p.name} has no business associate agreement on file"
        not_allowed = sorted(c.value for c in env.classes - p.allowed_classes - {DataClass.UNLABELLED})
        if not_allowed:
            return f"{p.name} is not approved for {', '.join(not_allowed)}"


class PRV09(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-09", "PHI is de-identified where the purpose needs none"
    on_fail = Outcome.REDACT
    fixtures = (Fixture("pass", "aggregate", {"role": "analyst", "purpose": "operations", "fields": {"metric": "wait"}},
                        Outcome.ALLOW),
                Fixture("fail", "identifiers-in-text", {"role": "analyst", "purpose": "operations",
                                                        "fields": {"metric": "wait"},
                                                        "text": "Mr Daniel Okoro waited 40 minutes on 03/04/2026."},
                        Outcome.REDACT),
                Fixture("adversarial", "contact-details", {"role": "analyst", "purpose": "operations",
                                                           "fields": {"metric": "callbacks"},
                                                           "text": "call back on 415-555-0182 or dana@example.com"},
                        Outcome.REDACT))

    def applies(self, req, env):
        return _hipaa_phi(req, env)

    def check(self, req, env):
        if not (env.reg("purposes").get(req.purpose) or {}).get("needs_phi", True):
            return f"{req.purpose} needs no PHI: identifiers are tokenised before sending", Effect(tokenise=True)


class PRV11(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-11", "A limited data set has a data use agreement with the recipient"
    on_fail = Outcome.HOLD
    fixtures = (Fixture("pass", "dua", {"purpose": "research", "pathway": "limited data set", "study": "ST-1",
                                        "subject": "P-600", "fields": {"age": 61, "results": "HbA1c 7.9"}}, Outcome.ALLOW),
                Fixture("fail", "no-dua", {"purpose": "research", "pathway": "limited data set", "study": "ST-1",
                                           "subject": "P-600", "fields": {"age": 61, "results": "HbA1c 7.9"}}, Outcome.HOLD,
                        registries=lambda r: r.update(data_use_agreements={})),
                Fixture("adversarial", "expired-dua", {"purpose": "research", "pathway": "limited data set",
                                                       "study": "ST-1", "subject": "P-600", "fields": {"age": 61, "results": "HbA1c 7.9"}},
                        Outcome.HOLD,
                        registries=lambda r: r["data_use_agreements"]["clinical-llm"].update(expiry="2026-01-01")))

    def applies(self, req, env):
        return req.pathway == "limited data set"

    def check(self, req, env):
        dua = env.reg("data_use_agreements").get(env.profile.name)
        if not dua or _date(dua["expiry"]) < env.today:
            return f"no current data use agreement with {env.profile.name}", Effect(approvers=frozenset({"privacy_officer"}))


class PRV12(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-12", "Research names exactly one pathway, with its proof on file"
    on_fail = Outcome.HOLD
    fixtures = (Fixture("pass", "waiver", {"purpose": "research", "pathway": "waiver", "study": "ST-1",
                                           "subject": "P-600", "fields": {"age": 61, "results": "HbA1c 7.9"}}, Outcome.ALLOW),
                Fixture("fail", "no-pathway", {"purpose": "research", "study": "ST-1", "subject": "P-600",
                                               "fields": {"age": 61, "results": "HbA1c 7.9"}}, Outcome.HOLD),
                Fixture("adversarial", "waiver-not-on-file", {"purpose": "research", "pathway": "waiver",
                                                              "study": "ST-1", "subject": "P-600",
                                                              "fields": {"age": 61, "results": "HbA1c 7.9"}},
                        Outcome.HOLD,
                        registries=lambda r: r.update(waivers={})))

    def applies(self, req, env):
        return req.purpose == "research" and _hipaa_phi(req, env)

    def check(self, req, env):
        if req.pathway not in env.reg("research_pathways"):
            return (f"research needs exactly one pathway ({', '.join(env.reg('research_pathways'))})",
                    Effect(approvers=frozenset({"irb_liaison"})))
        if req.pathway == "waiver":
            w = env.reg("waivers").get(req.study or "")
            if not w or not w.get("criteria_met") or not w.get("board"):
                return f"no IRB or Privacy Board waiver on file for {req.study}", Effect(approvers=frozenset({"irb_liaison"}))
        if req.pathway == "authorization" and not req.authorization:
            return "the authorization pathway needs an authorization record", Effect(approvers=frozenset({"irb_liaison"}))


class PRV14(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-14", "Agreed patient restrictions are honoured"
    fixtures = (Fixture("pass", "no-restriction", {}, Outcome.ALLOW),
                Fixture("fail", "restricted-purpose", {"subject": "P-200", "purpose": "operations",
                                                       "role": "analyst", "fields": {"metric": "x"}}, Outcome.DENY),
                Fixture("adversarial", "restricted-destination", {"subject": "P-200"}, Outcome.DENY,
                        registries=lambda r: r["restrictions"]["P-200"].update(destinations=["clinical-llm"])))

    def check(self, req, env):
        r = env.reg("restrictions").get(req.subject or "")
        if r and (req.purpose in r.get("purposes", []) or env.profile.name in r.get("destinations", [])):
            return f"{req.subject} has an agreed restriction on this use"


class PRV15(GateControl):
    pack, id, title = "med.hipaa.privacy", "PRV-15", "Opt-outs are applied"
    fixtures = (Fixture("pass", "no-opt-out", {"purpose": "marketing", "authorization": "AUTH-1",
                                               "fields": {"campaign": "x"}}, Outcome.ALLOW),
                Fixture("fail", "opted-out", {"subject": "P-300", "purpose": "marketing", "fields": {"campaign": "x"}},
                        Outcome.DENY),
                Fixture("adversarial", "opted-out-with-auth", {"subject": "P-300", "purpose": "marketing",
                                                               "authorization": "AUTH-1", "fields": {"campaign": "x"}},
                        Outcome.DENY))

    def check(self, req, env):
        if req.purpose in env.reg("opt_outs").get(req.subject or "", []):
            return f"{req.subject} opted out of {req.purpose}"


# ================= med.hipaa.security =================
class SEC08(GateControl):
    pack, id, title = "med.hipaa.security", "SEC-08", "Every caller has a unique identity"
    fixtures = (Fixture("pass", "named", {}, Outcome.ALLOW),
                Fixture("fail", "shared-account", {"caller": "service"}, Outcome.DENY),
                Fixture("adversarial", "blank", {"caller": "  "}, Outcome.DENY),
                Fixture("adversarial", "shared-mixed-case", {"caller": "Admin"}, Outcome.DENY))

    def check(self, req, env):
        c = (req.caller or "").strip().lower()
        if not c or c in env.reg("shared_accounts"):
            return f"caller {req.caller!r} is not a unique identity"


class SEC14(GateControl):
    pack, id, title = "med.hipaa.security", "SEC-14", "The destination is pinned to a version"
    fixtures = (Fixture("pass", "pinned", {}, Outcome.ALLOW),
                Fixture("fail", "latest", {}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"].update(version="latest")),
                Fixture("adversarial", "wildcard", {}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"].update(version="2026-*")))

    def check(self, req, env):
        v = str(env.profile.version).strip().lower()
        if not v or v in ("latest", "default", "auto") or any(ch in v for ch in "*^~><"):
            return f"{env.profile.name} is not pinned (version {env.profile.version!r})"


class SEC15(GateControl):
    pack, id, title = "med.hipaa.security", "SEC-15", "Transmission security: TLS endpoints only"
    fixtures = (Fixture("pass", "https", {}, Outcome.ALLOW),
                Fixture("fail", "http", {}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"].update(endpoint="http://llm.vendor-a.example/v1")),
                Fixture("adversarial", "no-scheme", {}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"].update(endpoint="llm.vendor-a.example/v1")))

    def check(self, req, env):
        if urlparse(env.profile.endpoint).scheme != "https":
            return f"{env.profile.name} endpoint is not https"


# make the destination controls route rather than deny, so a safe alternative can be used
SEC14.on_fail = SEC15.on_fail = Outcome.ROUTE


# ================= med.hipaa.baa =================
class BAA02(GateControl):
    pack, id, title = "med.hipaa.baa", "BAA-02", "The agreement's scope names the service used"
    on_fail = Outcome.ROUTE
    fixtures = (Fixture("pass", "in-scope", {}, Outcome.ALLOW),
                Fixture("fail", "other-product", {}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"]["agreements"][0].update(scope=["Vendor A Search"])),
                Fixture("adversarial", "near-name", {}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"]["agreements"][0].update(scope=["Vendor A Health"])))

    def applies(self, req, env):
        return _hipaa_phi(req, env) and env.profile.agreement("baa") is not None

    def check(self, req, env):
        if env.profile.service not in env.profile.agreement("baa").scope:
            return f"the agreement with {env.profile.name} does not name {env.profile.service}"


class BAA04(GateControl):
    pack, id, title = "med.hipaa.baa", "BAA-04", "Every subprocessor has a flow-down agreement"
    on_fail = Outcome.ROUTE
    fixtures = (Fixture("pass", "flowdown", {}, Outcome.ALLOW),
                Fixture("fail", "missing", {}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"]["subprocessors"][0].pop("agreement")),
                Fixture("adversarial", "lapsed", {}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"]["subprocessors"][0]["agreement"]
                        .update(expiry="2026-10-01")))

    def applies(self, req, env):
        return _hipaa_phi(req, env)

    def check(self, req, env):
        bad = [s.name for s in env.profile.subprocessors if s.agreement is None or not s.agreement.current(env.today)]
        if bad:
            return f"subprocessors without a current flow-down agreement: {', '.join(bad)}"


class BAA05(GateControl):
    pack, id, title = "med.hipaa.baa", "BAA-05", "The agreement is within its term (warning 60 days out)"
    on_fail = Outcome.ROUTE
    fixtures = (Fixture("pass", "in-term", {}, Outcome.ALLOW),
                Fixture("fail", "lapsed-today", {}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"]["agreements"][0].update(expiry="2026-11-23")),
                Fixture("adversarial", "not-started", {}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"]["agreements"][0].update(start="2026-12-01")))

    def applies(self, req, env):
        return _hipaa_phi(req, env) and env.profile.agreement("baa") is not None

    def check(self, req, env):
        a = env.profile.agreement("baa")
        if not a.current(env.today):
            return f"the agreement with {env.profile.name} is outside its term ({a.start} to {a.expiry})"

    def evaluate(self, req, env):
        r = super().evaluate(req, env)
        if r is None and self.applies(req, env):
            left = env.profile.agreement("baa").days_left(env.today)
            if left <= 60:                       # pass, with a warning the record carries
                return Result(self.key, Outcome.ALLOW, f"agreement expires in {left} days",
                              Effect(warnings=(f"{env.profile.name} agreement expires in {left} days",)))
        return r


# ================= med.sensitive =================
class SEN02(GateControl):
    pack, id, title = "med.sensitive", "SEN-02", "Part 2 records need written consent for this purpose"
    on_fail = Outcome.HOLD
    fixtures = (Fixture("pass", "consented", {"subject": "P-400", "fields": {"reason": "x", "sud_note": "x"},
                                              "labels": ["part2"]}, Outcome.ALLOW,
                        models=lambda m: m["models"]["clinical-llm"]["agreements"].append(
                            {"kind": "qso", "reference": "QSO-1", "signatory": "x", "scope": ["Vendor A Health API"],
                             "start": "2026-01-01", "expiry": "2027-12-31"}),
                        registries=lambda r: (r["purposes"]["treatment"]["fields"].append("sud_note"),
                                              r["field_categories"].update(sud_note="clinical"))),
                Fixture("fail", "no-consent", {"subject": "P-100", "labels": ["part2"]}, Outcome.HOLD,
                        models=lambda m: m["models"]["clinical-llm"]["agreements"].append(
                            {"kind": "qso", "reference": "QSO-1", "signatory": "x", "scope": ["Vendor A Health API"],
                             "start": "2026-01-01", "expiry": "2027-12-31"})),
                Fixture("adversarial", "found-in-free-text", {"subject": "P-100",
                                                              "text": "Attends the methadone clinic weekly."},
                        Outcome.HOLD,
                        models=lambda m: m["models"]["clinical-llm"]["agreements"].append(
                            {"kind": "qso", "reference": "QSO-1", "signatory": "x", "scope": ["Vendor A Health API"],
                             "start": "2026-01-01", "expiry": "2027-12-31"})))

    def applies(self, req, env):
        return DataClass.PART2 in env.classes

    def check(self, req, env):
        c = env.reg("part2_consents").get(req.subject or "")
        if not c or c.get("revoked") or req.purpose not in c.get("purposes", []):
            return f"Part 2 records need {req.subject}'s written consent for {req.purpose}", \
                Effect(approvers=frozenset({"privacy_officer"}))


class SEN04(GateControl):
    pack, id, title = "med.sensitive", "SEN-04", "Part 2 records are never used in proceedings against the patient"
    fixtures = (Fixture("pass", "treatment-use", {"labels": ["part2"], "subject": "P-400"}, Outcome.ALLOW,
                        models=lambda m: m["models"]["clinical-llm"]["agreements"].append(
                            {"kind": "qso", "reference": "QSO-1", "signatory": "x", "scope": ["Vendor A Health API"],
                             "start": "2026-01-01", "expiry": "2027-12-31"})),
                Fixture("fail", "legal-use", {"labels": ["part2"], "subject": "P-400", "use": "legal proceedings"},
                        Outcome.DENY, models=QSO),
                Fixture("adversarial", "legal-use-in-free-text-class", {"subject": "P-400", "use": "legal proceedings",
                                                                        "text": "opioid treatment program since 2024"},
                        Outcome.DENY, models=QSO))

    def applies(self, req, env):
        return DataClass.PART2 in env.classes

    def check(self, req, env):
        if (req.use or "").lower() in ("legal proceedings", "investigation", "prosecution"):
            return "Part 2 records may not be used in proceedings against the patient without a qualifying court order"


class SEN05(GateControl):
    pack, id, title = "med.sensitive", "SEN-05", "The provider is a QSO or has a Part 2 flow-down"
    on_fail = Outcome.ROUTE
    fixtures = (Fixture("pass", "qso", {"labels": ["part2"], "subject": "P-400"}, Outcome.ALLOW,
                        models=lambda m: m["models"]["clinical-llm"]["agreements"].append(
                            {"kind": "qso", "reference": "QSO-1", "signatory": "x", "scope": ["Vendor A Health API"],
                             "start": "2026-01-01", "expiry": "2027-12-31"})),
                Fixture("fail", "hipaa-only", {"labels": ["part2"], "subject": "P-400"}, Outcome.DENY),
                Fixture("adversarial", "lapsed-qso", {"labels": ["part2"], "subject": "P-400"}, Outcome.DENY,
                        models=lambda m: m["models"]["clinical-llm"]["agreements"].append(
                            {"kind": "qso", "reference": "QSO-1", "signatory": "x", "scope": ["Vendor A Health API"],
                             "start": "2026-01-01", "expiry": "2026-06-30"})))

    def applies(self, req, env):
        return DataClass.PART2 in env.classes

    def check(self, req, env):
        a = env.profile.agreement("qso", "part2-flowdown")
        if a is None or not a.current(env.today):
            return f"{env.profile.name} has no qualified service organisation or Part 2 flow-down agreement in force"


class SEN07(GateControl):
    pack, id, title = "med.sensitive", "SEN-07", "Psychotherapy notes are blocked from model calls"
    fixtures = (Fixture("pass", "ordinary-mental-health", {"fields": {"note": "low mood, reviewed in clinic"}},
                        Outcome.ALLOW),
                Fixture("fail", "labelled", {"labels": ["psychotherapy"]}, Outcome.DENY,
                        models=ALLOW_CLASS("psychotherapy")),
                Fixture("adversarial", "in-free-text", {"text": "From the psychotherapy notes of the last session"},
                        Outcome.DENY, models=ALLOW_CLASS("psychotherapy")))

    def applies(self, req, env):
        return DataClass.PSYCHOTHERAPY in env.classes

    def check(self, req, env):
        return "psychotherapy notes are blocked from every model call by default"


class SEN10(GateControl):
    pack, id, title = "med.sensitive", "SEN-10", "Genetic data is never used for underwriting or employment"
    fixtures = (Fixture("pass", "clinical-genetics", {"labels": ["genetic"]}, Outcome.ALLOW),
                Fixture("fail", "underwriting", {"labels": ["genetic"], "use": "underwriting"}, Outcome.DENY),
                Fixture("adversarial", "employment-free-text", {"use": "Employment",
                                                                "text": "BRCA1 carrier, genetic test 2025"},
                        Outcome.DENY))

    def applies(self, req, env):
        return DataClass.GENETIC in env.classes

    def check(self, req, env):
        if (req.use or "").strip().lower() in ("underwriting", "employment", "insurance eligibility"):
            return f"genetic data may not be used for {req.use}"


class SEN11(GateControl):
    pack, id, title = "med.sensitive", "SEN-11", "Minors' consent follows the state rule"
    on_fail = Outcome.HOLD
    fixtures = (Fixture("pass", "consent-ok", {"subject": "P-500", "labels": ["minors"]}, Outcome.ALLOW,
                        registries=lambda r: r["minors"]["P-500"].update(consent_ok=True)),
                Fixture("fail", "no-consent", {"subject": "P-500", "labels": ["minors"]}, Outcome.HOLD),
                Fixture("adversarial", "unknown-minor", {"subject": "P-999", "text": "Paediatric patient under 18"},
                        Outcome.HOLD))

    def applies(self, req, env):
        return DataClass.MINORS in env.classes

    def check(self, req, env):
        m = env.reg("minors").get(req.subject or "")
        if not m or not m.get("consent_ok"):
            return "minor: consent under the state's rule is not recorded", Effect(approvers=frozenset({"privacy_officer"}))


class SEN12(GateControl):
    pack, id, title = "med.sensitive", "SEN-12", "State-sensitive classes need a reviewed, current state-table row"
    on_fail = Outcome.HOLD
    fixtures = (Fixture("pass", "reviewed-row", {"labels": ["reproductive"]}, Outcome.ALLOW),
                Fixture("fail", "stale-row", {"labels": ["reproductive"]}, Outcome.HOLD,
                        registries=lambda r: r["state_table"]["US-CA"].update(reviewed="2025-10-01")),
                Fixture("adversarial", "unreviewed-state", {"labels": ["genetic"]}, Outcome.HOLD,
                        context=lambda c: c.update(jurisdictions=["US", "US-TX"])))

    def applies(self, req, env):
        return bool({DataClass.REPRODUCTIVE, DataClass.GENETIC, DataClass.MINORS} & env.classes)

    def check(self, req, env):
        states = sorted(j for j in (req.jurisdictions or env.context.jurisdictions) if str(j).startswith("US-"))
        table = env.reg("state_table")
        for s in states:
            row = table.get(s)
            if not row or not row.get("reviewed"):
                return f"no reviewed state-table row for {s}: unreviewed states hold", \
                    Effect(approvers=frozenset({"privacy_officer"}))
            if (env.today - _date(row["reviewed"])).days > 365:
                return f"the state-table row for {s} is stale (reviewed {row['reviewed']})", \
                    Effect(approvers=frozenset({"privacy_officer"}))


# ================= med.research =================
class _Research(GateControl):
    pack = "med.research"

    def applies(self, req, env):
        return req.purpose == "research" or bool(req.study)

    def study(self, req, env):
        return env.reg("studies").get(req.study or "")


RES_OK = {"purpose": "research", "pathway": "waiver", "study": "ST-1", "subject": "P-600",
          "fields": {"age": 61, "results": "HbA1c 7.9"}}


class RES01(_Research):
    id, title = "RES-01", "Research carries a registered study"
    fixtures = (Fixture("pass", "registered", RES_OK, Outcome.ALLOW),
                Fixture("fail", "no-study", {**RES_OK, "study": None}, Outcome.DENY),
                Fixture("adversarial", "unknown-study", {**RES_OK, "study": "ST-404"}, Outcome.DENY))

    def check(self, req, env):
        if not self.study(req, env):
            return f"study {req.study!r} is not registered"


class RES02(_Research):
    id, title = "RES-02", "IRB approval is current"
    fixtures = (Fixture("pass", "current", RES_OK, Outcome.ALLOW),
                Fixture("fail", "lapsed", {**RES_OK, "study": "ST-OLD"}, Outcome.DENY),
                Fixture("adversarial", "expires-yesterday", RES_OK, Outcome.DENY,
                        registries=lambda r: r["studies"]["ST-1"].update(irb_expiry="2026-11-23")))

    def check(self, req, env):
        s = self.study(req, env)
        if s and _date(s["irb_expiry"]) < env.today:
            return f"IRB approval for {req.study} lapsed on {s['irb_expiry']}"


class RES03(_Research):
    id, title = "RES-03", "Only the protocol's data list is sent"
    on_fail = Outcome.REDACT
    fixtures = (Fixture("pass", "in-protocol", RES_OK, Outcome.ALLOW),
                Fixture("fail", "extra-field", {**RES_OK, "fields": {"age": 61, "note": "x"}}, Outcome.REDACT),
                Fixture("adversarial", "only-extra", {**RES_OK, "fields": {"note": "x"}}, Outcome.REDACT))

    def check(self, req, env):
        s = self.study(req, env)
        if s:
            extra = frozenset(f for f in req.fields if f not in s.get("fields", []))
            if extra:
                return f"fields outside the protocol's data list dropped: {', '.join(sorted(extra))}", \
                    Effect(drop_fields=extra)


class RES04(_Research):
    id, title = "RES-04", "Current-version consent is on file"
    on_fail = Outcome.HOLD
    fixtures = (Fixture("pass", "consented", RES_OK, Outcome.ALLOW),
                Fixture("fail", "old-version", {**RES_OK, "subject": "P-601"}, Outcome.HOLD),
                Fixture("adversarial", "authorization-pathway-no-consent",
                        {**RES_OK, "pathway": "authorization", "authorization": "AUTH-9", "subject": "P-603"},
                        Outcome.HOLD,
                        registries=lambda r: r["authorizations"].update({"AUTH-9": {
                            **r["authorizations"]["AUTH-1"], "subject": "P-603", "purpose": "research"}})))

    def check(self, req, env):
        s = self.study(req, env)
        if not s:
            return None
        got, want = s.get("consents", {}).get(req.subject or ""), s.get("consent_version")
        # under a waiver consent is not required, but a participant who consented to an older version re-consents
        if (req.pathway == "waiver" and got not in (None, want)) or (req.pathway != "waiver" and got != want):
            return f"no consent in the current version ({want}) for {req.subject}", \
                Effect(approvers=frozenset({"irb_liaison"}))


class RES07(_Research):
    id, title = "RES-07", "Withdrawn participants are excluded"
    fixtures = (Fixture("pass", "active", RES_OK, Outcome.ALLOW),
                Fixture("fail", "withdrawn", {**RES_OK, "subject": "P-602"}, Outcome.DENY),
                Fixture("adversarial", "withdrawn-later", RES_OK, Outcome.DENY,
                        registries=lambda r: r["studies"]["ST-1"]["withdrawn"].append("P-600")))

    def check(self, req, env):
        s = self.study(req, env)
        if s and req.subject in s.get("withdrawn", []):
            return f"{req.subject} withdrew from {req.study}"


# ================= reg.eu =================
class _EU(GateControl):
    pack = "reg.eu"

    def applies(self, req, env):
        return "EU" in (req.jurisdictions or env.context.jurisdictions)


EU_CTX = {"context": lambda c: c.update(jurisdictions=["EU"], hipaa_role="none")}
EU_OK = {"lawful_basis": "contract", "art9_condition": "health care provision", "destination": "eu-llm"}


class EU01(_EU):
    id, title = "EU-01", "A lawful basis and an Article 9 condition are named"
    fixtures = (Fixture("pass", "named", EU_OK, Outcome.ALLOW, **EU_CTX),
                Fixture("fail", "no-condition", {**EU_OK, "art9_condition": None}, Outcome.DENY, **EU_CTX),
                Fixture("adversarial", "unknown-condition", {**EU_OK, "art9_condition": "legitimate interest"},
                        Outcome.DENY, **EU_CTX))
    CONDITIONS = ("explicit consent", "health care provision", "public health", "scientific research",
                  "vital interests", "legal claims")

    def check(self, req, env):
        if not req.lawful_basis or req.art9_condition not in self.CONDITIONS:
            return "health data needs an Article 6 basis and an Article 9 condition " \
                   f"({', '.join(self.CONDITIONS)})"


class EU03(_EU):
    id, title = "EU-03", "A processor agreement is in force with the provider"
    on_fail = Outcome.ROUTE
    fixtures = (Fixture("pass", "dpa", EU_OK, Outcome.ALLOW, **EU_CTX),
                Fixture("fail", "no-dpa", {**EU_OK, "destination": "clinical-llm"}, Outcome.ROUTE,
                        registries=lambda r: r["eu_transfer_mechanisms"].update({"clinical-llm": "scc"}), **EU_CTX),
                Fixture("adversarial", "lapsed-dpa", EU_OK, Outcome.DENY,
                        models=lambda m: m["models"]["eu-llm"]["agreements"][1].update(expiry="2026-01-01"), **EU_CTX))

    def check(self, req, env):
        a = env.profile.agreement("dpa")
        if a is None or not a.current(env.today):
            return f"no Article 28 processor agreement in force with {env.profile.name}"


class EU04(_EU):
    id, title = "EU-04", "Transfers outside the EEA have a mechanism"
    on_fail = Outcome.ROUTE
    fixtures = (Fixture("pass", "in-eea", EU_OK, Outcome.ALLOW, **EU_CTX),
                Fixture("fail", "us-no-mechanism", {**EU_OK, "destination": "clinical-llm"}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"]["agreements"].append(
                            {"kind": "dpa", "reference": "DPA-A", "signatory": "x", "scope": ["Vendor A Health API"],
                             "start": "2026-01-01", "expiry": "2027-12-31"}), **EU_CTX),
                Fixture("adversarial", "only-eea-route-removed", {**EU_OK, "destination": "clinical-llm"},
                        Outcome.DENY,
                        models=lambda m: (m["models"]["clinical-llm"]["agreements"].append(
                            {"kind": "dpa", "reference": "DPA-A", "signatory": "x", "scope": ["Vendor A Health API"],
                             "start": "2026-01-01", "expiry": "2027-12-31"}), m["models"].pop("eu-llm")), **EU_CTX))

    def check(self, req, env):
        if env.profile.region not in EEA and not env.reg("eu_transfer_mechanisms").get(env.profile.name):
            return f"{env.profile.name} processes in {env.profile.region} with no transfer mechanism on file"


# ================= reg.india (advisory until the core DPDP duties are enforceable) =================
class _IN(GateControl):
    pack, advisory = "reg.india", True

    def applies(self, req, env):
        return "IN" in (req.jurisdictions or env.context.jurisdictions)


IN_CTX = {"context": lambda c: c.update(jurisdictions=["IN"], hipaa_role="none", enforce_advisory=["reg.india"])}


class IN01(_IN):
    id, title = "IN-01", "Consent on file for this purpose (DPDP Act)"
    fixtures = (Fixture("pass", "consented", {"subject": "P-700"}, Outcome.ALLOW, **IN_CTX),
                Fixture("fail", "no-consent", {"subject": "P-100"}, Outcome.DENY, **IN_CTX),
                Fixture("adversarial", "advisory-mode-records-only", {"subject": "P-100"}, Outcome.ALLOW,
                        context=lambda c: c.update(jurisdictions=["IN"], hipaa_role="none")))

    def check(self, req, env):
        if req.purpose not in env.reg("india_consents").get(req.subject or "", []):
            return f"no DPDP consent from {req.subject} for {req.purpose}"


class IN08(_IN):
    id, title = "IN-08", "No transfer to a restricted country"
    on_fail = Outcome.ROUTE
    fixtures = (Fixture("pass", "allowed", {"subject": "P-700"}, Outcome.ALLOW, **IN_CTX),
                Fixture("fail", "restricted", {"subject": "P-700"}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"].update(region="XR"), **IN_CTX),
                Fixture("adversarial", "lower-case", {"subject": "P-700"}, Outcome.ROUTE,
                        models=lambda m: m["models"]["clinical-llm"].update(region="xr"), **IN_CTX))

    def check(self, req, env):
        if env.profile.region.upper() in {r.upper() for r in env.reg("india_restricted_regions")}:
            return f"{env.profile.region} is on the restricted-transfer list"


CONTROLS = (PRV01(), PRV02(), PRV03(), PRV04(), PRV06(), PRV09(), PRV07(), PRV08(), PRV11(), PRV12(), PRV14(), PRV15(),
            SEC08(), SEC14(), SEC15(), BAA02(), BAA04(), BAA05(),
            SEN02(), SEN04(), SEN05(), SEN07(), SEN10(), SEN11(), SEN12(),
            RES01(), RES02(), RES03(), RES04(), RES07(), EU01(), EU03(), EU04(), IN01(), IN08())
REGISTRY = {c.key: c for c in CONTROLS}


def by_control(pack, cid):
    return REGISTRY.get(f"{pack}:{cid}")
