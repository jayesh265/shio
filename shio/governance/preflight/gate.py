"""The pre-model compliance gate: one function between an agent and every model client.

    gate = Gate.from_folder("compliance/", records="records/", attestations="attestations/")
    decision = gate.decide(Request(caller="dr.mensah", role="clinician", purpose="treatment",
                                   destination="clinical-llm", fields={...}))
    reading = gate.client(decision, transport).send()        # only an allowed decision yields a client

Each request passes seven steps, cheapest and most decisive first, and every step's result goes in the record:

  1 classify       data classes in the payload (unlabelled free text counts as PHI)
  2 context        who the organisation is, the declared purpose (the compliance context)
  3 destination    the model profile asked for
  4 attestations   organisational duties code can't perform, as current signed attestations
  5 data controls  purpose, authorization, minimum necessary, de-identification
  6 decide         the strictest result wins (Outcome is a total order; results are joined)
  7 record, send, check the output: the signed record is written BEFORE anything is sent

Fail closed. A detector that crashes, a missing profile, an unreadable clock, a control that raises, a record that
can't be written: each is Deny, never a pass. Route re-runs every control against each approved alternative profile
(in preference order) and denies if none passes. Redact drops fields and tokenises identifiers, then runs the
detectors again on what would be sent: any identifier left holds the request.

The record stores references and hashes (request, payload, context, profiles, registries, packs, attestations used),
never the payload. The client a decision yields is bound to that decision's exact payload and can send it once.
"""
import dataclasses
import datetime as dt
import uuid
from pathlib import Path

from ..chain import ApprovalLog, ChainError, SignedChain
from ...ledger import _same_person
from .attest import AttestationLedger
from .classify import Classifier, ObfuscationDetector, PhiPatternDetector, TokenVault
from .context import load
from .controls import ADVISORY_PACKS, CONTROLS, Env, GateControl, pack_active
from .model import Decision, Effect, GateDenied, Outcome, Result, Stage, _thaw, digest, join

RECORD_FORMAT = "shio-preflight/1"


class AttestationControl(GateControl):
    """An organisational duty as a gate control: a current signed attestation of `kind` must exist."""

    def __init__(self, pack, cid, kind, on_fail, owner_role, title=""):
        self.pack, self.id, self.kind, self.on_fail, self.owner_role = pack, cid, kind, on_fail, owner_role
        self.title, self.stage = title or f"attestation: {kind}", Stage.X

    def applies(self, req, env):
        return pack_active(self.pack, req, env)

    def check(self, req, env):
        return None

    def evaluate(self, req, env):
        if not self.applies(req, env):
            return None
        cur = env.attestations.current(self.kind, env.today)
        if cur is None:
            advisory = self.pack in ADVISORY_PACKS and self.pack not in env.context.enforce_advisory
            return Result(self.key, self.on_fail, f"no current signed attestation: {self.kind} (owner "
                                                  f"{self.owner_role})", Effect(approvers=frozenset({self.owner_role})),
                          advisory=advisory)
        warn = (f"attestation {self.kind} expires {cur.expires}",) if (cur.expires - env.today).days <= 30 else ()
        return Result(self.key, Outcome.ALLOW, f"attested by {cur.signed_by} until {cur.expires}",
                      Effect(warnings=warn), attestations=(f"{cur.id}:{cur.kind}:expires {cur.expires}",))


class BoundClient:
    """A client bound to one approved decision: it sends that decision's payload to that destination, once."""

    def __init__(self, gate, decision, transport):
        self._gate, self._decision, self._transport, self._used = gate, decision, transport, False

    def send(self):
        d = self._decision
        if self._used:
            raise GateDenied(dataclasses.replace(d, outcome=Outcome.DENY, reasons=("this approval was already used",)))
        if digest(d.payload) != d.payload_sha256:
            raise GateDenied(dataclasses.replace(d, outcome=Outcome.DENY, reasons=("payload changed after approval",)))
        self._used = True
        return self._transport(self._gate.profiles.get(d.destination), _thaw(d.payload))


@dataclasses.dataclass
class _Held:
    request: object
    decision: Decision
    approvals: list


class Gate:
    def __init__(self, context, profiles, registries, attestations, records=None, controls=CONTROLS,
                 attestation_controls=(), packs=(), classifier=None, clock=dt.date.today, signer=None,
                 disabled=frozenset(), now=None):
        self.context, self.profiles, self.registries = context, profiles, registries
        self.attestations = attestations if isinstance(attestations, AttestationLedger) else \
            AttestationLedger(attestations)
        self.chain = SignedChain(records, "preflight") if records else None
        self.approvals = ApprovalLog(records, "preflight-holds") if records else None
        self.controls = [c for c in (*controls, *attestation_controls) if c.key not in disabled]
        self.packs = list(packs)
        self.classifier = classifier or Classifier(field_classes=registries.part("field_classes"),
                                                   public_fields=registries.data.get("public_fields") or ())
        self.clock, self.signer, self.now = clock, signer, now
        self.vaults, self._held = {}, {}

    @classmethod
    def from_folder(cls, folder, records=None, attestations=None, packs=None, **kw):
        context, profiles, registries = load(folder)
        loaded = list(packs) if packs is not None else _spec_packs()
        return cls(context, profiles, registries, attestations or Path(folder) / "attestations", records,
                   attestation_controls=attestation_controls(loaded), packs=loaded, **kw)

    # ---------------- steps 1 to 6 ----------------
    def _env(self, req, profile, classes, unlabelled, today):
        return Env(self.context, profile, self.profiles, self.registries, self.attestations, today, classes, unlabelled)

    def _evaluate(self, req, env):
        results = []
        for c in self.controls:
            try:
                if c.applies(req, env):
                    self._applied.add(c.key)
                r = c.evaluate(req, env)
            except Exception as e:               # fail closed: a control that raises denies
                r = Result(c.key, Outcome.DENY, f"fail-closed: {c.key} raised {type(e).__name__}")
            if r is not None:
                results.append(r)
        return results

    def _assess(self, req):
        """-> (outcome, effect, results, destination, classes): steps 1 to 6, without side effects."""
        self._applied = set()
        today = self.clock()
        if not isinstance(today, dt.date):
            raise TypeError("the clock did not return a date")
        classes, unlabelled = self.classifier.classify(req)
        profile = self.profiles.get(req.destination)
        if profile is None:
            return Outcome.DENY, Effect(), [Result("gate:destination", Outcome.DENY,
                                                   f"no model profile {req.destination!r}")], req.destination, classes
        results = self._evaluate(req, self._env(req, profile, classes, unlabelled, today))
        outcome, effect = join(results)
        if outcome is Outcome.ROUTE:
            for alt in self.profiles.alternatives(profile.name):
                alt_results = self._evaluate(req, self._env(req, alt, classes, unlabelled, today))
                alt_outcome, alt_effect = join(alt_results)
                if alt_outcome <= Outcome.REDACT:
                    note = Result("gate:route", Outcome.ROUTE, f"routed from {profile.name} to {alt.name}")
                    return Outcome.ROUTE, alt_effect, results + [note] + alt_results, alt.name, classes
            results.append(Result("gate:route", Outcome.DENY, f"no approved profile can take this request instead of "
                                                              f"{profile.name}"))
            return Outcome.DENY, effect, results, profile.name, classes
        return outcome, effect, results, profile.name, classes

    def _payload(self, req, effect):
        fields = {k: v for k, v in _thaw(req.fields).items() if k not in effect.drop_fields}
        text, vault = req.text, None
        if effect.tokenise:
            vault = TokenVault()
            text = vault.tokenise(text, self.classifier.spans(text)) if text else text
            fields = {k: vault.tokenise(v, self.classifier.spans(v)) if isinstance(v, str) else v
                      for k, v in fields.items()}
        return {"fields": fields, "text": text}, vault

    def _residual(self, payload):
        """Second detector pass (PHI-07) over what would actually be sent."""
        det, obf = PhiPatternDetector(), ObfuscationDetector()
        texts = [payload["text"], *[v for v in payload["fields"].values() if isinstance(v, str)]]
        left = {k for t in texts for k, s, e in det.spans(t or "")}
        left |= {f"{k} (disguised)" for t in texts for k in obf.hidden(t or "")}
        return sorted(left)

    # ---------------- step 7 ----------------
    def decide(self, req, approved=None):
        """-> Decision, with its signed record written. Never raises for a policy reason; never sends anything."""
        try:
            outcome, effect, results, destination, classes = self._assess(req)
            if approved:
                results = [dataclasses.replace(r, outcome=Outcome.ALLOW, reason=f"{r.reason} (approved by "
                                                                              f"{approved[r.control]})")
                           if r.outcome is Outcome.HOLD and r.control in approved else r for r in results]
                outcome, effect = join(results)
            payload = payload_sha = vault = None
            if outcome in (Outcome.ALLOW, Outcome.REDACT, Outcome.ROUTE):
                payload, vault = self._payload(req, effect)
                if effect.tokenise:
                    left = self._residual(payload)
                    if left:
                        results.append(Result("med.phi:PHI-07", Outcome.HOLD, f"identifiers left after redaction: "
                                                                             f"{', '.join(left)}",
                                              Effect(approvers=frozenset({"privacy_officer"}))))
                        outcome, effect = join(results)
                        payload = vault = None
                if payload is not None:
                    payload_sha = digest(payload)
            decision = Decision(outcome, req.sha256, destination, tuple(results),
                                tuple(r.reason for r in results if r.enforced > Outcome.ALLOW), classes,
                                payload if outcome <= Outcome.ROUTE else None, payload_sha,
                                approvers=effect.approvers if outcome is Outcome.HOLD else frozenset(),
                                evaluated=tuple(sorted(getattr(self, "_applied", ()))))
        except Exception as e:                   # fail closed: anything unexpected denies
            decision = Decision(Outcome.DENY, getattr(req, "sha256", "?"), getattr(req, "destination", "?"),
                                (Result("gate", Outcome.DENY, f"fail-closed: {type(e).__name__}"),),
                                (f"fail-closed: {type(e).__name__}: {e}"[:200],), frozenset())
            vault = None
        if decision.outcome is Outcome.HOLD:
            hid = f"HOLD-{uuid.uuid4().hex[:10].upper()}"
            decision = dataclasses.replace(decision, hold_id=hid)
            self._held[hid] = _Held(req, decision, [])
        try:
            decision = dataclasses.replace(decision, record=self._record(req, decision))
        except Exception as e:                   # no record, no call
            decision = Decision(Outcome.DENY, decision.request_sha256, decision.destination, decision.results,
                                (f"fail-closed: the decision record could not be written ({type(e).__name__})",),
                                decision.classes)
            vault = None
        if vault is not None:
            self.vaults[decision.request_sha256] = vault
        return decision

    def _record(self, req, d):
        body = {"format": RECORD_FORMAT, "outcome": d.outcome.label, "caller": req.caller, "role": req.role,
                "purpose": req.purpose, "asked_for": req.destination, "destination": d.destination,
                "source": req.source, "classes": sorted(c.value for c in d.classes),
                "request_sha256": d.request_sha256, "payload_sha256": d.payload_sha256,
                "context_sha256": self.context.sha256, "profiles_sha256": self.profiles.sha256,
                "registries_sha256": self.registries.sha256,
                "packs": [p.stamp() for p in self.packs],
                "results": [r.to_dict() for r in d.results],
                "attestations": sorted({a for r in d.results for a in r.attestations}),
                "hold": d.hold_id, "approvers": sorted(d.approvers), "evaluated": list(d.evaluated), "decided": dt.datetime.now().isoformat()}
        if self.now is not None:
            body["time"] = self.now()
        if self.chain is None:
            return body
        return self.chain.append("preflight_decision", body, self.signer)

    # ---------------- sending and output ----------------
    def client(self, decision, transport):
        if not decision.sendable or decision.payload is None or decision.record is None:
            raise GateDenied(decision)
        return BoundClient(self, decision, transport)

    def call(self, req, transport, output_controls=True):
        """decide, send once, check the output. -> (decision, text). Raises GateDenied for deny or hold."""
        d = self.decide(req)
        text = self.client(d, transport).send()
        if output_controls:
            r = self.check_output(d, text)
            if r is not None:
                raise GateDenied(dataclasses.replace(d, outcome=Outcome.DENY, reasons=(r.reason,)))
        return d, text

    def check_output(self, decision, text):
        """PHI-11: the reading may not carry an identifier that wasn't sent, or a token the model should not know."""
        vault = self.vaults.get(decision.request_sha256)
        sent = " ".join([decision.payload.get("text") or "", *map(str, decision.payload.get("fields", {}).values())]) \
            if decision.payload else ""
        leaked = [text[s:e] for k, s, e in PhiPatternDetector().spans(text or "") if k != "DATE" and
                  text[s:e] not in sent]
        import re
        unknown = [t for t in re.findall(r"\[\[[A-Z_]+-\d+\]\]", text or "") if not vault or t not in vault.tokens()]
        if leaked or unknown:
            r = Result("med.phi:PHI-11", Outcome.DENY, f"the reading carries {len(leaked)} identifier(s) not sent and "
                                                      f"{len(unknown)} unknown token(s)")
            if self.chain is not None:
                self.chain.append("preflight_output", {"request_sha256": decision.request_sha256,
                                                       "result": r.to_dict()}, self.signer)
            return r
        return None

    # ---------------- holds ----------------
    def approve(self, hold_id, by, role, note=""):
        """A named person in one of the hold's approver roles approves it. Maker-checker: not the caller."""
        h = self._held.get(hold_id)
        if h is None:
            raise ChainError(f"no hold {hold_id} (holds live with the gate that made them; payloads are never stored)")
        if role not in h.decision.approvers:
            raise ChainError(f"{hold_id} needs approval by {', '.join(sorted(h.decision.approvers))}, not {role}")
        if role in self.context.responsible_roles and not _same_person(by, self.context.responsible_roles[role]):
            raise ChainError(f"{by} is not the {role} named in the compliance context")
        if _same_person(by, h.request.caller):
            raise ChainError("maker-checker: the caller can't approve their own request")
        if self.approvals is not None:
            self.approvals.record("preflight-hold", h.decision.request_sha256, by, role, note or "approved",
                                  makers=[h.request.caller], signer=self.signer, title=hold_id)
        h.approvals.append((by, role))

    def release(self, hold_id):
        """Re-decide a held request with its approvals. Holds approved by someone in an approver role clear; a
        denial anywhere still denies."""
        h = self._held.pop(hold_id, None)
        if h is None or not h.approvals:
            raise ChainError(f"{hold_id}: nothing approved to release")
        by = ", ".join(f"{b} ({r})" for b, r in h.approvals)
        roles = {r for _, r in h.approvals}
        approved = {r.control: by for r in h.decision.results if r.outcome is Outcome.HOLD
                    and (not r.effect.approvers or r.effect.approvers & roles)}
        return self.decide(h.request, approved=approved)


def attestation_controls(packs):
    """One AttestationControl per `attestation` proof in the packs."""
    out = []
    for p in packs:
        for c in p.controls:
            for proof in c.proofs:
                if proof.kind.value == "attestation":
                    out.append(AttestationControl(p.id, c.id, proof.target, Outcome.parse(
                        p.raw_control(c.id).get("on_fail", "hold")), proof.param("owner", "privacy_officer"), c.title))
    return out


SPEC_PACKS = ("med.hipaa.privacy", "med.hipaa.security", "med.hipaa.baa", "med.hipaa.breach", "med.hipaa.records",
              "med.sensitive", "med.research", "reg.eu", "reg.india", "sec.agent", "gov.iso42001", "med.transparency",
              "med.fairness")


def _spec_packs():
    from ..packs import PackError, builtin, read
    have = builtin()
    out = []
    for pid in SPEC_PACKS:
        if pid in have:
            try:
                out.append(read(have[pid]))
            except PackError:
                pass
    return out


def explain(entry):
    """DX-2: a recorded gate decision in plain language, step by step, for someone who doesn't read code."""
    out = [f"Decision: {entry['outcome'].upper()} for a {entry['purpose']} request from {entry['caller']} "
           f"({entry['role']}), {entry.get('source', 'user')} content, to {entry['asked_for']}"
           + (f", sent to {entry['destination']} instead" if entry.get("destination") != entry.get("asked_for") else "")
           + "."]
    out.append(f"1. The content was classed as: {', '.join(entry.get('classes') or ['no health data'])}.")
    stopped = [r for r in entry.get("results", []) if r["outcome"] != "allow" and not r.get("advisory")]
    passed = [r for r in entry.get("results", []) if r["outcome"] == "allow"]
    advisory = [r for r in entry.get("results", []) if r.get("advisory") and r["outcome"] != "allow"]
    atts = entry.get("attestations") or []
    out.append(f"2. {len(passed)} control(s) passed, relying on {len(atts)} current signed attestation(s).")
    if stopped:
        out.append("3. These decided the outcome (the strictest wins):")
        out += [f"   - {r['control']}: {r['outcome']} because {r['reason']}" for r in stopped]
    else:
        out.append("3. Nothing objected, so the request was allowed as asked.")
    if advisory:
        out.append("   Recorded but not enforced (advisory packs): "
                   + "; ".join(f"{r['control']}: {r['reason']}" for r in advisory))
    warns = sorted({w for r in entry.get("results", []) for w in r.get("warnings", [])})
    if warns:
        out.append("   Warnings: " + "; ".join(warns))
    if entry.get("hold"):
        out.append(f"4. Held as {entry['hold']} until one of these roles approves: {', '.join(entry['approvers'])}.")
    out.append(f"The record keeps hashes only (request {str(entry['request_sha256'])[:12]}, payload "
               f"{str(entry.get('payload_sha256') or 'none')[:12]}); the content itself was never stored.")
    return "\n".join(out)
