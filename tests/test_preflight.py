"""The pre-model compliance gate (Shio policy pack specification, step 1): every control's fixtures and mutation
test, strictest-wins and order independence, fail-closed, no bypass, no PHI in the record, tool results through the
gate, holds with maker-checker, the bound client, output checks, attestations, the context loader and coverage."""
import dataclasses
import itertools
import json
import random
import sys
import types

import pytest

from shio.governance.preflight import harness
from shio.governance.preflight import world as W
from shio.governance.preflight.bypass import ImportSeal, lint
from shio.governance.preflight.context import ComplianceContext, ContextError
from shio.governance.preflight.controls import CONTROLS, RES_OK
from shio.governance.preflight.model import Effect, GateDenied, Outcome, Result, join

pytest.importorskip("pydantic")
RESULTS = harness.run_all()


# ---------------- every control: fixtures and mutation tests ----------------
@pytest.mark.parametrize("r", RESULTS, ids=lambda r: f"{r.control}/{r.fixture}/{r.kind}")
def test_every_gate_control_fixture_and_mutation(r):
    assert r.ok, r.detail


def test_every_control_has_pass_fail_adversarial_and_a_mutation_test():
    for c in CONTROLS:
        kinds = {f.kind for f in c.fixtures}
        assert {"pass", "fail", "adversarial"} <= kinds, c.key
    assert {r.control for r in RESULTS if r.kind == "mutation"} == {c.key for c in CONTROLS}


# ---------------- strictest wins, order independence ----------------
def test_join_is_the_strictest_outcome_and_order_independent():
    rng = random.Random(3)
    for _ in range(500):
        rs = [Result(f"p:C-{i}", rng.choice(list(Outcome)), effect=Effect(drop_fields=frozenset({f"f{rng.randint(0, 3)}"})),
                     advisory=rng.random() < 0.2) for i in range(rng.randint(0, 6))]
        base = join(rs)
        for perm in itertools.islice(itertools.permutations(rs), 24):
            assert join(perm) == base
        assert base[0] == max([r.outcome for r in rs if not r.advisory], default=Outcome.ALLOW)
        assert join(rs + rs) == base                                      # idempotent


def test_gate_decisions_do_not_depend_on_control_order():
    requests = [fx.request for c in CONTROLS for fx in c.fixtures if not (fx.context or fx.models or fx.registries)]
    with harness.fixture_gate() as gate:
        before = [gate.decide(harness.request(r)).outcome for r in requests]
        rng = random.Random(5)
        for _ in range(3):
            rng.shuffle(gate.controls)
            assert [gate.decide(harness.request(r)).outcome for r in requests] == before


# ---------------- fail closed ----------------
class Boom:
    name = "broken"

    def detect(self, text):
        raise RuntimeError("detector crashed")

    def spans(self, text):
        raise RuntimeError("detector crashed")


def test_fail_closed_every_way():
    with harness.fixture_gate() as gate:
        gate.classifier.detectors = [Boom()]
        assert gate.decide(harness.request({"text": "x"})).outcome is Outcome.DENY            # detector crashes
    with harness.fixture_gate() as gate:
        assert gate.decide(harness.request({"destination": "nope"})).outcome is Outcome.DENY  # profile missing
    with harness.fixture_gate() as gate:
        gate.clock = lambda: (_ for _ in ()).throw(OSError("no clock"))
        assert gate.decide(harness.request({})).outcome is Outcome.DENY                     # clock unreadable
    with harness.fixture_gate() as gate:
        gate.clock = lambda: "2026-11-24"
        assert gate.decide(harness.request({})).outcome is Outcome.DENY                     # clock returns garbage
    with harness.fixture_gate() as gate:
        type(gate.controls[0]).check, saved = (lambda self, r, e: 1 / 0), type(gate.controls[0]).check
        try:
            d = gate.decide(harness.request({}))
        finally:
            type(gate.controls[0]).check = saved
        assert d.outcome is Outcome.DENY and "fail-closed" in d.reasons[0]                  # a rule can't evaluate
    with harness.fixture_gate() as gate:
        gate.chain.path.parent.mkdir(parents=True, exist_ok=True)
        gate.chain.path.mkdir()                                                               # record unwritable
        d = gate.decide(harness.request({}))
        assert d.outcome is Outcome.DENY and "record could not be written" in d.reasons[0]
        with pytest.raises(GateDenied):
            gate.client(d, lambda p, payload: "sent")


def test_expired_attestation_and_corrupt_profile_deny(tmp_path):
    from shio.governance.preflight.gate import _spec_packs, attestation_controls
    packs = _spec_packs()
    ac = [c for c in attestation_controls(packs) if c.kind == "security-risk-analysis"]
    with harness.fixture_gate(attestation_controls=ac) as gate:
        assert gate.decide(harness.request({})).outcome is Outcome.ALLOW
        aid = gate.attestations.current("security-risk-analysis", W.TODAY).id
        gate.attestations.revoke(aid, "L. Brandt", "superseded")
        d = gate.decide(harness.request({}))
        assert d.outcome is Outcome.DENY and "security-risk-analysis" in d.reasons[0]
    with harness.fixture_gate(attestation_controls=ac) as gate:
        gate.clock = lambda: W.TODAY.replace(year=2027, month=3)                              # past its expiry
        assert gate.decide(harness.request({})).outcome is Outcome.DENY
    with pytest.raises(ContextError, match="training_on_inputs"):
        from shio.governance.preflight.context import Profiles
        c, m, r = W.world(models=lambda m: m["models"]["clinical-llm"].pop("training_on_inputs"))
        Profiles.from_dict(m)


def test_context_loading_never_guesses():
    c, _, _ = W.world(context=lambda c: c.pop("hipaa_role"))
    with pytest.raises(ContextError, match="hipaa_role"):
        ComplianceContext.from_dict(c)
    c, _, _ = W.world(context=lambda c: c.update(jurisdictions=["Mars"]))
    with pytest.raises(ContextError, match="Mars"):
        ComplianceContext.from_dict(c)


# ---------------- the record: before the call, no payload ----------------
def test_record_is_written_before_sending_and_holds_no_phi(tmp_path):
    secret = "Mr Daniel Okoro waited 40 minutes on 03/04/2026, phone 415-555-0182."
    sent = []
    with harness.fixture_gate() as gate:
        def transport(profile, payload):
            assert gate.chain.entries()[-1]["request_sha256"] == d.request_sha256           # recorded first
            sent.append(payload)
            return "ok"
        d = gate.decide(harness.request({"role": "analyst", "purpose": "operations", "fields": {"metric": "wait"},
                                         "text": secret}))
        assert d.outcome is Outcome.REDACT
        gate.client(d, transport).send()
        raw = gate.chain.path.read_text()
        entry = gate.chain.entries()[-1]
        ok, problems = gate.chain.verify()
    assert ok, problems
    assert "Okoro" not in raw and "415-555" not in raw and "03/04/2026" not in raw
    assert "Okoro" not in json.dumps(sent) and "[[NAME-1]]" in sent[0]["text"]
    assert entry["payload_sha256"] == d.payload_sha256 and entry["context_sha256"] and entry["classes"]
    assert {r["control"] for r in entry["results"]} >= {"med.hipaa.privacy:PRV-09"}


def test_tool_results_and_fed_back_output_go_through_the_gate():
    with harness.fixture_gate() as gate:
        for source in ("tool", "document", "retrieved", "model_output"):
            d = gate.decide(harness.request({"source": source, "text": "From the psychotherapy notes: ..."}))
            assert d.outcome is Outcome.DENY, source
            assert gate.chain.entries()[-1]["source"] == source


# ---------------- the bound client ----------------
def test_the_client_is_bound_to_one_approved_payload_and_sends_once():
    with harness.fixture_gate() as gate:
        d = gate.decide(harness.request({}))
        c = gate.client(d, lambda profile, payload: f"to {profile.name}")
        assert c.send() == "to clinical-llm"
        with pytest.raises(GateDenied, match="already used"):
            c.send()
        tampered = dataclasses.replace(d, payload={"fields": {"reason": "something else"}, "text": ""})
        with pytest.raises(GateDenied, match="payload changed"):
            gate.client(tampered, lambda p, x: "sent").send()
        held = gate.decide(harness.request({"whole_record": True}))
        with pytest.raises(GateDenied):
            gate.client(held, lambda p, x: "sent")


def test_route_sends_to_the_approved_profile():
    with harness.fixture_gate() as gate:
        d = gate.decide(harness.request({"destination": "general-llm"}))
        assert d.outcome is Outcome.ROUTE and d.destination == "clinical-llm"
        assert gate.client(d, lambda p, x: p.name).send() == "clinical-llm"


# ---------------- holds ----------------
def test_holds_need_the_named_role_and_maker_checker():
    from shio.governance.chain import ChainError
    with harness.fixture_gate() as gate:
        d = gate.decide(harness.request({"whole_record": True}))
        assert d.outcome is Outcome.HOLD and d.approvers == {"privacy_officer"}
        with pytest.raises(ChainError, match="needs approval by privacy_officer"):
            gate.approve(d.hold_id, "L. Brandt", "security_officer")
        with pytest.raises(ChainError, match="not the privacy_officer named"):
            gate.approve(d.hold_id, "Someone Else", "privacy_officer")
        gate.approve(d.hold_id, "P. Okafor", "privacy_officer", "transfer of care")
        released = gate.release(d.hold_id)
        assert released.outcome is Outcome.ALLOW and released.payload is not None
    with harness.fixture_gate(fx=types.SimpleNamespace(context=lambda c: c["responsible_roles"].update(
            privacy_officer="dr.mensah"), models=None, registries=None)) as gate:
        d = gate.decide(harness.request({"whole_record": True}))
        with pytest.raises(ChainError, match="maker-checker"):
            gate.approve(d.hold_id, "dr.mensah", "privacy_officer")


def test_an_approved_hold_never_clears_a_denial():
    with harness.fixture_gate() as gate:
        d = gate.decide(harness.request({"whole_record": True, "caller": "service"}))
        assert d.outcome is Outcome.DENY and d.hold_id is None                              # strictest wins


# ---------------- output (stage O) ----------------
def test_output_check_catches_leaks_and_unknown_tokens():
    with harness.fixture_gate() as gate:
        d = gate.decide(harness.request({"role": "analyst", "purpose": "operations", "fields": {"metric": "wait"},
                                         "text": "Mr Daniel Okoro waited on 03/04/2026."}))
        assert gate.check_output(d, "[[NAME-1]] waited 40 minutes.") is None
        assert gate.check_output(d, "Call dana@example.com").outcome is Outcome.DENY
        assert gate.check_output(d, "[[NAME-7]] waited").outcome is Outcome.DENY
        vault = gate.vaults[d.request_sha256]
        assert vault.reinsert({"patient": "[[NAME-1]]", "summary": "[[NAME-1]] waited"}, {"patient"}) == \
            {"patient": "Mr Daniel Okoro", "summary": "[[NAME-1]] waited"}               # never inside free text
        assert "Okoro" not in repr(vault)


def test_a_redaction_that_leaves_identifiers_holds():
    from shio.governance.preflight.classify import PhiPatternDetector

    class Blind(PhiPatternDetector):          # a first-pass detector that misses everything
        def spans(self, text):
            return []

        def detect(self, text):
            return set()

    with harness.fixture_gate() as gate:
        gate.classifier.detectors = [Blind()]
        d = gate.decide(harness.request({"role": "analyst", "purpose": "operations", "fields": {"metric": "wait"},
                                         "text": "call 415-555-0182"}))
        assert d.outcome is Outcome.HOLD and "identifiers left after redaction" in " ".join(d.reasons)


# ---------------- warnings, advisory mode ----------------
def test_agreement_expiring_within_60_days_warns_in_the_record():
    fx = types.SimpleNamespace(context=None, registries=None,
                               models=lambda m: m["models"]["clinical-llm"]["agreements"][0].update(expiry="2027-01-10"))
    with harness.fixture_gate(fx) as gate:
        d = gate.decide(harness.request({}))
        assert d.outcome is Outcome.ALLOW
        warns = [w for r in gate.chain.entries()[-1]["results"] for w in r["warnings"]]
        assert any("expires in 47 days" in w for w in warns)


def test_india_pack_is_advisory_unless_enforced():
    advisory = types.SimpleNamespace(context=lambda c: c.update(jurisdictions=["IN"], hipaa_role="none"),
                                     models=None, registries=None)
    with harness.fixture_gate(advisory) as gate:
        d = gate.decide(harness.request({"subject": "P-100"}))
        assert d.outcome is Outcome.ALLOW
        r = next(x for x in gate.chain.entries()[-1]["results"] if x["control"] == "reg.india:IN-01")
        assert r["advisory"] and r["outcome"] == "deny"                                    # recorded, not enforced


# ---------------- no bypass ----------------
def test_lint_finds_every_way_to_import_a_model_sdk(tmp_path):
    (tmp_path / "agent.py").write_text("import anthropic\nfrom openai import OpenAI\nimport importlib\n"
                                       "m = importlib.import_module('mistralai')\nx = __import__('cohere')\n")
    (tmp_path / "transport.py").write_text("import anthropic\n")
    (tmp_path / "fine.py").write_text("import json\nfrom shio.governance.preflight import Gate\n")
    found = lint([tmp_path], allow=[tmp_path / "transport.py"])
    assert sorted((f.split("/")[-1], line) for f, line, _ in found) == [("agent.py", 1), ("agent.py", 2),
                                                                        ("agent.py", 4), ("agent.py", 5)]


def test_the_runtime_seal_refuses_a_direct_import():
    fake = types.ModuleType("fake_model_sdk")
    fake.call = lambda: "sent"
    sys.modules["fake_model_sdk"] = fake
    try:
        with ImportSeal({"fake_model_sdk"}) as seal:
            with pytest.raises(ImportError, match="sealed"):
                import fake_model_sdk  # noqa: F401
            assert seal.module("fake_model_sdk").call() == "sent"            # the transport's way in
        import fake_model_sdk  # noqa: F401,F811                              # restored after the seal
    finally:
        sys.modules.pop("fake_model_sdk", None)


def test_shio_itself_has_no_bypass():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    found = lint([root / "shio", root / "examples"], allow=[root / "shio" / "models.py"])
    assert found == [], found


# ---------------- packs and coverage ----------------
def test_spec_packs_validate_and_their_gate_proofs_run():
    from shio.governance.packs import builtin, validate
    from shio.governance.preflight.gate import SPEC_PACKS
    have = builtin()
    for pid in SPEC_PACKS:
        ok, problems, pack = validate(have[pid])
        assert ok, (pid, problems)
    priv = validate(have["med.hipaa.privacy"])[2]
    assert {p.kind.value for c in priv.controls for p in c.proofs} >= {"gate", "attestation"}


def test_a_pack_naming_a_gate_control_that_does_not_exist_is_refused(tmp_path):
    import shutil
    from shio.governance.packs import BUILTIN, validate
    dest = tmp_path / "med.hipaa.privacy"
    shutil.copytree(BUILTIN / "med.hipaa.privacy", dest)
    d = json.loads((dest / "pack.json").read_text())
    d["controls"][0]["proof"] = [{"kind": "gate", "control": "PRV-99"}]
    (dest / "pack.json").write_text(json.dumps(d))
    ok, problems, _ = validate(dest)
    assert not ok and any("no control med.hipaa.privacy:PRV-99" in p for p in problems)


def test_coverage_matrix_marks_planned_as_not_covered_and_never_claims_compliance(tmp_path):
    from shio.governance.preflight import coverage
    from shio.governance.preflight.attest import AttestationLedger
    ledger = AttestationLedger(tmp_path / "a")
    ledger.attest("security-risk-analysis", "security_officer", "L. Brandt", "2026-02-01", "2027-02-01", "0" * 64)
    m = coverage.matrix(ledger=ledger, today=W.TODAY)
    rows = {(r["pack"], r["control"]): r for r in m["rows"]}
    assert rows[("med.hipaa.privacy", "PRV-01")]["coverage"] == "enforced"
    assert rows[("med.hipaa.breach", "BRE-03")]["coverage"] == "planned"
    assert rows[("med.hipaa.security", "SEC-01")]["attestation"]["state"] == "current"
    assert rows[("med.hipaa.security", "SEC-02")]["attestation"]["state"] == "missing"
    md = coverage.markdown(m)
    assert "compliant" not in md.replace("not a statement that the organisation is compliant", "")
    assert "FTC Health Breach Notification Rule" in md
