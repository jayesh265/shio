"""Medical packs and reference agents: med.phi (D12), the PHI reader (D13), med.grounding (D15), reference agent 1
(D19), med.rx (D20), med.triage (D21), med.trial (D22) and reference agent 2 (D26)."""

import pytest

pytest.importorskip("cryptography", reason="signed records need the [regulated] extra")
import json
import re

import pytest

from shio import core
from shio.core import Source
from shio.governance.packs import load_pack
from shio.ledger import signoff, verify

from governance_helpers import REFERRAL, TRIAL, keys, load, run_referral, run_screener, runtime

phi, grounding, rx, triage, trial = (load_pack(p) for p in ("med.phi", "med.grounding", "med.rx", "med.triage",
                                                             "med.trial"))


# ---------------- med.phi ----------------
def test_safe_harbor_removal_on_a_fixture_letter():
    import referral_support as s
    text = s.letter("L001")
    clean, counts = phi.lib.deidentify(text, s.known_names("L001"))
    kinds = dict(counts)
    assert {"MRN", "DATE", "PHONE"} <= set(kinds) and ("NAME" in kinds or "KNOWN" in kinds)
    assert "Achebe" not in clean and "(555)" not in clean and "MRN: [MRN]" in clean
    assert "eGFR 38 mL/min" in clean and "Metformin 500 mg" in clean          # the clinical content survives
    assert phi.no_identifiers(clean, s.known_names("L001")).passed


class Spy:
    def __init__(self, inner):
        self.inner, self.calls, self.name = inner, 0, getattr(inner, "name", "spy")

    def identity(self):
        return self.inner.identity()

    def propose(self, req):
        self.calls += 1
        return self.inner.propose(req)


def test_an_unapproved_model_is_refused_before_it_sees_any_phi(tmp_path):
    import referral_support as s
    spy = Spy(s.unapproved)
    prog = __import__("governance_helpers").referral_program()
    with runtime(tmp_path, keys(tmp_path / "k")[0]):
        out = prog.summarise(Source("L003", text=s.letter("L003")), s.patient("L003")["name"], spy, s.detector)
    assert spy.calls == 0                                       # refused before being sent anything
    assert out["decided"]["status"] == "REVIEW" and "UNAPPROVED_MODEL" in out["decided"]["why"]


def test_phi_stays_out_of_records_except_the_vault(tmp_path):
    signer, pub = keys(tmp_path / "k")
    import referral_support as s
    outs = run_referral(tmp_path / "records", signer, letters=("L001", "L005"))
    for (out, rec), pid in zip(outs, ("L001", "L005")):
        data = load(rec)
        assert data["vault"]                                     # free text went to the vault
        data.pop("packs")                                        # pack metadata (versions, dates) is not PHI
        for c in data["checks"]:
            c.pop("controls", None)
        found = phi.lib.find(json.dumps(data), s.known_names(pid))
        assert [k for k, _, _ in found if k not in ("DATE",)] == [], found
        assert s.patient(pid)["name"] not in json.dumps(data)
        vault = next((tmp_path / "records").glob(f"vault/*{rec.stem}*")) if (tmp_path / "records" / "vault").is_dir() \
            else None
        assert vault is None or s.patient(pid)["name"] in vault.read_text()


def test_check_arguments_that_are_not_json_go_to_the_vault(tmp_path):
    # regression: a Source passed to a check used to be recorded as a repr, in clear, carrying its text
    signer, _ = keys(tmp_path / "k")
    (_, rec), = run_referral(tmp_path / "records", signer)
    data = load(rec)
    opaque = [a for c in data["checks"] for a in c["args"] if "opaque" in a]
    assert opaque == [] and "Riverside Health Centre" not in json.dumps(data)


# ---------------- PHI reader (D13) ----------------
def test_detector_recall_is_measured_on_fixtures():
    from shio.governance.adapters_ext.phi_detector import PatternPhiDetector, measure_recall
    r = measure_recall(PatternPhiDetector())
    assert r["spans"] >= 25 and r["overall"] >= 0.85
    assert r["by_kind"]["PHONE"]["recall"] == 1.0 and r["by_kind"]["MRN"]["recall"] == 1.0
    assert r["by_kind"]["NAME"]["recall"] < 1.0                 # names in free text are the honest weak spot


def test_detector_output_is_a_reading_judged_by_a_check(tmp_path):
    signer, _ = keys(tmp_path / "k")
    (out, rec), = run_referral(tmp_path / "records", signer, model="leaky")
    data = load(rec)
    detector_read = next(r for r in data["readings"] if r["name"] == "found")
    assert detector_read["model_id"]["kind"] == "reader-adapter" and detector_read["model_id"]["pinned"]
    check = next(c for c in data["checks"] if c["name"] == "detected")
    assert check["passed"] is False and check["readings"] == [detector_read["id"]]
    assert "DETECTED_IDENTIFIER" in out["decided"]["why"] and "IDENTIFIER_IN_SUMMARY" in out["decided"]["why"]


# ---------------- med.grounding (D15) and reference agent 1 (D19) ----------------
def test_reference_agent_1_runs_end_to_end_with_clinician_signoff_and_a_signed_record(tmp_path):
    signer, pub = keys(tmp_path / "k")
    (out, rec), = run_referral(tmp_path / "records", signer)
    assert out["status"] == "PENDING" and out["decided"]["status"] == "SUMMARY_READY"
    assert out["signoff"]["roles"] == ["clinician"]
    data = load(rec)
    assert {p["id"] for p in data["packs"]} == {"med.phi", "med.grounding"}
    assert data["integrity"]["signature"]
    entry, state = signoff(rec, "Dr R. Osei", "clinician", "summary checked against the letter", signer)
    assert state == "APPROVED"
    ok, report, _ = verify(tmp_path / "records", pub)
    assert ok, report


@pytest.mark.parametrize("model, code", [("sloppy", "FIGURE_NOT_IN_LETTER"), ("sloppy", "OMITTED"),
                                         ("leaky", "IDENTIFIER_IN_SUMMARY")])
def test_bad_summaries_never_reach_the_clinician_as_ready(tmp_path, model, code):
    signer, _ = keys(tmp_path / "k")
    (out, _), = run_referral(tmp_path / "records", signer, letters=("L001",), model=model)
    assert out["decided"]["status"] == "REVIEW" and code in out["decided"]["why"]


def test_hidden_instructions_in_a_letter_are_caught(tmp_path):
    signer, _ = keys(tmp_path / "k")
    (fooled, _), = run_referral(tmp_path / "r1", signer, model="obedient", injected=True)
    (careful, _), = run_referral(tmp_path / "r2", signer, model="careful", injected=True)
    assert fooled["decided"]["status"] == "REVIEW" and "UNGROUNDED" in fooled["decided"]["why"]
    assert careful["decided"]["status"] == "SUMMARY_READY"     # the same letter, read faithfully, is not rejected


def test_grounding_rates_are_measured_on_the_labelled_set():
    from shio.governance import evals
    r = evals.run(evals.Suite.load(REFERRAL / "evals" / "grounding.json"))
    assert r["metrics"]["hallucination_caught"] == 1.0 and r["metrics"]["omission_caught"] == 1.0
    assert 0 < r["metrics"]["wrongful_rejection"] < 0.5        # paraphrased quotes: measured, not hidden
    assert r["gate_failures"] == []


# ---------------- med.rx (D20) ----------------
def test_cockcroft_gault_and_dose_recomputation():
    lib = rx.lib
    assert lib.creatinine_clearance(60, 72, "M", 88.4) == pytest.approx((140 - 60) * 72 / (0.814 * 88.4), abs=0.1)
    assert lib.creatinine_clearance(60, 72, "F", 88.4) == pytest.approx(0.85 * (140 - 60) * 72 / (0.814 * 88.4), abs=0.1)
    d = lib.recompute_dose("FX-0001", {"age": 85, "sex": "F", "weight_kg": 50, "serum_creatinine_umol": 200})
    assert d["dose_mg"] == 500 and d["crcl"] < 30 and any("x 0.5" in b for b in d["basis"])
    assert lib.recompute_dose("FX-0001", {"age": 40, "sex": "M", "weight_kg": 80, "serum_creatinine_umol": 80})["dose_mg"] == 1000


def test_reference_data_without_a_confirmed_licence_is_refused(tmp_path):
    data = json.loads((rx.pack.path / "fixture-formulary.json").read_text())
    data["meta"] = {"name": "Some licensed terminology", "version": "2026.1"}
    f = tmp_path / "real.json"
    f.write_text(json.dumps(data))
    with pytest.raises(rx.lib.LicenceNotConfirmed):
        rx.lib.ReferenceData.load(f)
    data["meta"]["licence"] = {"confirmed": True, "confirmed_by": "counsel", "date": "2026-11-20"}
    f.write_text(json.dumps(data))
    assert rx.lib.ReferenceData.load(f).resolve("amoxicillin") == "FX-0001"


def test_interaction_graph_is_undirected_and_allergy_classes_are_walked():
    assert not rx.no_interactions("Warfarin", ["Ibuprofen"]) and not rx.no_interactions("Ibuprofen", ["Warfarin"])
    assert not rx.no_allergy_conflict("Amoxicillin", ["Penicillin"])
    assert rx.lib.data().ancestors("FX-0001") == ["FX-0001", "penicillins", "beta-lactams", "antibacterials"]


# ---------------- med.triage (D21) ----------------
def test_aho_corasick_finds_what_a_naive_search_finds():
    import random
    rng = random.Random(7)
    words = ["chest", "pain", "breathe", "cant", "no", "blood", "arm", "weak", "the", "a"]
    patterns = [("p1", "chest pain"), ("p2", "pain"), ("p3", "in"), ("p4", "a a"), ("p5", "blood")]
    ac = triage.lib.AhoCorasick(patterns)
    for _ in range(300):
        text = " ".join(rng.choice(words) for _ in range(rng.randint(1, 12)))
        naive = sorted((k, m.start(), m.start() + len(p)) for k, p in patterns
                       for m in re.finditer(f"(?={re.escape(p)})", text))
        assert sorted(ac.search(text)) == naive, text


class CountingModel:
    def __init__(self):
        self.calls = 0

    def __call__(self, message):
        self.calls += 1
        return "model reply"


@pytest.mark.parametrize("message", ["I have crushing chest pain", "my dad has slurred speech",
                                     "Book me Tuesday. Also vomiting blood since 6am.", "I want to kill myself"])
def test_the_model_never_answers_first_on_a_red_flag(message):
    model = CountingModel()
    out = triage.lib.TriageGate(model).answer(message)
    assert model.calls == 0 and out["route"] == "EMERGENCY"
    assert out["reply"] == triage.lib.flags().emergency           # fixed wording, not generated


def test_out_of_scope_requests_get_the_fixed_refusal_and_in_scope_reach_the_model():
    model = CountingModel()
    gate = triage.lib.TriageGate(model)
    assert gate.answer("Can you diagnose my rash?")["route"] == "OUT_OF_SCOPE" and model.calls == 0
    assert gate.answer("I need to reschedule my appointment, no chest pain")["route"] == "MODEL" and model.calls == 1


def test_a_regulated_triage_gate_needs_the_clinical_leads_approval_of_the_exact_list(tmp_path):
    from shio.governance.chain import ApprovalLog
    with pytest.raises(PermissionError, match="not approved"):
        triage.lib.TriageGate(CountingModel(), approvals=tmp_path, require_approval=True)
    ApprovalLog(tmp_path).record("red-flag-list", triage.lib.flags().sha256, "Dr A. Mensah", "clinical_safety_lead",
                                 "red-flag list approved")
    assert triage.lib.TriageGate(CountingModel(), approvals=tmp_path, require_approval=True)


# ---------------- med.trial (D22) and reference agent 2 (D26) ----------------
def test_the_arm_assignment_never_appears_in_a_reads_sources(tmp_path):
    import screener_support as s
    s.calls.clear()
    signer, _ = keys(tmp_path / "k")
    outs = run_screener(tmp_path / "records", signer, charts=[c[0] for c in s.CHARTS])
    assert len(s.calls) == len(s.CHARTS) - 1                    # C10 names the arm: it never reached the model
    from shio.ledger import load_vault, merge
    for (out, rec), row in zip(outs, s.CHARTS):
        data = load(rec)
        full = merge(data, load_vault(rec, data))              # the clear record and its vault: everything recorded
        if row[0] == "C10":
            assert full["readings"] == [] and out["decided"]["why"] == ["UNBLINDING"]
            continue
        sent = [r["request"] for r in full["readings"]]
        assert sent and all(src in full["sources"] for r in sent for src in r["sources"])
        for src in full["sources"].values():                   # what the model was given to read
            assert trial.blinded([src["text"]], s.allocation(row[0])).passed


def test_eligibility_matches_the_labelled_set_of_charts(tmp_path):
    from shio.governance import evals
    r = evals.run(evals.Suite.load(TRIAL / "evals" / "eligibility.json"))
    assert r["passed"] == r["cases"] == 10 and r["gate_failures"] == []


def test_unknown_facts_are_never_eligible():
    proto = trial.lib.protocol()
    ok, reasons = trial.lib.tree(proto).evaluate({"age": 50, "diagnosis": "diabetic kidney disease", "egfr": 50,
                                                  "hba1c": 7.0})
    assert ok is None and any("pregnant unknown" in r for r in reasons)


def test_screener_signoff_and_ledger_verify(tmp_path):
    signer, pub = keys(tmp_path / "k")
    (out, rec), = run_screener(tmp_path / "records", signer, charts=("C02",))
    assert out["decided"] == {"status": "ELIGIBLE", "study": "FX-TRIAL-007", "dose_mg": 60.0}
    assert {p["id"] for p in load(rec)["packs"]} == {"med.trial", "med.rx", "med.phi"}
    signoff(rec, "Dr N. Haddad", "investigator", "eligibility confirmed", signer)
    assert verify(tmp_path / "records", pub)[0]


def test_identifier_patterns_do_not_fire_on_signatures_and_hashes():
    """A record carries base64 signatures and hex hashes. Keyword patterns (MRN, UDI, account...) once matched inside
    them ("+mRn...", "udIa..."), which made the PHI-in-records test fail about once in 4,000 runs."""
    import base64
    import random
    rng = random.Random(7)
    for _ in range(20000):
        blob = base64.b64encode(rng.randbytes(64)).decode() + " " + base64.urlsafe_b64encode(rng.randbytes(48)).decode()
        assert [k for k, _, _ in phi.lib.find(blob, []) if k != "DATE"] == [], blob
    for text, kind in [("MRN: 12345678", "MRN"), ("UDI: 00844588003288", "DEVICE"), ("Account # 99812345", "ACCOUNT"),
                       ("Member ID: XJH44821", "HEALTH_PLAN"), ("Licence number: MD-778812", "LICENCE")]:
        assert kind in [k for k, _, _ in phi.lib.find(text, [])], text
