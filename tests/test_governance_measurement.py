"""Phase 2 measurement: generate-then-verify (D16), change-impact replay (D17), control effectiveness (D18)."""

import pytest

pytest.importorskip("cryptography", reason="signed records need the [regulated] extra")
import json

from shio.governance import effectiveness, gtv, impact
from shio.ledger import label, signoff
from shio.models import replay

from governance_helpers import keys, run_referral

SOURCE = ("Reason for referral: declining kidney function over 12 months.\nMedication: Metformin 500 mg twice daily.\n"
          "Results: eGFR 38 mL/min, down from 52 mL/min; HbA1c 7.9%.\n")


def test_the_three_option_ladder():
    text = ("Referred for declining kidney function over 12 months. Takes metformin 500 mg twice daily. "
            "eGFR is 38 mL/min. Started insulin glargine last week.")
    two = gtv.verify(text, SOURCE, gtv.Option.VERIFY_AND_DROP)
    assert two.dropped == ["Started insulin glargine last week."] and "1 unsupported sentence removed" in two.output
    three = gtv.verify(text, SOURCE, gtv.Option.VERIFY_AND_REJECT)
    assert three.rejected and three.output is None
    one = gtv.verify(None, SOURCE, gtv.Option.STRUCTURED_ONLY,
                     claims=[{"text": "on metformin", "quote": "Metformin 500 mg twice daily"},
                             {"text": "on insulin", "quote": "insulin glargine 20 units"}])
    assert [c["text"] for c in one.kept] == ["on metformin"] and "insulin" not in one.output


def test_a_changed_figure_is_never_supported():
    r = gtv.verify("eGFR is 83 mL/min.", SOURCE, 2)
    assert r.dropped and r.checks[0].missing_figures == ["83 mL/min"]


def test_wrongful_rejection_of_good_text_is_reported_per_option():
    cases = [{"id": "a", "source": SOURCE,
              "text": "Referred for declining kidney function. Takes metformin 500 mg twice daily.",
              "sentences": [True, True], "claims": [{"text": "x", "quote": "declining kidney function", "good": True}]},
             {"id": "b", "source": SOURCE,
              "text": "Kidney function has been getting worse for a year. eGFR 38 mL/min.",
              "sentences": [True, True], "claims": [{"text": "y", "quote": "kidney getting worse", "good": True}]},
             {"id": "c", "source": SOURCE, "text": "eGFR 83 mL/min. Takes metformin 500 mg twice daily.",
              "sentences": [False, True], "claims": [{"text": "z", "quote": "eGFR 83", "good": False}]}]
    m = gtv.measure(cases)
    assert set(m) == {"STRUCTURED_ONLY", "VERIFY_AND_DROP", "VERIFY_AND_REJECT"}
    assert m["VERIFY_AND_REJECT"]["wrongful_rejection"] == 0.5     # the paraphrased good text is rejected
    assert m["VERIFY_AND_DROP"]["pass_through"] == 0.0              # the wrong figure never gets through
    assert m["STRUCTURED_ONLY"]["wrongful_rejection"] == 0.5 and m["STRUCTURED_ONLY"]["pass_through"] == 0.0


def test_swapping_a_model_reports_exactly_which_decisions_change(tmp_path):
    import referral_support as s
    signer, _ = keys(tmp_path / "k")
    outs = run_referral(tmp_path / "records", signer, letters=("L001", "L002", "L003", "L004"))
    records = [rec for _, rec in outs]

    def candidate(req):          # a new model that slips a figure, but only on two of the letters
        out = json.loads(s.careful_reader(req))
        if "Achebe" in req.sources[0].text or "Tanaka" in req.sources[0].text:
            out["findings"] = out["findings"].replace("38", "83").replace("9.8", "98")
        return json.dumps(out)

    with __import__("governance_helpers").runtime(None, signer):
        result = impact.run(records, swap={"referral-mock": replay(candidate, name="referral-mock"),
                                           "pattern-phi-detector": s.detector})
    flipped = sorted(i.file for i in result["items"] if i.status == "FLIPPED")
    assert flipped == sorted([records[0].name, records[3].name])
    assert result["summary"] == {"FLIPPED": 2, "CHECKS_CHANGED": 0, "UNCHANGED": 2, "NOT_REPLAYED": 0}
    item = next(i for i in result["items"] if i.status == "FLIPPED")
    assert item.recorded["status"] == "SUMMARY_READY" and item.now["status"] == "REVIEW"
    with __import__("governance_helpers").runtime(None, signer):
        same = impact.run(records, swap={"referral-mock": s.careful})
    assert same["summary"]["UNCHANGED"] == 4                       # the same model flips nothing


def test_impact_reports_what_cannot_be_replayed(tmp_path):
    signer, _ = keys(tmp_path / "k")
    (_, rec), = run_referral(tmp_path / "records", signer)
    from shio.ledger import erase
    erase(rec, "test erasure", signer)
    with __import__("governance_helpers").runtime(None, signer):
        r = impact.run([rec], model=replay(lambda req: "{}", name="x"))
    assert r["summary"]["NOT_REPLAYED"] == 1 and "erased" in r["items"][0].detail


def test_every_check_shows_its_measured_numbers_from_reviewer_labels(tmp_path):
    signer, _ = keys(tmp_path / "k")
    good = run_referral(tmp_path / "records", signer, letters=("L002", "L004"))
    bad = run_referral(tmp_path / "records", signer, letters=("L001", "L003"), model="sloppy")   # both list allergies
    label(good[0][1], "right", "Dr R. Osei")
    label(bad[0][1], "right", "Dr R. Osei", "checks: figures, complete")      # the blocks were correct
    label(bad[1][1], "wrong", "Dr R. Osei", "checks: complete")               # this block was a false alarm
    signoff(good[1][1], "Dr R. Osei", "clinician", "checked", signer)
    m = effectiveness.measure(tmp_path / "records")
    checks = m["checks"]
    assert m["decisions"] == 4 and m["labelled"] == 3
    assert set(checks) >= {"summarise.grounded", "summarise.figures", "summarise.complete", "summarise.no_identifiers",
                           "summarise.approved", "summarise.detected", "summarise.minimum"}
    assert checks["summarise.complete"]["blocked"] == 2 and checks["summarise.complete"]["upheld"] == 1
    assert checks["summarise.complete"]["overturned"] == 1 and checks["summarise.complete"]["precision"] == 0.5
    assert checks["summarise.figures"]["upheld"] == 1 and checks["summarise.figures"]["unlabelled"] == 1
    assert checks["summarise.grounded"]["blocked"] == 0 and checks["summarise.grounded"]["precision"] is None
    assert checks["summarise.figures"]["controls"] == ["med.grounding@0.1.0:GRD-2"]
    assert "summarise.complete" in effectiveness.report(m)
