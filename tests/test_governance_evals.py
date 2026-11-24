"""The eval harness (D14): metrics per slice, gates, regressions against a baseline, and red-team suites derived from
every pack's adversarial fixtures."""
import json

import pytest

from shio.governance import evals
from shio.governance.assess import check_seal
from shio.governance.packs import builtin

from governance_helpers import keys


def _suite(cases, **kw):
    return evals.Suite("regression", [evals.Case(**c) for c in cases], **kw)


def toy(inp):
    if inp.get("boom"):
        raise RuntimeError("bad input")
    return {"status": "OK" if inp["x"] > 0 else "REVIEW", "rejected": inp["x"] <= 0}


CASES = [{"id": f"c{i}", "input": {"x": x}, "expect": {"status": s}, "slices": {"site": site}}
         for i, (x, s, site) in enumerate([(1, "OK", "a"), (2, "OK", "a"), (3, "OK", "a"), (-1, "REVIEW", "b"),
                                           (5, "OK", "b"), (0, "OK", "b")])]


def test_metrics_per_slice_and_gap():
    r = evals.run(_suite(CASES, metrics=[{"name": "pass_rate"}, {"name": "max_slice_gap", "min_n": 3}]), toy)
    assert r["passed"] == 5 and r["metrics"]["pass_rate"] == pytest.approx(5 / 6, abs=1e-6)
    assert r["slices"]["site"]["a"]["pass_rate"] == 1.0 and r["slices"]["site"]["b"]["pass_rate"] == pytest.approx(2 / 3, abs=1e-6)
    assert r["metrics"]["max_slice_gap"] == pytest.approx(1 / 3, abs=1e-4)
    failed = [x for x in r["results"] if not x["passed"]]
    assert [x["id"] for x in failed] == ["c5"] and "expected 'OK'" in failed[0]["detail"]


def test_a_gate_not_met_fails_the_run():
    r = evals.run(_suite(CASES, gates={"pass_rate": [">=", 0.95]}), toy)
    assert r["gate_failures"] and not r["gates"]["pass_rate"]["ok"]


def test_regression_against_a_baseline_fails_ci():
    base = evals.run(_suite(CASES[:5]), toy)
    worse = evals.run(_suite(CASES[:4] + [{**CASES[4], "input": {"x": -5}}]), toy)
    regressions = evals.compare(worse, base)
    assert any(r.startswith("metric pass_rate") for r in regressions)
    assert any("case c4: passed in the baseline, fails now" in r for r in regressions)
    assert evals.compare(base, base) == []
    assert evals.compare(worse, base, tolerance=0.5) == [x for x in regressions if x.startswith("case")]


def test_a_crashing_target_fails_that_case_only():
    r = evals.run(_suite([{"id": "ok", "input": {"x": 1}, "expect": {"status": "OK"}},
                          {"id": "boom", "input": {"x": 1, "boom": True}, "expect": {"status": "OK"}}]), toy)
    assert [x["passed"] for x in r["results"]] == [True, False] and "RuntimeError" in r["results"][1]["detail"]


def test_label_rates_measure_catches_and_wrongful_rejections():
    cases = [{"id": "g1", "input": {"x": 1}, "labels": {"good": True}}, {"id": "g2", "input": {"x": -1}, "labels": {"good": True}},
             {"id": "h1", "input": {"x": -2}, "labels": {"hallucinated": True}}]
    r = evals.run(_suite(cases, metrics=[{"name": "caught", "kind": "label_rate", "label": "hallucinated",
                                          "field": "rejected", "value": True},
                                         {"name": "wrongful", "kind": "label_rate", "label": "good",
                                          "field": "rejected", "value": True}]), toy)
    assert r["metrics"] == {"caught": 1.0, "wrongful": 0.5}


def test_results_are_sealed_and_signed(tmp_path):
    pytest.importorskip("cryptography")
    signer, pub = keys(tmp_path)
    r = evals.run(_suite(CASES), toy, signer, subject={"release_sha256": "x"})
    assert check_seal(r, pub) == (True, []) and r["subject"] == {"release_sha256": "x"}
    r["metrics"]["pass_rate"] = 1.0
    assert not check_seal(r, pub)[0]


def test_red_team_cases_are_derived_from_every_packs_adversarial_fixtures():
    suite = evals.derive_redteam(*builtin())
    packs_with_checks = {c.slices["pack"] for c in suite.cases}
    assert {"med.phi", "med.grounding", "med.rx", "med.triage", "med.trial", "med.monitor", "med.change"} <= packs_with_checks
    r = evals.run(suite, evals.pack_check_target)
    assert r["cases"] >= 25 and r["gate_failures"] == [], [x for x in r["results"] if not x["passed"]]
    assert all(x["origin"] for x in r["results"])


def test_suite_files_refuse_duplicate_case_ids(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"format": "shio-eval-suite/1", "suite": "s", "cases": [{"id": "a"}, {"id": "a"}]}))
    with pytest.raises(evals.EvalError, match="twice"):
        evals.Suite.load(f)
