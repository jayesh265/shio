"""The Phase 1 gate and D9: one agent produces a signed agent card and an evidence bundle, and an outsider verifies
both offline with nothing but the public key (shio verify)."""

import pytest

pytest.importorskip("cryptography", reason="signed records need the [regulated] extra")
import datetime as dt
import json
import subprocess
import sys

import pytest

from shio.governance import assess, bundle, card, evals
from shio.governance.chain import ApprovalLog

from governance_helpers import REFERRAL, keys, run_referral


@pytest.fixture(scope="module")
def gate(tmp_path_factory):
    root = tmp_path_factory.mktemp("gate")
    signer, pub = keys(root / "keys")
    m = card.load_manifest(REFERRAL / "agent.json")
    c, problems = card.scan(m, signer)
    assert problems == []
    (root / "card.json").write_text(json.dumps(c))
    (root / "assessment.json").write_text(json.dumps(assess.assess(card.program_path(m), m, signer=signer)))
    outs = run_referral(root / "records", signer, letters=("L001", "L002", "L003"))
    outs += run_referral(root / "records", signer, letters=("L004",), model="sloppy")
    from shio.ledger import signoff
    for _, rec in outs[:2]:
        signoff(rec, "Dr R. Osei", "clinician", "checked against the letter", signer)
    card.review(c, root / "reviews", "Dr A. Mensah", "clinical_safety_lead", "reviewed", signer)
    card.review(c, root / "reviews", "J. Ortiz", "governance_reviewer", "reviewed", signer)
    paths = []
    for name in ("regression", "redteam", "grounding"):
        r = evals.run(evals.Suite.load(REFERRAL / "evals" / f"{name}.json"), signer=signer)
        (root / f"{name}.json").write_text(json.dumps(r))
        paths.append(root / f"{name}.json")
    mon = {"format": "shio-monitoring/1", "sha256": "m" * 64}
    ApprovalLog(root / "reviews").record("monitoring", mon["sha256"], "J. Ortiz", "governance_reviewer", "reviewed",
                                         signer=signer)
    today = dt.date.today()
    b, out = bundle.build(root / "records", "gov.nist-ai-rmf", root / "bundle", today, today, root / "card.json",
                          root / "assessment.json", paths, [root / "reviews"], signer, pub)
    return {"root": root, "pub": pub, "bundle": b, "out": out, "card": c}


def _shio(*args):
    return subprocess.run([sys.executable, "-m", "shio.cli", *map(str, args)], capture_output=True, text=True)


def test_an_outsider_verifies_the_card_and_bundle_offline_with_the_public_key(gate):
    root = gate["root"]
    for target in (root / "card.json", root / "bundle", root / "assessment.json", root / "records"):
        r = _shio("verify", target, "--pubkey", root / "keys" / "shio-signing.pub")
        assert r.returncode == 0 and "VERIFIED" in r.stdout, (target, r.stdout, r.stderr)


def test_every_control_of_the_framework_is_mapped(gate):
    b = gate["bundle"]
    assert len(b["controls"]) == 11
    status = {c["id"]: c["status"] for c in b["controls"]}
    assert status["GOV-2"] == "EVIDENCED"            # a not-applicable proof (no acting tools) is not a gap
    assert status["GOV-1"] == "EVIDENCED" and status["GOV-11"] == "EVIDENCED"
    assert status["GOV-9"] == "EVIDENCED"            # runtime evidence: records citing med.phi PHI-1
    assert b["ledger"]["verified"] is True and all(a["ok"] for a in b["attachments"].values())
    gov9 = next(c for c in b["controls"] if c["id"] == "GOV-9")["evidence"][0]
    assert gov9["checks_run"] == 4 and gov9["cited_as"] == ["med.phi@0.1.0:PHI-1"]
    md = (gate["out"] / "bundle.md").read_text()
    assert "does not state compliance" in md and "compliant" not in md.replace("compliance", "")


def test_a_tampered_bundle_fails_verification(gate, tmp_path):
    import shutil
    copy = tmp_path / "bundle"
    shutil.copytree(gate["out"], copy)
    data = json.loads((copy / "bundle.json").read_text())
    data["controls"][0]["status"] = "EVIDENCED" if data["controls"][0]["status"] != "EVIDENCED" else "GAP"
    (copy / "bundle.json").write_text(json.dumps(data))
    ok, lines = bundle.verify(copy, gate["pub"])
    assert not ok and any("bundle.json: changed" in x for x in lines)


def test_a_file_slipped_into_a_bundle_or_an_edited_attachment_is_caught(gate, tmp_path):
    import shutil
    copy = tmp_path / "b2"
    shutil.copytree(gate["out"], copy)
    (copy / "extra.txt").write_text("added later")
    assert any("not in the manifest" in x for x in bundle.verify(copy, gate["pub"])[1])
    copy3 = tmp_path / "b3"
    shutil.copytree(gate["out"], copy3)
    att = copy3 / "attachments" / "card.json"
    c = json.loads(att.read_text())
    c["purpose"] = "something else"
    att.write_text(json.dumps(c))
    ok, lines = bundle.verify(copy3, gate["pub"])
    assert not ok and any("attachments/card.json" in x for x in lines)


def test_verifying_against_the_wrong_key_fails(gate, tmp_path):
    _, other = keys(tmp_path / "other")
    assert not bundle.verify(gate["out"], other)[0]


def test_bundle_without_evidence_reports_missing_not_evidenced(gate, tmp_path):
    today = dt.date.today()
    b, _ = bundle.build(gate["root"] / "records", "gov.nist-ai-rmf", tmp_path / "bare", today, today)
    status = {c["id"]: c["status"] for c in b["controls"]}
    assert status["GOV-3"] == "MISSING" and status["GOV-6"] == "MISSING"
    assert status["GOV-9"] == "EVIDENCED"


def test_cli_builds_a_framework_bundle(gate, tmp_path):
    root = gate["root"]
    today = dt.date.today().isoformat()
    r = _shio("evidence", root / "records", "--from", today, "--to", today, "-o", tmp_path / "cli-bundle",
              "--framework", "gov.nist-ai-rmf", "--card", root / "card.json", "--assessment", root / "assessment.json",
              "--eval", root / "regression.json", "--approvals", root / "reviews")
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "cli-bundle" / "bundle.md").exists() and "evidenced" in r.stdout
