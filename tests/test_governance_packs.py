"""Packs (D2, D7): the format, the validator, hash pinning, the runtime citing pack versions, OSCAL export."""
import json
import shutil

import pytest

from shio import core
from shio.governance import Verdict
from shio.governance.packs import (BUILTIN, PackError, builtin, load_pack, read, to_oscal, tree_sha256, validate)

from governance_helpers import runtime


def test_every_builtin_pack_validates_with_its_fixtures():
    found = builtin()
    assert {"med.phi", "med.grounding", "gov.nist-ai-rmf", "med.rx", "med.triage", "med.trial", "med.monitor",
            "med.change", "med.cds", "eu.ai-act", "in.icmr", "in.dpdp", "in.cdsco"} <= set(found)
    for pid, folder in found.items():
        ok, problems, _ = validate(folder)
        assert ok, (pid, problems)


def test_two_sample_controls_pass_the_validator():
    # the D2 gate: at least two sample controls pass (here, every runtime control of med.phi with its fixtures)
    ok, problems, pack = validate(BUILTIN / "med.phi")
    assert ok and len([c for c in pack.controls if c.proofs_of("runtime")]) >= 2


@pytest.fixture
def pack_copy(tmp_path):
    dest = tmp_path / "med.phi"
    shutil.copytree(BUILTIN / "med.phi", dest, ignore=shutil.ignore_patterns("__pycache__"))
    return dest


def _edit(folder, fn):
    d = json.loads((folder / "pack.json").read_text())
    fn(d)
    (folder / "pack.json").write_text(json.dumps(d))


def test_validator_refuses_a_compliance_claim_without_review(pack_copy):
    _edit(pack_copy, lambda d: d.update(description="Makes your agent compliant with HIPAA."))
    ok, problems, _ = validate(pack_copy)
    assert not ok and any("compliant" in p for p in problems)
    _edit(pack_copy, lambda d: d.update(status="reviewed", review={"counsel": {"name": "C", "date": "2026-11-01"},
                                                                  "clinical_lead": {"name": "L", "date": "2026-11-02"}}))
    assert validate(pack_copy)[0]


def test_validator_needs_pass_fail_and_adversarial_fixtures(pack_copy):
    f = pack_copy / "fixtures" / "minimum_necessary.json"
    d = json.loads(f.read_text())
    d["cases"] = [c for c in d["cases"] if c["kind"] != "adversarial"]
    f.write_text(json.dumps(d))
    ok, problems, _ = validate(pack_copy)
    assert not ok and any("adversarial" in p for p in problems)


def test_validator_runs_fixtures_and_catches_a_broken_check(pack_copy):
    src = (pack_copy / "checks.py").read_text()
    (pack_copy / "checks.py").write_text(src.replace('if found:\n        return Verdict.fail', 'if False:\n        return Verdict.fail'))
    ok, problems, _ = validate(pack_copy)
    assert not ok and any("no_identifiers" in p and "expected to fail" in p for p in problems)


@pytest.mark.parametrize("edit, fragment", [
    (lambda d: d.update(version="1.0"), "not semantic"),
    (lambda d: d.update(id="Med PHI"), "lower-case"),
    (lambda d: d.update(licence="MIT OR (Apache-2.0"), "licence"),
    (lambda d: d["controls"][0]["proof"].append({"kind": "lint", "proof": "no-such-proof"}), "lint proof"),
    (lambda d: d["controls"][0]["refs"].append({"framework": "undeclared", "ref": "x"}), "does not declare"),
    (lambda d: d["controls"].append(dict(d["controls"][0])), "used twice"),
    (lambda d: d["controls"][0]["proof"].append({"kind": "eval", "suite": "s"}), "numeric"),
])
def test_validator_reports_malformed_packs(pack_copy, edit, fragment):
    _edit(pack_copy, edit)
    ok, problems, _ = validate(pack_copy)
    assert not ok and any(fragment in p for p in problems), problems


def test_readme_must_state_limits(pack_copy):
    (pack_copy / "README.md").write_text("# med.phi\n\nNo limits section.\n")
    ok, problems, _ = validate(pack_copy)
    assert not ok and any("Limits" in p for p in problems)


def test_any_file_change_changes_the_tree_hash_and_a_pin_refuses_it(pack_copy):
    before = tree_sha256(pack_copy)
    rt = load_pack(str(pack_copy), sha256=before)
    assert rt.pack.sha256 == before
    (pack_copy / "fixtures" / "no_identifiers.json").write_text(
        (pack_copy / "fixtures" / "no_identifiers.json").read_text().replace("Type 2", "Type II"))
    assert tree_sha256(pack_copy) != before
    with pytest.raises(PackError, match="pinned"):
        load_pack(str(pack_copy), sha256=before)


def test_a_pack_whose_fixtures_fail_is_never_loaded(pack_copy):
    (pack_copy / "checks.py").write_text((pack_copy / "checks.py").read_text().replace(
        "def no_identifiers(text, known=()):", "def no_identifiers(text, known=()):\n    return Verdict.ok('x')\n\n"
                                               "def _old(text, known=()):"))
    with pytest.raises(PackError, match="does not validate"):
        load_pack(str(pack_copy))


def test_records_cite_the_pack_name_version_and_control():
    # the D7 gate: a program loads a pack, its checks run, and the record cites the pack and the control
    phi = load_pack("med.phi")

    @core.agent(name="cite_probe")
    def probe(text):
        ok = core.check(lambda t: phi.no_identifiers(t), name="clean")(text)
        return {"clean": ok}

    with runtime():
        out = probe("Call 555-201-3344")
    run = core.last_run["run"].to_dict()
    assert out == {"clean": False}
    assert run["packs"] == [phi.stamp()] and run["packs"][0]["version"] == "0.1.0"
    check = run["checks"][0]
    assert check["controls"] == ["med.phi@0.1.0:PHI-1"]
    assert "identifiers remain" in check["detail"] and "555" not in check["detail"]   # never the value itself


def test_pack_checks_return_verdicts_that_cannot_be_flipped():
    v = load_pack("med.phi").no_identifiers("email a@b.org")
    assert isinstance(v, Verdict) and not v and bool(v) is False
    with pytest.raises(AttributeError):
        v._passed = True
    with pytest.raises(AttributeError, match="no runtime check"):
        load_pack("med.phi").deidentify


def test_oscal_export_carries_every_control_and_its_proofs():
    pack = read(BUILTIN / "gov.nist-ai-rmf")
    cat = to_oscal(pack)["catalog"]
    controls = [c for g in cat["groups"] for c in g["controls"]]
    assert cat["metadata"]["oscal-version"] == "1.1.2" and cat["metadata"]["version"] == pack.version
    assert len(controls) == len(pack.controls)
    assert all(any(p["name"] == "proof" for p in c["props"]) for c in controls)
    assert to_oscal(pack)["catalog"]["uuid"] == cat["uuid"]           # deterministic
