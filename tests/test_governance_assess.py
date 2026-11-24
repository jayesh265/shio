"""shio assess (D8): control proofs over every code path of a program hash, and a negative test for each proof
showing it fails when the code breaks the control (the build plan's "negative tests for every guarantee")."""

import pytest

pytest.importorskip("cryptography", reason="signed records need the [regulated] extra")
import shutil

import pytest

from shio.governance import assess
from shio.governance.assess import FAILED, NOT_APPLICABLE, PROVEN, PROOFS, Program, check_seal
from shio.governance.card import load_manifest

from governance_helpers import REFERRAL, TRIAL, keys


@pytest.fixture
def agent(tmp_path):
    dest = tmp_path / "referral"
    shutil.copytree(REFERRAL, dest, ignore=shutil.ignore_patterns("__pycache__", "evals"))
    return dest


def _prove(pid, program, manifest=None):
    return PROOFS[pid].prove(program if isinstance(program, Program) else Program.load(program), manifest)


def test_reference_agents_prove_at_least_three_controls_for_every_path(tmp_path):
    signer, pub = keys(tmp_path / "k")
    for folder, prog in ((REFERRAL, "referral.shio"), (TRIAL, "screener.shio")):
        m = load_manifest(folder / "agent.json")
        doc = assess.assess(folder / prog, m, signer=signer)
        status = {p["proof"]: p["status"] for p in doc["proofs"]}
        for must in ("readings-through-rules", "models-pinned", "regulated-mode", "signoff-required", "pack-wired"):
            assert status[must] == PROVEN, (prog, must, doc["proofs"])
        assert doc["summary"][FAILED] == 0 and doc["summary"][PROVEN] >= 3
        assert all(p["covered"] > 0 for p in doc["proofs"] if p["status"] == PROVEN)
        assert "Imported Python modules are trusted" in doc["scope"]
        assert check_seal(doc, pub) == (True, [])
        assert {c["control"] for c in doc["controls"]} >= {"PHI-2", "PHI-5"}


def test_examples_prove_the_boundary_with_no_false_alarms():
    import glob
    for f in sorted(glob.glob(str(REFERRAL.parent.parent / "**" / "*.shio"), recursive=True)):
        if f.endswith("_unsafe.shio"):
            continue
        p = Program.load(f)
        for pid in ("readings-through-rules", "tools-gated", "no-reflection"):
            assert _prove(pid, p).status != FAILED, (f, pid, _prove(pid, p).findings)


# ---------------- negative tests: each proof fails when the code breaks its control ----------------
def _compiled_with(agent, find, replace):
    p = Program.load(agent / "referral.shio")
    assert find in p.py
    return Program(p.path, p.source, p.py.replace(find, replace, 1), p.lines + [0] * 5, p.meta)


def test_readings_through_rules_fails_when_a_reading_reaches_plain_code(agent):
    # the compiler would refuse this at the .shio level; the proof analyses the compiled program independently
    broken = _compiled_with(agent, "    decide = __shio_rule_summarise_decide_", "    leaked = s\n    decide = __shio_rule_summarise_decide_")
    r = _prove("readings-through-rules", broken)
    assert r.status == FAILED and "reading 's'" in r.findings[0].message
    broken = _compiled_with(agent, "    return decide", "    return {'summary': s}")
    assert _prove("readings-through-rules", broken).status == FAILED
    broken = _compiled_with(agent, "    decide = __shio_rule_summarise_decide_", "    print(s)\n    decide = __shio_rule_summarise_decide_")
    assert "passed to print()" in _prove("readings-through-rules", broken).findings[0].message


def test_tools_gated_fails_when_an_acting_tool_is_called_outside_a_rule():
    src = ("tool send_email(to: email, body: text) acts = send\n"
           "def send(to, body):\n    return to\n\n"
           "agent a(x: str):\n    rule r:\n        return call send_email(to='a@b.co', body='hi')\n    return r\n")
    import shio
    py, lines = shio.compile_source(src)
    meta = shio.compiler.program_map(src)
    good = Program.from_python(py, meta, source=src)
    assert _prove("tools-gated", good).status == PROVEN
    bad_py = py.replace("    r = __shio_rule_a_r_1()", "    __shio.tool_call(__shio_tools__, 'send_email')(to='x@y.co', body='')\n"
                                                          "    r = __shio_rule_a_r_1()")
    assert bad_py != py
    assert _prove("tools-gated", Program.from_python(bad_py, meta, source=src)).status == FAILED


def test_models_pinned_fails_for_an_unpinned_model(agent):
    m = load_manifest(agent / "agent.json")
    assert _prove("models-pinned", agent / "referral.shio", m).status == PROVEN
    loose = {**m, "models": {"llm": {"kind": "openai_compat", "model": "latest"}, "detector": m["models"]["detector"]}}
    r = _prove("models-pinned", agent / "referral.shio", loose)
    assert r.status == FAILED and "no digest or pinned version" in r.findings[0].message
    assert _prove("models-pinned", agent / "referral.shio", {**m, "models": {}}).status == FAILED
    src = 'model m = ollama("qwen3:8b")\nagent a(x: str):\n    read r: str by m:\n        say {x}\n    return 1\n'
    p = Program.from_python(__import__("shio").compile_source(src)[0], __import__("shio").compiler.program_map(src))
    assert _prove("models-pinned", p).status == FAILED


def test_regulated_mode_fails_when_the_pragma_is_removed(agent):
    prog = agent / "referral.shio"
    assert _prove("regulated-mode", prog).status == PROVEN
    prog.write_text(prog.read_text().replace("\nregulated\n", "\n"))
    assert _prove("regulated-mode", prog).status == FAILED


def test_signoff_required_fails_when_the_signoff_is_removed(agent):
    m = load_manifest(agent / "agent.json")
    prog = agent / "referral.shio"
    prog.write_text(prog.read_text().replace('    signoff * by role "clinician"\n', ""))
    r = _prove("signoff-required", prog, m)
    assert r.status == FAILED and any("SUMMARY_READY" in f.message for f in r.findings)
    assert _prove("signoff-required", prog, {**m, "requires_signoff": None}).status == NOT_APPLICABLE


def test_signoff_required_fails_for_a_conditional_signoff(agent):
    m = load_manifest(agent / "agent.json")
    prog = agent / "referral.shio"
    prog.write_text(prog.read_text().replace('signoff * by role "clinician"',
                                             'signoff SUMMARY_READY when False by role "clinician"'))
    assert _prove("signoff-required", prog, m).status == FAILED


def test_no_reflection_fails_when_a_reflection_route_appears(agent):
    broken = _compiled_with(agent, "    return decide", "    x = locals()\n    return decide")
    assert _prove("no-reflection", broken).status == FAILED


def test_pack_wired_fails_when_a_pack_check_is_not_called(agent):
    m = load_manifest(agent / "agent.json")
    prog = agent / "referral.shio"
    src = prog.read_text()
    call = "grounding.figures_in_source([s.history, s.findings] + [m.dose for m in s.medications], letter_text.text)"
    assert call in src
    prog.write_text(src.replace(call, "len(s.findings) > 0"))
    r = _prove("pack-wired", prog, m)
    assert r.status == FAILED and "figures_in_source" in r.findings[0].message


def test_dependencies_pinned_fails_for_a_wrong_adapter_pin(agent):
    m = load_manifest(agent / "agent.json")
    assert _prove("dependencies-pinned", agent / "referral.shio", m).status == PROVEN
    m["adapters"][0]["sha256"] = "f" * 64
    assert _prove("dependencies-pinned", agent / "referral.shio", m).status == FAILED


def test_cds_posture_fails_when_the_card_contradicts_it(agent):
    m = load_manifest(agent / "agent.json")
    assert _prove("cds-posture", agent / "referral.shio", m).status == PROVEN
    m["decision_support"] = {**m["decision_support"], "time_critical": True}
    r = _prove("cds-posture", agent / "referral.shio", m)
    assert r.status == FAILED and "CDS-5" in r.findings[0].message
    m["packs"] = [{"id": "med.phi"}]
    m["decision_support"]["time_critical"] = False
    assert "CDS-4" in _prove("cds-posture", agent / "referral.shio", m).findings[0].message


def test_an_edited_assessment_fails_its_seal(tmp_path):
    signer, pub = keys(tmp_path / "k")
    doc = assess.assess(REFERRAL / "referral.shio", load_manifest(REFERRAL / "agent.json"), signer=signer)
    doc["proofs"][0]["status"] = "PROVEN" if doc["proofs"][0]["status"] != "PROVEN" else "FAILED"
    assert not check_seal(doc, pub)[0]
