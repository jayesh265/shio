"""Agent cards (D5), the re-review trigger (D6), and the adapter framework's refusals at build time (D10)."""
import json
import shutil

import pytest

from shio.governance import card
from shio.governance.adapters import Manifest, ReaderAdapter, TrustClass, conformance, sbom
from shio.governance.chain import ChainError

from governance_helpers import REFERRAL, keys

pytest.importorskip("cryptography", reason="signed records need the [regulated] extra")


@pytest.fixture
def agent(tmp_path):
    """A copy of the referral agent's folder, so tests can change its program."""
    dest = tmp_path / "referral"
    shutil.copytree(REFERRAL, dest, ignore=shutil.ignore_patterns("__pycache__", "evals"))
    return dest


def test_card_is_signed_and_describes_the_agent(tmp_path, agent):
    signer, pub = keys(tmp_path / "keys")
    c, problems = card.scan(card.load_manifest(agent / "agent.json"), signer)
    assert problems == []
    assert c["signature"] and card.verify(c, pub) == (True, [])
    assert c["purpose"].startswith("Summarise") and c["audience"] == "clinician"
    assert {m["name"] for m in c["models"]} == {"llm", "detector"} and all(m["pinned"] for m in c["models"])
    assert {x["name"] for x in c["checks"]} >= {"grounded", "figures", "complete", "no_identifiers", "approved"}
    assert c["signoff_roles"] == ["clinician"]
    assert {p["id"] for p in c["packs"]} == {"med.phi", "med.grounding"}
    assert [d["risk_tier"] for d in c["deployments"]] == ["limited", "high"]
    assert "referral_support.py" in c["dependencies"]
    kinds = {p["value"] for comp in c["sbom"]["components"] for p in comp.get("properties", [])}
    assert "reader" in kinds                                      # the SBOM carries the adapter and its trust class


def test_changing_a_tool_changes_the_card_hash(tmp_path, agent):
    c1, _ = card.scan(card.load_manifest(agent / "agent.json"))
    prog = agent / "referral.shio"
    prog.write_text(prog.read_text().replace("codes:", "def notify(to, body):\n    return to\n\n"
                                                       "tool notify_team(to: email, body: text) acts = notify\n\ncodes:"))
    c2, _ = card.scan(card.load_manifest(agent / "agent.json"))
    assert c1["sha256"] != c2["sha256"]
    assert [t["name"] for t in c2["tools"]] == ["notify_team"]
    c3, _ = card.scan(card.load_manifest(agent / "agent.json"))
    assert c3["sha256"] == c2["sha256"]                           # the time it was generated is not in the hash


def test_verify_rejects_an_edited_card(tmp_path, agent):
    signer, pub = keys(tmp_path / "keys")
    c, _ = card.scan(card.load_manifest(agent / "agent.json"), signer)
    edited = json.loads(json.dumps(c))
    edited["deployments"][1]["risk_tier"] = "minimal"
    ok, problems = card.verify(edited, pub)
    assert not ok and any("edited" in p for p in problems)
    resigned = card.sign(card.content(edited))                    # re-hashed but unsigned: a key still rejects it
    assert not card.verify(resigned, pub)[0]
    other_signer, _ = keys(tmp_path / "other")
    assert not card.verify(card.sign(card.content(edited), other_signer), pub)[0]


def test_verify_notices_the_program_changed_since_the_card(agent):
    c, _ = card.scan(card.load_manifest(agent / "agent.json"))
    (agent / "referral.shio").write_text((agent / "referral.shio").read_text() + "\n# a change\n")
    ok, problems = card.verify(c, program=agent / "referral.shio")
    assert not ok and "changed since the card was built" in problems[0]


def test_ci_fails_until_the_right_roles_sign_off_the_exact_hash(tmp_path, agent):
    signer, _ = keys(tmp_path / "keys")
    reviews = tmp_path / "reviews"
    c, _ = card.scan(card.load_manifest(agent / "agent.json"), signer)
    assert card.review_status(c, reviews)[0] is False
    with pytest.raises(card.CardError, match="asks for review by"):
        card.review(c, reviews, "Sam", "intern", "looked at it", signer)
    with pytest.raises(ChainError, match="maker-checker"):
        card.review(c, reviews, "Referrals product team", "governance_reviewer", "mine", signer)
    card.review(c, reviews, "Dr A. Mensah", "clinical_safety_lead", "reviewed", signer)
    ok, lines = card.review_status(c, reviews)
    assert not ok and "governance_reviewer" in lines[1]
    card.review(c, reviews, "J. Ortiz", "governance_reviewer", "reviewed", signer)
    assert card.review_status(c, reviews)[0] is True
    # the card changes: the old reviews no longer apply, and CI fails until it is reviewed again
    prog = agent / "referral.shio"
    prog.write_text(prog.read_text().replace('signoff * by role "clinician"', 'signoff * by role "clinician" and "pharmacist"'))
    c2, _ = card.scan(card.load_manifest(agent / "agent.json"), signer)
    ok, lines = card.review_status(c2, reviews)
    assert not ok and any("re-review required" in line for line in lines)


def test_a_rejection_blocks_the_card(tmp_path, agent):
    c, _ = card.scan(card.load_manifest(agent / "agent.json"))
    card.review(c, tmp_path / "r", "Dr A. Mensah", "clinical_safety_lead", "unsafe", reject=True)
    card.review(c, tmp_path / "r", "J. Ortiz", "governance_reviewer", "fine")
    assert card.review_status(c, tmp_path / "r")[1][0].endswith("REJECTED")


class UnpinnedReader(ReaderAdapter):
    manifest = Manifest("loose-classifier", ">=1.0", TrustClass.READER, "MIT", "deliberately unpinned")

    def read_request(self, req):
        return json.dumps({"value": {"ok": True}})


def test_a_deliberately_unpinned_adapter_is_refused_at_build_time(agent):
    m = card.load_manifest(agent / "agent.json")
    m["adapters"] = m["adapters"] + [{"ref": f"{__name__}:UnpinnedReader"}]
    _, problems = card.scan(m)
    assert any("loose-classifier" in p and "unpinned" in p for p in problems)
    assert any("implementation hash pinned" in p for p in problems)
    r = conformance(UnpinnedReader(), regulated=False)
    assert r.ok                                                  # outside regulated mode it is allowed...
    assert not conformance(UnpinnedReader(), regulated=True).ok  # ...in regulated mode it is refused


def test_an_adapter_whose_code_changed_no_longer_matches_its_pin(agent):
    m = card.load_manifest(agent / "agent.json")
    m["adapters"][0]["sha256"] = "0" * 64
    _, problems = card.scan(m)
    assert any("pinned 0000" in p for p in problems)


def test_regulated_build_refuses_an_unpinned_model(agent):
    m = card.load_manifest(agent / "agent.json")
    del m["models"]["llm"]
    _, problems = card.scan(m)
    assert problems == ["model llm is not pinned for this regulated agent"]


def test_sbom_lists_dependencies_with_licences():
    from shio.governance.adapters_ext.frameworks import OpenAIToolGate
    doc = sbom([(OpenAIToolGate(), "x")])
    names = {c["name"]: c for c in doc["components"]}
    assert names["openai"]["licenses"] == [{"expression": "Apache-2.0"}]
    assert doc["bomFormat"] == "CycloneDX"


def test_manifest_needs_purpose_owner_and_risk_tier(tmp_path, agent):
    m = json.loads((agent / "agent.json").read_text())
    m["deployments"][0]["risk_tier"] = "spicy"
    (agent / "agent.json").write_text(json.dumps(m))
    with pytest.raises(card.CardError, match="risk_tier"):
        card.load_manifest(agent / "agent.json")
