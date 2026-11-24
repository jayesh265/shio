"""The Microsoft Agent Governance Toolkit (AGT) backend: its policies on any agent's tool calls, layered after Shio
Guard, decisions in a signed Shio ledger, approvals bound to the exact call, and fail-safe on every error."""
import json

import pytest

pytest.importorskip("agentmesh.governance", reason="needs shio-lang[agt] (Python 3.11+)")

from shio.governance.adapters import conformance
from shio.governance.adapters_ext import agt
from shio.governance.cedar import PolicyBackend

POLICY = agt.DEMO_POLICY


def helpdesk_tools(gate):
    done = []

    def issue_refund(order, amount):
        done.append(("refund", order, amount))
        return "refunded"

    def send_email(to, body):
        done.append(("email", to))
        return "sent"

    def drop_table(table):
        done.append(("drop", table))

    return done, {f.__name__: gate.wrap(f) for f in (issue_refund, send_email, drop_table)}


def test_agt_policy_is_enforced_on_a_plain_python_agent(tmp_path):
    gate = agt.AgtGate(POLICY, ledger=tmp_path / "gates", agent="helpdesk", requester="intake-bot")
    done, tools = helpdesk_tools(gate)
    assert tools["issue_refund"](order="A-1", amount=40) == "refunded"
    with pytest.raises(agt.AgtDenied, match="refund-cap") as err:
        tools["issue_refund"](order="A-1", amount=900)
    assert err.value.decision.effect == "deny" and not err.value.decision.allowed
    with pytest.raises(agt.AgtDenied, match="block-destructive"):
        tools["drop_table"](table="users")
    with pytest.raises(agt.AgtDenied, match="needs approval"):     # no approver: require_approval is a refusal
        tools["send_email"](to="dana@example.com", body="hi")
    assert done == [("refund", "A-1", 40)]                         # nothing denied ever ran


def test_every_decision_is_a_signed_chained_ledger_entry_without_argument_values(tmp_path):
    from governance_helpers import keys
    pytest.importorskip("cryptography")
    signer, pub = keys(tmp_path / "k")
    gate = agt.AgtGate(POLICY, ledger=tmp_path / "gates", agent="helpdesk", signer=signer)
    _, tools = helpdesk_tools(gate)
    tools["issue_refund"](order="A-1", amount=40)
    with pytest.raises(agt.AgtDenied):
        tools["issue_refund"](order="SECRET-ORDER", amount=900)
    ok, problems, entries = agt.gate_entries(tmp_path / "gates")
    assert ok, problems
    assert [e["decision"]["effect"] for e in entries] == ["allow", "deny"]
    assert entries[1]["decision"]["rule"] == "refund-cap" and entries[1]["policy_sha256"] == gate.backend.sha256
    assert entries[1]["args"] == ["amount", "order"] and "SECRET-ORDER" not in json.dumps(entries)
    assert gate.chain.verify(pub) == (True, [])
    raw = (tmp_path / "gates" / "agt-gate.jsonl").read_text().replace('"deny"', '"allow"')
    (tmp_path / "gates" / "agt-gate.jsonl").write_text(raw)
    assert not agt.gate_entries(tmp_path / "gates")[0]               # an edited decision breaks the chain


def test_require_approval_is_bound_to_the_call_and_maker_checker_holds(tmp_path):
    seen = []

    def approver(req):
        seen.append(req)
        return True, "M. Chen", "checked the recipient"

    gate = agt.AgtGate(POLICY, ledger=tmp_path / "g", agent="helpdesk", requester="intake-bot", approver=approver)
    done, tools = helpdesk_tools(gate)
    assert tools["send_email"](to="dana@example.com", body="hi") == "sent"
    assert seen[0].rule == "send-needs-approval" and seen[0].approvers == ("support-lead",)
    assert seen[0].digest == agt.call_digest("send_email", {"to": "dana@example.com", "body": "hi"})
    assert gate.log[-1]["approval"]["by"] == "M. Chen" and gate.log[-1]["approval"]["call_sha256"] == seen[0].digest
    selfish = agt.AgtGate(POLICY, agent="helpdesk", requester="intake-bot",
                          approver=lambda req: (True, "Intake-Bot", "mine"))
    _, tools = helpdesk_tools(selfish)
    with pytest.raises(agt.AgtDenied):
        tools["send_email"](to="dana@example.com", body="hi")
    assert "maker-checker" in selfish.log[-1]["approval"]["note"]


def test_a_failing_approver_or_engine_is_a_denial_never_a_pass(tmp_path, monkeypatch):
    def broken(req):
        raise RuntimeError("approval service down")

    gate = agt.AgtGate(POLICY, agent="helpdesk", approver=broken)
    _, tools = helpdesk_tools(gate)
    with pytest.raises(agt.AgtDenied):
        tools["send_email"](to="a@example.com", body="x")
    assert "approver failed" in gate.log[-1]["approval"]["note"]

    def boom(*a, **k):
        raise RuntimeError("engine crashed")

    monkeypatch.setattr(gate.backend.engine, "evaluate", boom)
    with pytest.raises(agt.AgtDenied, match="policy engine error"):
        tools["issue_refund"](order="A-1", amount=1)
    assert gate.log[-1]["decision"]["effect"] == "error"


def test_a_missing_or_unreadable_argument_fails_closed():
    raw = agt.AgtBackend(POLICY, strict=False)          # AGT alone: a missing amount reads as 0, "lots" as no match
    assert raw.decide("issue_refund", {"order": "A-1"}).allowed
    assert raw.decide("issue_refund", {"amount": "lots"}).allowed
    strict = agt.AgtBackend(POLICY)                     # Shio's strict layer: a rule it can't rule out denies
    for args in ({"order": "A-1"}, {"amount": "lots"}, {"amount": None}, {"amount": True}):
        d = strict.decide("issue_refund", args)
        assert not d.allowed and d.rule == "refund-cap" and d.layer == "shio-strict", args
        assert "amount.value missing or unreadable" in d.reason
    assert strict.decide("issue_refund", {"amount": "40"}).allowed          # a number in a string is still read
    assert strict.decide("lookup_order", {}).allowed                         # rules for other actions don't apply
    d = strict.decide("send_email", {"to": "a@example.com"})
    assert d.effect == "require_approval" and d.layer == "agt"


def test_strict_layer_never_loosens_agt_and_unknown_approval_rules_still_ask_a_person():
    pol = POLICY + """  - name: pii-export
    condition: "action.type == 'export' and data.contains_pii"
    action: require_approval
    approvers: [privacy-officer]
"""
    b = agt.AgtBackend(pol)
    assert not b.decide("drop_table", {"table": "x"}).allowed               # AGT's denial stands
    d = b.decide("export", {"format": "csv"})                               # contains_pii unknown
    assert d.effect == "require_approval" and d.approvers == ("privacy-officer",) and d.layer == "shio-strict"
    assert b.decide("export", {"data": {"contains_pii": False}}).allowed


def test_a_policy_that_does_not_load_is_refused():
    with pytest.raises(ValueError, match="does not load"):
        agt.AgtBackend("apiVersion: governance.toolkit/v1\nname: bad\nrules:\n  - name: x\n    action: explode\n")


def test_a_rule_agt_could_never_match_is_refused_at_load():
    silent = ("apiVersion: governance.toolkit/v1\nname: p\nrules:\n  - name: cap\n"
              "    condition: \"amount.value > 500 USD\"\n    action: deny\n")
    with pytest.raises(ValueError, match="rule cap.*would never match"):
        agt.AgtBackend(silent)
    assert agt.AgtBackend(silent, strict=False)                             # AGT alone accepts it, and never denies


def test_shio_guard_runs_first_and_either_layer_can_stop_a_call(tmp_path):
    from shio.governance.adapters_ext.frameworks import _scratch_traces, fixture_session
    with _scratch_traces():
        session = fixture_session()      # the user asked to email dana@acme.com
        gate = agt.AgtGate(POLICY, ledger=tmp_path / "g", agent="helpdesk",
                           approver=lambda req: (True, "M. Chen", "ok"), guard=session)
        sent = []
        send = gate.wrap(lambda to, body: sent.append(to) or "sent", action="send_email")
        assert send(to="dana@acme.com", body="Q3 summary") == "sent"            # Guard runs it, AGT approval given
        with pytest.raises(agt.AgtDenied, match="stopped by Shio Guard"):
            send(to="audit@acme-review.co", body="Q3 notes")                    # Guard: not from the user's request
    assert sent == ["dana@acme.com"]
    layers = [e["decision"]["layer"] for e in agt.gate_entries(tmp_path / "g")[2]]
    assert layers == ["agt", "guard"]


def test_backend_interface_check_adapter_and_conformance():
    b = agt.AgtBackend(POLICY)
    assert isinstance(b, PolicyBackend)
    assert b.allowed('Agent::"helpdesk"', "issue_refund", None, {"amount": 10})
    assert not b.allowed('Agent::"helpdesk"', "issue_refund", None, {"amount": 10_000})
    desc = b.describe()
    assert desc["engine"] == "microsoft-agt" and desc["version"] == agt.AGT_VERSION
    assert {r["name"] for r in desc["policies"][0]["rules"]} == {"block-destructive", "refund-cap",
                                                                  "send-needs-approval"}
    check = agt.AgtPolicyCheck()
    r = conformance(check, regulated=True, pin=check.implementation_sha256())
    assert r.ok, [x for x in r.results if not x.ok]
    assert check.manifest.pinned and check.manifest.dependencies[0].version == f"=={agt.AGT_VERSION}"


def test_agt_audit_log_is_imported_with_its_chain_verified():
    from agentmesh.governance import AuditLog
    log = AuditLog()
    log.log(event_type="policy_evaluation", agent_did="helpdesk", action="issue_refund", outcome="deny",
            data={"rule": "refund-cap"})
    out = agt.import_audit(log)
    assert out["verified"] and out["entries"][0]["action"] == "issue_refund" and out["entries"][0]["entry_hash"]
