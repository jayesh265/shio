"""The live monitor (D25, D27): every checkpoint from a workspace as JSON, served read-only by the console with a
strict content security policy, private by construction (no vault, no readings, no argument values), and cached
against the files it reads."""
import json
import threading
import urllib.error
import urllib.request

import pytest

pytest.importorskip("cryptography", reason="signed records need the [regulated] extra")

from shio.governance import card, monitors
from shio.governance.console import Console, serve
from shio.governance.monitor import SECTIONS, MonitorService, Workspace

from governance_helpers import REFERRAL, keys, run_referral


@pytest.fixture(scope="module")
def ws(tmp_path_factory):
    root = tmp_path_factory.mktemp("ws")
    signer, pub = keys(root / "keys")
    outs = run_referral(root / "records", signer, letters=("L001", "L002"))
    outs += run_referral(root / "records", signer, letters=("L004",), model="sloppy")
    (root / "cards").mkdir()
    c, _ = card.scan(card.load_manifest(REFERRAL / "agent.json"), signer)
    (root / "cards" / "referral.json").write_text(json.dumps(c))
    monitors.open_incident(root / "records", "Test incident", "high", "J. Ortiz", signer=signer)
    try:
        from shio.governance.adapters_ext import agt
    except ImportError:
        agt = None
    if agt is not None and agt.installed_version():
        (root / "policies").mkdir()
        (root / "policies" / "p.yaml").write_text(agt.DEMO_POLICY)
        gate = agt.AgtGate(agt.DEMO_POLICY, ledger=root / "gates", agent="helpdesk", signer=signer)
        refund = gate.wrap(lambda **kw: "ok", action="issue_refund")
        refund(order="SECRET-ORDER-1", amount=10)
        with pytest.raises(agt.AgtDenied):
            refund(order="SECRET-ORDER-2", amount=9000)
    return {"root": root, "pub": pub, "signer": signer}


def test_every_view_answers_and_the_summary_lists_checkpoints(ws):
    m = MonitorService(Workspace(ws["root"]), public_key=ws["pub"])
    for section in SECTIONS:
        assert json.dumps(m.view(section)), section
    s = m.summary()
    by_title = {c["title"]: c for c in s["checkpoints"]}
    assert by_title["Decision ledger intact"]["status"] == "ok"
    assert by_title["Agent cards reviewed"]["status"] == "warn"            # nobody has reviewed the card
    assert by_title["Incidents"]["status"] == "fail" and "1 open" in by_title["Incidents"]["detail"]
    assert by_title["Control packs valid, fixtures pass"]["status"] == "ok"
    assert all(c["status"] in ("ok", "warn", "fail", "none") and c["tab"] for c in s["checkpoints"])
    assert s["kpis"]["decisions"] == 3 and s["kpis"]["open_incidents"] == 1


def test_checks_count_every_run_and_cite_controls(ws):
    m = MonitorService(Workspace(ws["root"]))
    checks = {c["key"]: c for c in m.checks()["checks"]}
    g = checks["summarise.grounded"]
    assert g["runs"] == 3 and g["passed"] + g["failed"] + g["skipped"] == 3
    assert any(c["failed"] for c in checks.values())                         # the sloppy model failed something
    assert any(x.startswith("med.grounding@") for x in g["controls"])
    assert sum(p["passed"] + p["failed"] for p in g["series"]) == g["passed"] + g["failed"]


def test_decisions_filter_and_page(ws):
    m = MonitorService(Workspace(ws["root"]))
    all_rows = m.decisions()
    assert all_rows["total"] == 4 and "summarise" in all_rows["agents"]      # 3 decisions and the incident
    assert all(r["failed"] for r in m.decisions(failed="1")["rows"])
    assert m.decisions(limit=1, offset=1)["rows"][0] == all_rows["rows"][1]
    assert m.decisions(agent="summarise")["total"] == 3
    with pytest.raises(ValueError):
        m.decisions(limit="lots")


def test_a_tampered_ledger_shows_as_failing(ws, tmp_path):
    import shutil
    copy = tmp_path / "ws"
    shutil.copytree(ws["root"], copy)
    rec = next((copy / "records").glob("summarise-*.json"))
    rec.write_text(rec.read_text().replace('"passed": true', '"passed": false', 1))
    s = MonitorService(Workspace(copy), public_key=ws["pub"]).summary()
    assert next(c for c in s["checkpoints"] if c["title"] == "Decision ledger intact")["status"] == "fail"


def test_views_are_cached_until_a_file_changes(ws, tmp_path):
    import shutil
    copy = tmp_path / "ws"
    shutil.copytree(ws["root"], copy)
    m = MonitorService(Workspace(copy))
    first = m.decisions()
    assert m.decisions() is not None and m._cache["decision_rows"][1] is m._decision_rows()   # served from cache
    run_referral(copy / "records", ws["signer"], letters=("L003",))
    assert m.decisions()["total"] == first["total"] + 1                       # a new record: re-read


def test_the_monitor_never_shows_patient_data_or_argument_values(ws):
    con = Console(workspace=ws["root"])
    for section in SECTIONS:
        status, body = con.api(section, {})
        assert status == 200, section
        for secret in ("Achebe", "Solberg", "Riverside Health Centre", "SECRET-ORDER"):
            assert secret not in body, (section, secret)


def test_console_serves_the_monitor_with_a_strict_csp_and_stays_read_only(ws):
    con = Console(workspace=ws["root"])
    srv = serve(con, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/monitor") as r:
            csp = r.headers["Content-Security-Policy"]
            assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp
            assert "frame-ancestors 'none'" in csp and r.headers["X-Frame-Options"] == "DENY"
            assert '<script src="/static/monitor.js"' in r.read().decode()
        with urllib.request.urlopen(base + "/static/monitor.js") as r:
            js = r.read().decode()
            assert r.headers["Content-Type"].startswith("text/javascript")
            import re
            assert not re.search(r"\.(inner|outer)HTML\s*=|insertAdjacentHTML|document\.write|\beval\(|new Function", js)
        with urllib.request.urlopen(base + "/api/summary") as r:
            assert r.headers["Content-Type"].startswith("application/json") and json.loads(r.read())["checkpoints"]
            assert r.headers["Cache-Control"] == "no-store"
        for bad in ("/static/../console.py", "/static/console.py", "/api/nope", "/api/summary/../x"):
            with pytest.raises(urllib.error.HTTPError) as err:
                urllib.request.urlopen(base + bad)
            assert err.value.code == 404, bad
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(urllib.request.Request(base + "/api/summary", data=b"{}", method="POST"))
        assert err.value.code == 405
        with pytest.raises(urllib.error.HTTPError) as err:                    # DNS rebinding: a foreign Host
            urllib.request.urlopen(urllib.request.Request(base + "/api/summary", headers={"Host": "evil.example"}))
        assert err.value.code == 403
        with urllib.request.urlopen(base + "/") as r:                          # the classic pages: still no scripts
            assert "script-src" not in r.headers["Content-Security-Policy"]
    finally:
        srv.shutdown()


def test_an_empty_workspace_says_no_data_instead_of_failing(tmp_path):
    s = MonitorService(Workspace(tmp_path)).summary()
    by_title = {c["title"]: c["status"] for c in s["checkpoints"]}
    assert by_title["Decision ledger intact"] == "none" and by_title["Eval results"] == "none"
    assert by_title["Control packs valid, fixtures pass"] == "ok"           # the built-in packs are always there


def test_gate_view_reads_agt_decisions(ws):
    pytest.importorskip("agentmesh.governance")
    m = MonitorService(Workspace(ws["root"]), public_key=ws["pub"])
    g = m.gates()
    assert g["total"] == 2 and g["chains"][0]["verified"] and g["by_effect"] == {"allowed": 1, "denied": 1}
    assert g["by_rule"][0]["rule"] == "refund-cap"
    p = m.policies()
    assert p["installed"] and p["policies"][0]["ok"] and p["policies"][0]["policies"][0]["rules"]


def test_the_demo_workspace_builds_and_every_view_has_data(tmp_path):
    from shio.governance import demo
    root = demo.build(tmp_path / "demo", days=30, log=lambda *a: None)
    from shio.ledger import load_public_key
    m = MonitorService(Workspace(root), public_key=load_public_key(root / "keys" / "shio-signing.pub"))
    s = m.summary()
    by_title = {c["title"]: c["status"] for c in s["checkpoints"]}
    assert by_title["Decision ledger intact"] == "ok" and by_title["Eval gates met"] == "ok"
    assert by_title["Drift and failure-rate monitors"] == "fail"            # the seeded drift fires
    assert s["kpis"]["decisions"] > 100 and m.bundles()["bundles"] and m.evals()["documents"]
    assert len({c["agent"] for c in m.checks()["checks"]}) >= 2              # both reference agents ran
    if m.policies()["installed"]:
        assert m.gates()["total"] > 50 and by_title["Gate ledgers intact"] == "ok"
    p = m.preflight()
    assert p["total"] > 50 and p["verified"] and {"allow", "deny", "hold"} <= set(p["by_outcome"])
    assert any(a["state"] == "missing" for a in p["attestations"])
    assert {c["title"] for c in s["checkpoints"] if c["area"] == "Pre-model gate"} >= {"Gate ledger intact",
                                                                                      "Attestations current"}
    with pytest.raises(demo.DemoError, match="not empty"):
        demo.build(root)
