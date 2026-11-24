"""Phases 3 and 4: the policy-to-checks compiler (D23), the safety case (D24), the console (D25), monitors and
incidents (D27), med.monitor (D28), promotion (D29), Cedar interop (D31), further adapters (D32), the Credo sink
(D33) and the open pack registry (D35)."""

import pytest

pytest.importorskip("cryptography", reason="signed records need the [regulated] extra")
import datetime as dt
import json
import shutil
import threading
import time
import urllib.error
import urllib.request

import pytest

from shio import core
from shio.governance import card, cedar, evals, monitors, policy_compiler as pc, promote, safety
from shio.governance.chain import ApprovalLog, SignedChain
from shio.governance.packs import BUILTIN, load_pack
from shio.ledger import verify, write

from governance_helpers import REFERRAL, keys, load, run_referral, runtime

POLICY = """1. The refund amount must not exceed 500 USD.
2. The claim must include a receipt number.
3. The currency must be one of USD, EUR or GBP.
4. Any refund over 200 USD requires approval by a finance manager.
5. Staff should be polite to customers."""


# ---------------- D23 ----------------
def test_policy_becomes_draft_checks_tests_and_a_traceability_matrix():
    doc = pc.compile_policy(POLICY, "claim", "refunds.txt")
    by_clause = {r["clause"]: r for r in doc["matrix"]}
    assert set(by_clause) == {"1", "2", "3", "4", "5"}
    assert by_clause["1"]["draft"] and by_clause["1"]["tests_pass"] is True and len(by_clause["1"]["tests"]) == 3
    assert by_clause["4"]["kind"] == "signoff"
    assert by_clause["5"]["draft"] is None and "needs a person" in by_clause["5"]["status"]
    d1 = next(d for d in doc["drafts"] if d["clause_id"] == "1")
    assert d1["code"].startswith("check refund_amount_d1: claim.refund_amount <= 500")
    assert pc.compile_policy(POLICY, "claim", "refunds.txt")["drafts"][2]["sha256"] == doc["drafts"][2]["sha256"]


def test_every_draft_needs_a_recorded_human_approval(tmp_path):
    doc = pc.compile_policy(POLICY, "claim", "refunds.txt")
    lines, pending = pc.export(doc, tmp_path)
    assert len(lines) == 1 and len(pending) == len(doc["drafts"])   # nothing exported without approval
    pc.approve(doc, "D1", tmp_path, "M. Chen", "policy_owner")
    lines, pending = pc.export(doc, tmp_path)
    assert any("refund_amount_d1" in x for x in lines) and "D1" not in pending
    assert pc.status(doc, tmp_path)["D1"] == "APPROVED" and pc.status(doc, tmp_path)["D2"] == "PENDING"


def test_exported_drafts_compile_as_shio(tmp_path):
    doc = pc.compile_policy(POLICY, "claim", "refunds.txt")
    for d in doc["drafts"]:
        pc.approve(doc, d["id"], tmp_path, "M. Chen", "policy_owner")
    lines, _ = pc.export(doc, tmp_path)
    checks = "\n".join("    " + x.split("    #")[0] for x in lines[1:] if x.startswith("check"))
    signoffs = "\n".join("    " + x.split("    #")[0] for x in lines[1:] if x.startswith("signoff"))
    src = (f"type Claim:\n    refund_amount: float\n    receipt_number: str\n    currency: str\n\n"
           f"agent refund(form: str, llm):\n    read claim: Claim by llm:\n        Read the claim. {{form}}\n"
           f"{checks}\n    rule decide:\n        return {{'status': 'REFUND', 'amount': claim.refund_amount}}\n"
           f"{signoffs}\n    return decide\n")
    import shio
    shio.to_code(src, "drafts.shio")


# ---------------- D24 ----------------
def test_safety_case_is_rebuilt_from_records_and_needs_the_clinical_lead(tmp_path):
    signer, pub = keys(tmp_path / "k")
    run_referral(tmp_path / "records", signer, letters=("L001", "L002"))
    run_referral(tmp_path / "records", signer, letters=("L003",), model="sloppy")
    m = card.load_manifest(REFERRAL / "agent.json")
    from shio.governance.assess import assess
    a = assess(card.program_path(m), m, signer=signer)
    g = evals.run(evals.Suite.load(REFERRAL / "evals" / "grounding.json"), signer=signer)
    today = dt.date.today()
    case = safety.build("summarise", ["med.phi", "med.grounding"], tmp_path / "records", today, today, a, [g],
                        signer=signer)
    ids = {h["id"] for h in case["hazards"]}
    assert ids == {"HAZ-PHI-1", "HAZ-GRD-1", "HAZ-GRD-2"}
    grd1 = next(h for h in case["hazards"] if h["id"] == "HAZ-GRD-1")
    assert grd1["initial_risk"] == safety.rating(4, 3) and grd1["residual_risk"] <= grd1["initial_risk"]
    ctl = next(c for c in grd1["controls"] if c["id"] == "GRD-2")
    assert ctl["status"] == "EVIDENCED" and ctl["effectiveness"]["summarise.figures"]["blocked"] == 1
    assert case["status"].startswith("DRAFT")
    out = safety.write(case, tmp_path / "case", tmp_path / "approvals")
    assert "PENDING" in (out / "safety-case.md").read_text()
    safety.approve(case, tmp_path / "approvals", "Dr A. Mensah", signer=signer)
    safety.write(case, tmp_path / "case", tmp_path / "approvals")
    assert "**APPROVED**" in (tmp_path / "case" / "safety-case.md").read_text()


# ---------------- D25 ----------------
@pytest.fixture
def console_dirs(tmp_path):
    signer, _ = keys(tmp_path / "k")
    run_referral(tmp_path / "records", signer, letters=("L001",))
    (tmp_path / "cards").mkdir()
    c, _ = card.scan(card.load_manifest(REFERRAL / "agent.json"), signer)
    (tmp_path / "cards" / "summarise.json").write_text(json.dumps(c))
    return tmp_path


def test_a_compliance_user_finds_a_controls_evidence_without_the_command_line(console_dirs):
    from shio.governance.console import Console
    con = Console(console_dirs / "records", console_dirs / "cards", None, console_dirs / "reviews")
    status, page = con.handle("/controls?q=PHI-1")
    assert status == 200 and "/control/med.phi/PHI-1" in page
    status, page = con.handle("/control/med.phi/PHI-1")
    assert status == 200 and "summarise-" in page and "passed" in page
    status, page = con.handle("/queue")
    assert status == 200 and "clinician" in page and "waiting for review" in page
    for path in ("/", "/records", "/cards", "/card/summarise.json", "/bundles"):
        assert con.handle(path)[0] == 200, path


def test_the_console_is_read_only_and_never_opens_the_vault_or_other_files(console_dirs):
    from shio.governance.console import Console, handler_for, serve
    con = Console(console_dirs / "records", console_dirs / "cards")
    assert con.handle("/record/..%2F..%2Fetc%2Fpasswd")[0] == 404
    assert con.handle("/card/../records/ledger.jsonl")[0] == 404
    rec = next(p.name for p in (console_dirs / "records").glob("summarise-*.json"))
    page = con.handle(f"/record/{rec}")[1]
    assert "Achebe" not in page and "Riverside Health Centre" not in page
    srv = serve(con, "127.0.0.1", 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/"
        with urllib.request.urlopen(url) as resp:
            assert resp.status == 200 and "script-src" not in resp.headers["Content-Security-Policy"]
            assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
        for method in ("POST", "PUT", "DELETE"):
            with pytest.raises(urllib.error.HTTPError) as err:
                urllib.request.urlopen(urllib.request.Request(url, data=b"x", method=method))
            assert err.value.code == 405
    finally:
        srv.shutdown()


def test_console_escapes_what_it_shows(console_dirs):
    from shio.governance.console import Console
    c = load(console_dirs / "cards" / "summarise.json")
    c["purpose"] = "<script>alert(1)</script>"
    (console_dirs / "cards" / "summarise.json").write_text(json.dumps(c))
    page = Console(console_dirs / "records", console_dirs / "cards").handle("/cards")[1]
    assert "<script>" not in page and "&lt;script&gt;" in page


# ---------------- D27, D28 ----------------
def _seed(folder, signer, start, days, outcome_for):
    """Decisions with chosen outcomes on chosen days (records written straight to the ledger)."""
    for d in range(days):
        day = start + dt.timedelta(days=d)
        ts = time.mktime(day.timetuple()) + 3600
        for i in range(3):
            status = outcome_for(d, i)
            write({"agent": "summarise", "started": ts, "ended": ts, "inputs": {}, "sources": {}, "readings": [],
                   "checks": [{"name": "grounded", "passed": status == "SUMMARY_READY", "reward": True, "key": None}],
                   "rules": [], "outcome": {"status": status}, "children": [], "slices": {"site": "riverside" if i else
                   "harbour"}}, folder, f"seed-{day.isoformat()}-{i}", signer=signer)


def test_an_alert_fires_on_seeded_drift_and_an_incident_becomes_a_signed_record(tmp_path):
    signer, pub = keys(tmp_path / "k")
    today = dt.date(2026, 11, 20)
    rec = tmp_path / "records"
    _seed(rec, signer, today - dt.timedelta(days=69), 56, lambda d, i: "SUMMARY_READY" if i else "REVIEW")
    calm = monitors.monitor(rec, today - dt.timedelta(days=14), window_days=14, baseline_days=42)
    assert [a for a in calm["alerts"] if a["kind"] == "drift"] == []
    _seed(rec, signer, today - dt.timedelta(days=13), 14, lambda d, i: "REVIEW")           # the drift
    r = monitors.monitor(rec, today, window_days=14, baseline_days=56)
    kinds = {a["kind"] for a in r["alerts"]}
    assert "drift" in kinds and "check_drift" in kinds and r["metrics"]["outcome_psi"] > monitors.PSI_ALERT
    alert = next(a for a in r["alerts"] if a["kind"] == "drift")
    iid, path = monitors.open_incident(rec, "Summaries rejected far more often", "high", "J. Ortiz", alert,
                                       r["files"][:2], signer=signer)
    monitors.update_incident(rec, iid, "INVESTIGATING", "J. Ortiz", "model weights changed?", signer)
    inc = monitors.incidents(rec)
    assert inc[0]["incident"] == iid and inc[0]["status"] == "INVESTIGATING" and len(inc[0]["history"]) == 2
    assert load(path)["integrity"]["signature"]
    ok, report, _ = verify(rec, pub)
    assert ok, report
    from shio.evidence import collect
    data = collect(rec, today - dt.timedelta(days=100), today)
    assert data["events"]["incident"] == 1 and data["decisions"] == (56 + 14) * 3   # incidents aren't decisions
    rep = monitors.report(r, signer)
    ApprovalLog(tmp_path / "reviews").record("monitoring", rep["sha256"], "J. Ortiz", "governance_reviewer", "ok")
    assert ApprovalLog(tmp_path / "reviews").status(rep["sha256"], ["governance_reviewer"])[0] == "APPROVED"


def test_incident_refuses_unknown_records_and_severities(tmp_path):
    signer, _ = keys(tmp_path / "k")
    run_referral(tmp_path / "records", signer)
    with pytest.raises(ValueError, match="not records"):
        monitors.open_incident(tmp_path / "records", "x", "high", "me", records=["nope.json"])
    with pytest.raises(ValueError, match="severity"):
        monitors.open_incident(tmp_path / "records", "x", "apocalyptic", "me")


def test_metrics_are_sliced_by_group_and_site_and_safety_events_are_records(tmp_path):
    mon = load_pack("med.monitor")

    @core.agent(name="sliced")
    def sliced(site, band, ok):
        core.check(lambda s, b: mon.slices_recorded({"site": s, "age_band": b}), name="groups")(site, band)
        core.check(lambda v: v, name="quality")(ok)
        return {"status": "OK" if ok else "REVIEW"}

    signer, pub = keys(tmp_path / "k")
    with runtime(tmp_path / "records", signer):
        for i in range(12):
            sliced("riverside" if i % 2 else "harbour", "65+" if i < 6 else "18-39", i % 2 == 1 or i % 4 == 0)
        sliced("riverside", "Jane Okafor", True)              # an identifier offered as a group: not recorded
    recs = sorted((tmp_path / "records").glob("sliced-*.json"))
    sliced_recs = [load(r) for r in recs if "slices" in load(r)]
    assert len(recs) == 13 and len(sliced_recs) == 12          # the one with an identifier as a group: no slices
    assert all(r["slices"]["site"] in ("riverside", "harbour") for r in sliced_recs)
    assert "Jane" not in "".join(r.read_text() for r in recs if "slices" in load(r))
    m = mon.lib.subgroup_metrics(tmp_path / "records", min_n=5)
    assert set(m["groups"]["site"]) == {"riverside", "harbour"}
    assert m["groups"]["site"]["riverside"]["check_failure_rate"] == 0.0
    assert any(f.startswith("site:") for f in m["flags"])
    path = mon.lib.record_safety_event(tmp_path / "records", {"what": "allergy omitted, caught at sign-off",
                                                                "when": "2026-11-20T10:00", "harm": "none",
                                                                "reported_by": "Dr R. Osei",
                                                                "records": [recs[0].name]}, signer)
    assert load(path)["record_type"] == "safety_event" and verify(tmp_path / "records", pub)[0]
    with pytest.raises(ValueError):
        mon.lib.record_safety_event(tmp_path / "records", {"what": "x"}, signer)


# ---------------- D29 ----------------
def test_a_change_without_signoff_cannot_be_promoted(tmp_path):
    signer, pub = keys(tmp_path / "k")
    c, _ = card.scan(card.load_manifest(REFERRAL / "agent.json"), signer)
    suite = evals.Suite.load(REFERRAL / "evals" / "regression.json")
    with pytest.raises(promote.PromotionBlocked) as err:
        promote.promote(c, [], tmp_path / "approvals", tmp_path / "promotions", "pilot", "ops")
    assert any("no regression run" in r for r in err.value.reasons) and any("sign-off" in r for r in err.value.reasons)
    other = evals.run(suite, signer=signer, subject={"release_sha256": "someone-else"})
    run = evals.run(suite, signer=signer, subject=promote.subject_of(c))
    with pytest.raises(promote.PromotionBlocked, match="sign-off pending"):
        promote.promote(c, [other, run], tmp_path / "approvals", tmp_path / "promotions", "pilot", "ops", signer=signer)
    with pytest.raises(Exception, match="maker-checker"):
        promote.approve(c, tmp_path / "approvals", "Referrals product team")
    promote.approve(c, tmp_path / "approvals", "R. Banerjee", signer=signer)
    e = promote.promote(c, [run], tmp_path / "approvals", tmp_path / "promotions", "pilot", "ops", signer=signer,
                        public_key=pub)
    assert e["release"]["program_sha256"] == c["program"]["sha256"]
    assert promote.current(tmp_path / "promotions", "summarise", "pilot")["seq"] == e["seq"]
    assert SignedChain(tmp_path / "promotions", "promotions").verify(pub)[0]
    chg = load_pack("med.change")
    assert chg.release_pinned(promote.release_of(c)) and chg.regression_covers(promote.release_of(c), run)


def test_a_regression_run_that_misses_its_gates_blocks_promotion(tmp_path):
    c, _ = card.scan(card.load_manifest(REFERRAL / "agent.json"))
    s = evals.Suite.load(REFERRAL / "evals" / "regression.json")
    s.gates = {"pass_rate": [">=", 1.01]}
    run = evals.run(s, subject=promote.subject_of(c))
    promote.approve(c, tmp_path / "a", "R. Banerjee")
    ready, reasons, _ = promote.readiness(c, [run], tmp_path / "a")
    assert not ready and any("did not meet its gates" in r for r in reasons)


# ---------------- D31 ----------------
def test_a_cedar_policy_is_enforced_on_a_non_shio_agent():
    refunds = []

    def issue_refund(order, amount):
        refunds.append((order, amount))
        return "refunded"

    def lookup(order):
        return {"order": order, "total": 120}

    gate = cedar.CedarGate("""
        @id("support-tools") permit (principal in Role::"support", action in [Action::"issue_refund", Action::"lookup"], resource);
        @id("cap") forbid (principal, action == Action::"issue_refund", resource) when { context.amount > 100 };
    """, entities={'Agent::"helpdesk"': {"parents": ['Role::"support"']}}, principal='Agent::"helpdesk"')
    tools = {"issue_refund": gate.wrap(issue_refund), "lookup": gate.wrap(lookup)}

    def plain_agent(plan):              # an ordinary Python agent loop, no Shio inside
        out = []
        for name, kwargs in plan:
            try:
                out.append(tools[name](**kwargs))
            except PermissionError as e:
                out.append(f"refused: {e}")
        return out

    out = plain_agent([("lookup", {"order": "A-1"}), ("issue_refund", {"order": "A-1", "amount": 40}),
                       ("issue_refund", {"order": "A-1", "amount": 400.0})])
    assert out[:2] == [{"order": "A-1", "total": 120}, "refunded"] and out[2].startswith("refused: issue_refund: forbidden by cap")
    assert refunds == [("A-1", 40)]
    assert [x["allowed"] for x in gate.log] == [True, True, False]
    gate.principal = 'Agent::"stranger"'
    with pytest.raises(PermissionError, match="no policy permits"):
        tools["lookup"](order="A-2")


def test_cedar_errors_skip_the_policy_and_export_round_trips():
    ps = cedar.parse('@id("p") permit (principal, action, resource) when { context.missing > 1 };')
    d = cedar.authorize(ps, 'U::"a"', 'Action::"x"', 'R::"r"', {})
    assert not d.allowed and d.errors and "missing" in d.errors[0]
    text = '@id("a") permit (principal == User::"ana", action, resource) when { context.n >= 2 && !(context.k == "x") };'
    again = cedar.parse(cedar.to_cedar(cedar.parse(text)))
    for ctx, want in [({"n": 2, "k": "y"}, True), ({"n": 1, "k": "y"}, False), ({"n": 3, "k": "x"}, False)]:
        assert cedar.authorize(again, 'User::"ana"', 'Action::"x"', 'R::"r"', ctx).allowed is want
    assert "default allow := false" in cedar.to_rego(again)
    with pytest.raises(cedar.CedarError):
        cedar.parse("permit (principal, action);")


def test_opa_backend_treats_anything_but_true_as_denial():
    class Resp:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self.body

    seen = []

    def opener(req, timeout):
        seen.append(json.loads(req.data))
        return Resp(json.dumps({"result": seen[-1]["input"]["context"].get("ok")}).encode())

    opa = cedar.OpaBackend("http://opa.local:8181", opener=opener)
    assert opa.allowed("u", "a", "r", {"ok": True}) is True
    assert opa.allowed("u", "a", "r", {"ok": "yes"}) is False
    assert seen[0]["input"]["principal"] == "u"


# ---------------- D32, D33 ----------------
def test_each_adapter_passes_conformance_and_the_licence_check(tmp_path):
    from shio.governance.adapters import conformance
    from shio.governance.adapters_ext import frameworks, integrations
    from shio.governance.adapters_ext.credo import CredoSink
    from shio.governance.adapters_ext.phi_detector import PatternPhiDetector, PresidioPhiDetector
    adapters = [PatternPhiDetector(), frameworks.GuardGate(), frameworks.OpenAIToolGate(), frameworks.ClaudeToolGate(),
                frameworks.LangChainToolGate(), frameworks.MCPToolGate(), integrations.TemporalHost(),
                integrations.JUnitSink(tmp_path), CredoSink(), cedar.CedarCheck(),
                integrations.ValidatorReader(lambda t: {"toxic": "hate" in t}, "keyword-toxicity", "1.0.0", "MIT")]
    for a in adapters:
        r = conformance(a, regulated=True, pin=type(a).implementation_sha256())
        assert r.ok, (type(a).__name__, [x for x in r.results if not x.ok])
    assert PresidioPhiDetector.manifest.extra == "presidio" and PresidioPhiDetector.manifest.pinned


def test_dspy_reader_and_junit_export():
    from shio.governance.adapters_ext.integrations import DSPyReader, to_junit

    class Pred(dict):
        pass

    module = lambda document, question: Pred(answer="ok", length=len(document))  # noqa: E731
    from shio.core import Source

    @core.agent(record=False, name="dspy_probe")
    def probe(src):
        r = core.read(dict, "q", by=DSPyReader(module), sources=[src])
        return core.check(lambda v: v["answer"] == "ok", name="answered")(r)

    assert probe(Source("d", text="hello")) is True
    xml = to_junit({"suite": "s", "cases": 2, "results": [{"id": "a", "passed": True, "detail": ""},
                                                           {"id": "b", "passed": False, "detail": "bad"}],
                    "gate_failures": []}).decode()
    assert 'failures="1"' in xml and 'name="b"' in xml


def test_credo_sink_dry_run_maps_cards_and_bundles(tmp_path):
    from shio.governance.adapters_ext.credo import CredoSink
    c, _ = card.scan(card.load_manifest(REFERRAL / "agent.json"))
    sink = CredoSink(out=tmp_path)
    assert sink.emit(c, "card.json") is None
    payload = json.loads((tmp_path / "card-card.json").read_text())
    assert payload["body"]["metadata"]["shio_card_sha256"] == c["sha256"] and sink.sent[0]["dry_run"]
    with pytest.raises(RuntimeError, match="needs base_url"):
        CredoSink(dry_run=False).emit(c, "card.json")
    with pytest.raises(ValueError):
        CredoSink("http://insecure.example")


# ---------------- D35 ----------------
def test_a_third_party_publishes_a_pack_that_passes_the_validator(tmp_path):
    from shio.governance.registry_index import RegistryError, install, publish, resolve
    signer, pub = keys(tmp_path / "k")
    third = tmp_path / "acme.discharge"
    shutil.copytree(BUILTIN / "med.trial", third, ignore=shutil.ignore_patterns("__pycache__"))
    d = json.loads((third / "pack.json").read_text())
    d.update(id="acme.discharge", name="Acme discharge checks", version="1.0.0")
    (third / "pack.json").write_text(json.dumps(d))
    index, store = tmp_path / "index.json", tmp_path / "store"
    e = publish(third, index, store, "Acme Health (fictional)", signer)
    assert e["id"] == "acme.discharge" and e["signature"]
    d["version"] = "1.1.0"
    (third / "pack.json").write_text(json.dumps(d))
    publish(third, index, store, "Acme Health (fictional)", signer)
    assert resolve(index, "acme.discharge@^1.0")["version"] == "1.1.0"
    assert resolve(index, "acme.discharge@~1.0.0")["version"] == "1.0.0"
    (third / "README.md").write_text((third / "README.md").read_text() + "\nchanged\n")
    with pytest.raises(RegistryError, match="immutable"):
        publish(third, index, store, "Acme Health (fictional)", signer)
    pk = install(index, "acme.discharge@1.0.0", tmp_path / "installed", pub, store=store)
    assert pk.version == "1.0.0" and pk.sha256 == e["tree_sha256"]
    assert load_pack(str(tmp_path / "installed" / "acme.discharge"), sha256=e["tree_sha256"])


def test_install_refuses_tampered_archives_and_entries_and_unsafe_paths(tmp_path):
    import io
    import tarfile
    from shio.governance.registry_index import RegistryError, install, publish, safe_extract
    signer, pub = keys(tmp_path / "k")
    index, store = tmp_path / "index.json", tmp_path / "store"
    e = publish(BUILTIN / "med.change", index, store, "shio", signer)
    arc = store / e["archive"]
    good = arc.read_bytes()
    arc.write_bytes(good[:-10] + b"0" * 10)
    with pytest.raises(RegistryError, match="sha256"):
        install(index, "med.change", tmp_path / "i1", pub, store=store)
    arc.write_bytes(good)
    idx = json.loads(index.read_text())
    idx["packs"]["med.change"]["0.1.0"]["publisher"] = "someone else"
    index.write_text(json.dumps(idx))
    with pytest.raises(RegistryError, match="edited"):
        install(index, "med.change", tmp_path / "i2", pub, store=store)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("../escape.txt")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(RegistryError, match="unsafe"):
        safe_extract(buf.getvalue(), tmp_path / "x")
    assert not (tmp_path / "escape.txt").exists()


def test_semver_ordering_and_constraints():
    from shio.governance.registry_index import best, parse_version
    assert parse_version("1.0.0-rc.1") < parse_version("1.0.0") < parse_version("1.0.1") < parse_version("1.10.0")
    vs = ["0.1.0", "0.1.4", "0.2.0", "1.0.0-rc.1", "1.0.0", "1.2.0"]
    assert best(vs, "*") == "1.2.0" and best(vs, "^0.1") == "0.1.4" and best(vs, ">=0.2.0,<1.0.0") == "0.2.0"
    assert best(vs, "~1.0.0") == "1.0.0" and best(vs, "^3") is None
