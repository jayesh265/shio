"""A demo workspace for the monitor: `shio console --demo DIR` builds one and serves it.

Everything in it is SYNTHETIC: the reference agents' fictional letters and charts, their replay models, ninety days of
seeded decision history with a drift in the last fortnight, and a fictional helpdesk agent's tool calls gated by a
Microsoft AGT policy. It exists to show what the dashboard shows; none of its numbers are evidence about anything.

Needs a source checkout (the examples folder) and the [regulated] extra (signed records). The AGT gate decisions need
the [agt] extra; without it that part is skipped and the dashboard says so.
"""
import contextlib
import datetime as dt
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
EXAMPLES = ROOT / "examples" / "medical"

HELPDESK_POLICY = """apiVersion: governance.toolkit/v1
name: helpdesk-tools
description: SYNTHETIC demo policy for a fictional helpdesk agent
default_action: allow
rules:
  - name: block-destructive
    condition: "action.type in ['drop_table', 'delete_records', 'truncate']"
    action: deny
    description: Destructive operations are never run by an agent
  - name: refund-cap
    condition: "action.type == 'issue_refund' and amount.value > 500"
    action: deny
    description: Refunds over 500 need a person, not an agent
  - name: refund-review
    condition: "action.type == 'issue_refund' and amount.value > 200"
    action: require_approval
    approvers: [finance-manager]
    description: Refunds over 200 are approved by finance
  - name: send-needs-approval
    condition: "action.type == 'send_email'"
    action: require_approval
    approvers: [support-lead]
    description: Outbound email is approved by a person
"""


class DemoError(RuntimeError):
    pass


@contextlib.contextmanager
def _runtime(trace_dir, signer, actor):
    from .. import core
    saved = dict(core._config)
    core._config.update(trace_dir=str(trace_dir), signer=signer or False, actor=actor, policies=False,
                        jurisdiction=None, as_of=None, table_override=None)
    try:
        yield
    finally:
        core._config.clear()
        core._config.update(saved)


def _on_path(*folders):
    for f in folders:
        if str(f) not in sys.path:
            sys.path.insert(0, str(f))


def build(root, days=90, seed=7, today=None, log=print):
    """Build the demo workspace in root (which must be empty or missing). -> root."""
    try:
        import cryptography  # noqa: F401
    except ImportError as e:
        raise DemoError("the demo signs its records: pip install \"shio-lang[regulated]\"") from e
    if not (EXAMPLES / "referral" / "referral.shio").exists():
        raise DemoError(f"the demo needs the examples folder from a source checkout ({EXAMPLES} not found)")
    root = Path(root)
    if root.exists() and any(root.iterdir()):
        raise DemoError(f"{root} is not empty")
    from .. import load as load_program
    from ..core import Source
    from ..ledger import keygen, load_public_key, load_signer, signoff, write
    from . import assess, bundle, card, evals, monitors
    rng = random.Random(seed)
    today = today or dt.date.today()
    priv, pub_path, _ = keygen(root / "keys")
    signer, pub = load_signer(str(priv)), load_public_key(pub_path)
    for d in ("records", "cards", "reviews", "evals", "gates", "policies"):
        (root / d).mkdir(parents=True, exist_ok=True)
    rec_dir = root / "records"
    _on_path(EXAMPLES / "referral", EXAMPLES / "trial")

    # ---- 1. history: seeded decisions, steady for most of the period, drifting in the last 14 days ----
    log("seeding decision history ...")
    sites, bands = ("riverside", "northgate", "harbour"), ("18-39", "40-64", "65+")
    for d in range(days, 0, -1):
        day = today - dt.timedelta(days=d)
        drifting = d <= 14
        for i in range(rng.randint(3, 6)):
            ts = time.mktime(day.timetuple()) + rng.randint(8, 18) * 3600 + i * 60
            grounded = rng.random() > (0.45 if drifting else 0.08)
            ids = rng.random() > 0.03
            status = "SUMMARY_READY" if grounded and ids else "REVIEW"
            write({"agent": "summarise", "started": ts, "ended": ts + 4, "inputs": {}, "sources": {},
                   "readings": [{"raw": "{}" if rng.random() > 0.02 else None}],
                   "checks": [{"name": "grounded", "passed": grounded, "reward": True, "key": None,
                               "code": None if grounded else "UNGROUNDED", "controls": ["med.grounding@0.1.0:GRD-1"]},
                              {"name": "no_identifiers", "passed": ids, "reward": True, "key": None,
                               "code": None if ids else "PHI_FOUND", "controls": ["med.phi@0.1.0:PHI-1"]},
                              {"name": "figures", "passed": rng.random() > 0.05, "reward": True, "key": None}],
                   "rules": [], "outcome": {"status": status}, "children": [],
                   "slices": {"site": rng.choice(sites), "age_band": rng.choice(bands)}},
                  rec_dir, f"history-{day.isoformat()}-{i}", signer=signer)

    # ---- 2. the reference agents, run for real on their synthetic inputs ----
    log("running the referral summariser and the trial screener ...")
    import referral_support as rs
    import screener_support as ss
    referral = load_program(EXAMPLES / "referral" / "referral.shio")
    screener = load_program(EXAMPLES / "trial" / "screener.shio")
    made = []
    with _runtime(rec_dir, signer, "intake-bot"):
        for i, pid in enumerate([p[0] for p in rs.PATIENTS]):
            model = rs.sloppy if i == 3 else rs.careful
            text = rs.injected_letter(pid) if i == 5 else rs.letter(pid)
            referral.summarise(Source(pid, text=text), rs.patient(pid)["name"], model, rs.detector)
            made.append(Path(referral.summarise.last_trace))
    with _runtime(rec_dir, signer, "screening-bot"):
        for row in ss.CHARTS:
            screener.screen(Source(row[0], text=ss.chart(row[0])), ss.allocation(row[0]), ss.careful)
    for path in made[:3]:
        signoff(path, "Dr R. Osei", "clinician", "summary checked against the letter", signer)
    signoff(made[4], "Dr R. Osei", "clinician", "summary misses the anticoagulant", signer, reject=True)

    # ---- 3. agent cards, one reviewed and one waiting; an assessment ----
    log("building agent cards and assessments ...")
    for name, folder in (("referral", EXAMPLES / "referral"), ("trial", EXAMPLES / "trial")):
        m = card.load_manifest(folder / "agent.json")
        c, _ = card.scan(m, signer)
        (root / "cards" / f"{name}.json").write_text(json.dumps(c, indent=1))
        if name == "trial":
            card.review(c, root / "reviews", "Dr A. Mensah", "clinical_safety_lead", "reviewed", signer)
            card.review(c, root / "reviews", "J. Ortiz", "governance_reviewer", "reviewed", signer)
        else:
            card.review(c, root / "reviews", "Dr A. Mensah", "clinical_safety_lead", "reviewed", signer)
        a = assess.assess(card.program_path(m), m, signer=signer)
        (root / "evals" / f"assessment-{name}.json").write_text(json.dumps(a, indent=1))

    # ---- 4. eval suites ----
    log("running eval suites ...")
    evals_paths = []
    for suite in ("regression", "redteam", "grounding"):
        r = evals.run(evals.Suite.load(EXAMPLES / "referral" / "evals" / f"{suite}.json"), signer=signer)
        p = root / "evals" / f"referral-{suite}.json"
        p.write_text(json.dumps(r, indent=1))
        evals_paths.append(p)
    r = evals.run(evals.Suite.load(EXAMPLES / "trial" / "evals" / "eligibility.json"), signer=signer)
    (root / "evals" / "trial-eligibility.json").write_text(json.dumps(r, indent=1))
    from .packs import builtin
    r = evals.run(evals.derive_redteam(*builtin()), evals.pack_check_target, signer)
    (root / "evals" / "packs-redteam.json").write_text(json.dumps(r, indent=1))

    # ---- 5. monitoring: the drift fires; an incident is opened on it ----
    mon = monitors.monitor(rec_dir, today)
    drift = next((a for a in mon["alerts"] if a["kind"] in ("drift", "check_drift")), None)
    if drift:
        iid, _ = monitors.open_incident(rec_dir, "Summaries failing grounding far more often", "high", "J. Ortiz",
                                        drift, mon["files"][-2:], "seeded drift in the demo", signer)
        monitors.update_incident(rec_dir, iid, "INVESTIGATING", "J. Ortiz", "did the model change?", signer)
    old, _ = monitors.open_incident(rec_dir, "PHI detector missed a name in free text", "moderate", "J. Ortiz",
                                    records=mon["files"][:1], signer=signer)
    monitors.update_incident(rec_dir, old, "CLOSED", "J. Ortiz", "pattern added, fixture added", signer)
    rep = monitors.report(mon, signer)
    (root / "evals" / "monitoring-report.json").write_text(json.dumps(rep, indent=1))

    # ---- 6. a framework evidence bundle ----
    log("building an evidence bundle ...")
    bundle.build(rec_dir, "gov.nist-ai-rmf", root / "bundles" / "nist-ai-rmf", today - dt.timedelta(days=days), today,
                 root / "cards" / "referral.json", root / "evals" / "assessment-referral.json", evals_paths,
                 [root / "reviews"], signer, pub)

    # ---- 7. Microsoft AGT on a fictional helpdesk agent's tool calls ----
    (root / "policies" / "helpdesk.yaml").write_text(HELPDESK_POLICY)
    try:
        from .adapters_ext import agt
        agt.AgtBackend(HELPDESK_POLICY)
    except ImportError:
        log("AGT is not installed: skipping the gate decisions (pip install \"shio-lang[agt]\")")
    else:
        log("gating a helpdesk agent's tool calls with Microsoft AGT ...")
        clock = {"t": 0.0}
        approvals = iter(lambda: rng.random() > 0.25, None)

        def approver(req):
            return next(approvals), rng.choice(["M. Chen", "P. Ruiz"]), "checked"

        gate = agt.AgtGate(root / "policies" / "helpdesk.yaml", ledger=root / "gates", agent="helpdesk",
                           requester="helpdesk-bot", approver=approver, signer=signer, clock=lambda: clock["t"])
        tools = {n: gate.wrap(lambda **kw: "ok", action=n) for n in
                 ("lookup_order", "issue_refund", "send_email", "drop_table", "update_address")}
        for d in range(30, -1, -1):
            day = today - dt.timedelta(days=d)
            for i in range(rng.randint(4, 12)):
                clock["t"] = time.mktime(day.timetuple()) + 9 * 3600 + i * 900
                name = rng.choices(list(tools), weights=[40, 25, 15, 3, 10])[0]
                args = {"order": f"A-{rng.randint(100, 999)}"}
                if name == "issue_refund":
                    args["amount"] = rng.choice([25, 60, 120, 180, 240, 380, 750, None])
                    if args["amount"] is None:
                        del args["amount"]
                if name == "send_email":
                    args.update(to="customer@example.com", body="(text)")
                with contextlib.suppress(agt.AgtDenied):
                    tools[name](**args)
    # ---- 8. the pre-model gate over a month of synthetic model calls ----
    log("deciding a month of model calls with the pre-model gate ...")
    _preflight(root, signer, rng, today)
    log(f"demo workspace ready: {root}")
    return root


def _preflight(root, signer, rng, today):
    from .preflight import world as W
    from .preflight.attest import AttestationLedger
    from .preflight.context import load
    from .preflight.controls import BASE_REQUEST, RES_OK
    from .preflight.gate import Gate, _spec_packs, attestation_controls
    from .preflight.model import Request
    conf = root / "compliance"
    conf.mkdir()
    c, m, r = W.world()
    for name, doc in (("compliance.json", c), ("models.json", m), ("registries.json", r)):
        (conf / name).write_text(json.dumps(doc, indent=1))
    packs = _spec_packs()
    controls = attestation_controls(packs)
    ledger = AttestationLedger(root / "attestations")
    missing = {"reg.eu.eu-05", "med.research.res-13"}     # unsigned duties: research calls hold; EU is not active
    for kind, owner in sorted({(x.kind, x.owner_role) for x in controls}):
        if kind in missing:
            continue
        expires = today + dt.timedelta(days=20 if kind == "med.hipaa.privacy.prv-19" else 300)
        ledger.attest(kind, owner, "P. Okafor" if owner == "privacy_officer" else "L. Brandt",
                      today - dt.timedelta(days=60), expires, "0" * 64, signer=signer)
    context, profiles, registries = load(conf)
    clock = {"t": 0.0, "d": today}
    gate = Gate(context, profiles, registries, ledger, root / "gates",
                attestation_controls=controls, packs=packs,
                clock=lambda: clock["d"], now=lambda: clock["t"], signer=signer)
    mix = [({}, 50), ({"destination": "general-llm"}, 8), ({"role": "billing"}, 4),
           ({"role": "analyst", "purpose": "operations", "fields": {"metric": "wait"},
             "text": "Mr Daniel Okoro waited 40 minutes on 03/04/2026."}, 10),
           ({"source": "tool", "text": "From the psychotherapy notes of the last session"}, 3),
           ({**RES_OK}, 8), ({**RES_OK, "subject": "P-602"}, 2), ({"whole_record": True}, 4),
           ({"caller": "service"}, 2), ({"purpose": "marketing", "fields": {"campaign": "flu clinic"}}, 3)]
    for d in range(30, -1, -1):
        clock["d"] = today - dt.timedelta(days=d)
        for i in range(rng.randint(3, 9)):
            clock["t"] = time.mktime(clock["d"].timetuple()) + 8 * 3600 + i * 1200
            over = rng.choices([x for x, _ in mix], weights=[w for _, w in mix])[0]
            gate.decide(Request(**{**BASE_REQUEST, **over}))
