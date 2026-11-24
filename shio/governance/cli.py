"""The Shio Guard commands, registered into `shio` (shio.cli.main calls register()).

    shio registry scan|review|check     agent cards and the re-review trigger
    shio assess                         control proofs over a program
    shio pack validate|list|show|oscal|redteam|publish|install
    shio adapters check                 conformance, pins and licences of an agent's adapters
    shio licences check                 the licence and dependency policy (CI)
    shio eval                           eval suites: slices, gates, regressions against a baseline
    shio impact                         change-impact replay over recorded decisions
    shio effectiveness                  per-check blocked / overturned / precision from reviewer labels
    shio monitors                       failure, override and drift monitors
    shio incident open|update|list      incidents as signed records
    shio safety-case                    the clinical safety case
    shio policy-draft compile|approve|status|export
    shio release status|approve|promote
    shio cds                            decision-support posture check on a card
    shio cedar check|export             Cedar policies: decide a request, export Cedar or Rego
    shio credo export                   cards and bundles to a Credo AI tenant (dry run by default)
    shio console                        the read-only web console and the live monitor (/monitor)
"""
import datetime as dt
import importlib
import json
import sys
from pathlib import Path


def _signer():
    from ..core import _signer as s
    return s()


def _pub(a):
    from ..ledger import load_public_key
    return load_public_key(a.pubkey) if getattr(a, "pubkey", None) else None


def _secret(a):
    return a.secret.encode() if getattr(a, "secret", None) else None


def _write(doc, out):
    if out:
        Path(out).write_text(json.dumps(doc, indent=1, ensure_ascii=False, default=str))
        print(f"wrote {out}", file=sys.stderr)


def _date(text, default=None):
    return dt.date.fromisoformat(text) if text else (default or dt.date.today())


def _object(ref, path=None):
    """'module:attr' -> the object, importing with path (and the current folder) on sys.path."""
    for p in [path, "."]:
        if p and str(Path(p).resolve()) not in sys.path:
            sys.path.insert(0, str(Path(p).resolve()))
    mod, _, attr = ref.partition(":")
    obj = importlib.import_module(mod)
    for part in attr.split("."):
        obj = getattr(obj, part)
    return obj


# ---------------- registry ----------------
def _registry(a):
    from . import card
    if a.action == "scan":
        c, problems = card.scan(card.load_manifest(a.target), _signer())
        _write(c, a.out)
        if not a.out:
            print(json.dumps(c, indent=1, default=str))
        print(f"card {c['name']} sha256 {c['sha256']}" + (" (signed)" if c.get("signature") else " (unsigned)"),
              file=sys.stderr)
        for p in problems:
            print(f"BUILD REFUSED: {p}", file=sys.stderr)
        sys.exit(1 if problems else 0)
    c = json.loads(Path(a.target).read_text())
    if a.action == "review":
        if not (a.reviews and a.signer and a.role and a.meaning):
            sys.exit("shio registry review CARD --reviews DIR --as NAME --role ROLE --meaning TEXT")
        e = card.review(c, a.reviews, a.signer, a.role, a.meaning, _signer(), a.reject)
        print(f"{e['decision']} card {c['sha256'][:16]}… by {e['by']} ({e['role']}), entry {e['seq']}")
        return
    ok, problems = card.verify(c, _pub(a), _secret(a))
    if not ok:
        print("\n".join(problems))
        sys.exit(1)
    if not a.reviews:
        sys.exit("shio registry check CARD --reviews DIR")
    ok, lines = card.review_status(c, a.reviews)
    print("\n".join(lines))
    sys.exit(0 if ok else 1)


# ---------------- assess ----------------
def _assess(a):
    from .assess import FAILED, assess, report
    from .card import load_manifest, program_path
    manifest = load_manifest(a.manifest) if a.manifest else None
    program = a.program or (program_path(manifest) if manifest else None)
    if not program:
        sys.exit("shio assess PROGRAM [--manifest agent.json]")
    doc = assess(program, manifest, a.proof or None, _signer(), a.pack or ())
    _write(doc, a.out)
    print(json.dumps(doc, indent=1) if a.json else report(doc))
    sys.exit(1 if doc["summary"][FAILED] else 0)


# ---------------- packs ----------------
def _pack(a):
    from . import packs
    if a.action == "validate":
        bad = 0
        for t in a.targets or list(packs.builtin().values()):
            ok, problems, pk = packs.validate(packs.resolve(str(t)), run_fixtures=not a.no_fixtures)
            print(f"{'ok' if ok else 'INVALID'}  {pk.label() if pk else t}" + (f"  sha256 {pk.sha256[:16]}" if pk else ""))
            for p in problems:
                print(f"    {p}")
            bad += not ok
        sys.exit(1 if bad else 0)
    if a.action == "list":
        for pid, folder in packs.builtin().items():
            pk = packs.read(folder)
            print(f"{pk.label():<26} {pk.status:<9} {len(pk.controls):>2} controls  {pk.name}")
        return
    if a.action == "redteam":
        from .evals import derive_redteam
        s = derive_redteam(*(a.targets or packs.builtin()))
        doc = {"format": "shio-eval-suite/1", "suite": "redteam", "target": "shio.governance.evals:pack_check_target",
               "slices": ["pack"], "metrics": [{"name": "pass_rate"}], "gates": {"pass_rate": [">=", 1.0]},
               "cases": [{"id": c.id, "input": c.input, "expect": c.expect, "slices": c.slices, "origin": c.origin}
                         for c in s.cases]}
        _write(doc, a.out)
        print(f"{len(s.cases)} red-team cases from {len(a.targets or packs.builtin())} packs", file=sys.stderr)
        return
    if a.action == "publish":
        from .registry_index import publish
        if not (a.index and a.store and a.publisher):
            sys.exit("shio pack publish DIR --index index.json --store DIR --publisher NAME")
        for t in a.targets:
            e = publish(t, a.index, a.store, a.publisher, _signer())
            print(f"published {e['id']}@{e['version']} archive sha256 {e['archive_sha256'][:16]}")
        return
    if a.action == "install":
        from .registry_index import install
        if not (a.index and a.to):
            sys.exit("shio pack install REF --index index.json --to DIR")
        for t in a.targets:
            pk = install(a.index, t, a.to, _pub(a), _secret(a), a.store)
            print(f"installed {pk.label()} into {Path(a.to) / pk.id} (sha256 {pk.sha256[:16]})")
        return
    pk = packs.read(packs.resolve(a.targets[0]))
    if a.action == "oscal":
        doc = packs.to_oscal(pk)
        _write(doc, a.out)
        if not a.out:
            print(json.dumps(doc, indent=1))
        return
    print(f"{pk.label()} ({pk.status}), effective {pk.effective}, licence {pk.licence}, sha256 {pk.sha256}")
    print(f"  {pk.name}")
    for c in pk.controls:
        print(f"  {c.id:<8} {c.title}\n           " + ", ".join(p.label() for p in c.proofs))
    print(f"  limits: {pk.limits}")


# ---------------- adapters, licences ----------------
def _adapters(a):
    from .adapters import Registry
    from .card import load_manifest
    m = load_manifest(a.manifest)
    ok, results = Registry.from_manifest(m.get("adapters")).check(regulated=a.regulated)
    for r in results:
        print(f"{'ok' if r.ok else 'FAILED'}  {r.adapter}")
        for x in r.results:
            if not x.ok:
                print(f"    {x.test}: {x.detail}")
    sys.exit(0 if ok else 1)


def _licences(a):
    from .licences import Policy, check
    ok, findings, notes = check(Policy.load(a.policy), a.root, a.extra or (), a.strict)
    for f in findings:
        if not f.ok or a.verbose:
            print(f"{'ok' if f.ok else 'VIOLATION'}  {f.scope:<16} {f.package} {f.version}: {f.why}"
                  + (f"  (via {' > '.join(f.via)})" if f.via and not f.ok else ""))
    for n in notes:
        print(f"note: {n}")
    print(f"{len(findings)} dependencies checked: {'OK' if ok else 'VIOLATIONS'}")
    sys.exit(0 if ok else 1)


# ---------------- evals, impact, effectiveness ----------------
def _eval(a):
    from . import evals
    suite = evals.Suite.load(a.suite)
    subject = None
    if a.card:
        from .promote import subject_of
        subject = subject_of(json.loads(Path(a.card).read_text()))
    result = evals.run(suite, a.target, _signer(), subject)
    regressions = evals.compare(result, json.loads(Path(a.baseline).read_text()), a.tolerance) if a.baseline else []
    _write(result, a.out)
    if a.junit:
        from .adapters_ext.integrations import JUnitSink
        JUnitSink(a.junit).emit(result, f"{suite.name}.json")
    print(evals.report(result, regressions))
    sys.exit(1 if result["gate_failures"] or regressions else 0)


def _impact(a):
    from . import impact
    model = _object(a.model, a.path) if a.model else None
    models = {k: _object(v, a.path) for k, v in (x.split("=", 1) for x in a.replace or [])}
    swap = {k: _object(v, a.path) for k, v in (x.split("=", 1) for x in a.swap or [])}
    result = impact.run(a.records, model, models or None, a.program, swap=swap or None)
    print(json.dumps(impact.as_json(result), indent=1, default=str) if a.json else impact.report(result))
    sys.exit(1 if a.exit_code and result["summary"]["FLIPPED"] else 0)


def _effectiveness(a):
    from .effectiveness import measure, report
    m = measure(a.folder)
    print(json.dumps(m, indent=1) if a.json else report(m))


# ---------------- monitors, incidents ----------------
def _monitors(a):
    from . import monitors
    r = monitors.monitor(a.folder, _date(a.today), a.window_days, a.baseline_days)
    if a.report:
        _write(monitors.report(r, _signer()), a.report)
    if a.json:
        print(json.dumps(r, indent=1, default=str))
    else:
        m = r["metrics"]
        print(f"window {r['window'][0]} to {r['window'][1]}: {m['decisions']} decisions; failure rate "
              f"{m['failure_rate']}, check failures {m['check_failure_rate']}, overrides {m['override_rate']}, "
              f"outcome PSI {m['outcome_psi']}")
        for x in r["alerts"]:
            print(f"  ALERT ({x['severity']}) {x['kind']}: {x['message']}")
        print(f"{len(r['alerts'])} alert{'s' if len(r['alerts']) != 1 else ''}")
    sys.exit(1 if a.exit_code and r["alerts"] else 0)


def _incident(a):
    from . import monitors
    if a.action == "open":
        iid, path = monitors.open_incident(a.folder, a.title, a.severity, a.signer, None, a.record or (),
                                           a.description or "", _signer())
        print(f"opened {iid}: {path.name}")
    elif a.action == "update":
        path = monitors.update_incident(a.folder, a.id, a.status, a.signer, a.note or "", _signer())
        print(f"{a.id} is {a.status}: {path.name}")
    else:
        for i in monitors.incidents(a.folder):
            print(f"{i['incident']} {i['status']:<13} {i['severity']:<9} {i['opened']} {i['title']}")


# ---------------- safety case, policy drafts, releases ----------------
def _safety(a):
    from . import safety
    load = lambda p: json.loads(Path(p).read_text())  # noqa: E731
    case = safety.build(a.agent, a.pack, a.records, _date(a.start, dt.date(2000, 1, 1)), _date(a.end),
                        load(a.assessment) if a.assessment else None, [load(e) for e in a.eval or []],
                        a.approvals or (), _signer())
    safety.write(case, a.out, a.approvals[0] if a.approvals else None)
    print(f"safety case for {a.agent}: {case['summary']['hazards']} hazards, unacceptable residual: "
          f"{', '.join(case['summary']['unacceptable_residual']) or 'none'} -> {a.out}/safety-case.md")


def _policy_draft(a):
    from . import policy_compiler as pc
    if a.action == "compile":
        doc = pc.compile_policy(Path(a.target).read_text(), a.subject, Path(a.target).name)
        _write(doc, a.out)
        print(pc.matrix_markdown(doc))
        return
    doc = json.loads(Path(a.target).read_text())
    if a.action == "approve":
        e = pc.approve(doc, a.draft, a.approvals, a.signer, a.role, signer=_signer(), reject=a.reject)
        print(f"{e['decision']} draft {a.draft} by {e['by']} ({e['role']})")
    elif a.action == "status":
        print(pc.matrix_markdown(doc, a.approvals))
    else:
        lines, pending = pc.export(doc, a.approvals)
        print("\n".join(lines))
        if pending:
            print(f"# not exported (no approval yet): {', '.join(pending)}", file=sys.stderr)


def _release(a):
    from . import promote
    c = json.loads(Path(a.card).read_text())
    evals_ = [json.loads(Path(e).read_text()) for e in a.eval or []]
    if a.action == "approve":
        e = promote.approve(c, a.approvals, a.signer, a.role, signer=_signer(), reject=a.reject)
        print(f"{e['decision']} release {e['subject']['sha256'][:16]}… by {e['by']} ({e['role']})")
        return
    if a.action == "status":
        ready, reasons, rel = promote.readiness(c, evals_, a.approvals, public_key=_pub(a))
        print(f"release {rel['sha256'][:16]}… of {c['name']}: {'READY' if ready else 'BLOCKED'}")
        for r in reasons:
            print(f"  {r}")
        sys.exit(0 if ready else 1)
    try:
        e = promote.promote(c, evals_, a.approvals, a.promotions, a.env, a.signer, signer=_signer(),
                            public_key=_pub(a))
    except promote.PromotionBlocked as err:
        print("\n".join(f"BLOCKED: {r}" for r in err.reasons))
        sys.exit(1)
    print(f"promoted {c['name']} release {e['release']['sha256'][:16]}… to {a.env} (entry {e['seq']})")


def _cds(a):
    from .cds import check_posture
    v = check_posture(json.loads(Path(a.card).read_text()))
    print("\n".join(f"VIOLATION {x}" for x in v) or "the card fits its declared posture")
    sys.exit(1 if v else 0)


def _cedar(a):
    from . import cedar
    policies = cedar.parse(Path(a.policies).read_text())
    if a.action == "export":
        print(cedar.to_rego(policies, a.package) if a.to == "rego" else cedar.to_cedar(policies))
        return
    ents = json.loads(Path(a.entities).read_text()) if a.entities else None
    d = cedar.authorize(policies, a.principal, a.action_ref, a.resource, json.loads(a.context or "{}"), ents)
    print(json.dumps({"allowed": d.allowed, "permits": d.permits, "forbids": d.forbids, "errors": d.errors}, indent=1))
    sys.exit(0 if d.allowed else 1)


def _credo(a):
    from .adapters_ext.credo import CredoSink
    sink = CredoSink(a.base_url, a.tenant, dry_run=not a.send, out=a.out)
    p = Path(a.target)
    if p.is_dir():
        sink.export_bundle(p)
    else:
        sink.emit(json.loads(p.read_text()), p.name)
    for s in sink.sent:
        print(f"{'would POST' if s['dry_run'] else 'POSTed'} {s['kind']} to {s['path']}"
              + (f" ({s['status']})" if "status" in s else ""))


def _console(a):
    from .console import Console, serve
    workspace = a.workspace
    if a.demo:
        from .demo import build
        workspace = build(a.demo)
    pub = None
    if a.pubkey:
        from ..ledger import load_public_key
        pub = load_public_key(a.pubkey)
    elif workspace and (Path(workspace) / "keys" / "shio-signing.pub").exists():
        from ..ledger import load_public_key
        pub = load_public_key(Path(workspace) / "keys" / "shio-signing.pub")
    con = Console(a.records, a.cards, a.bundles, a.reviews, a.pack or (), a.evals, a.gates, a.policies, workspace, pub)
    srv = serve(con, a.host, a.port)
    print(f"Shio Guard console (read-only) on http://{a.host}:{srv.server_address[1]}/")
    print(f"  live monitor:  http://{a.host}:{srv.server_address[1]}/monitor   (Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


# ---------------- shio verify, extended ----------------
def verify_artifact(path, public_key=None, secret=None):
    """-> (ok, lines) for a card, a framework bundle, a sealed governance document, or a signed chain, else None."""
    p = Path(path)
    if p.is_dir() and (p / "manifest.json").exists() and \
            json.loads((p / "manifest.json").read_text()).get("type") == "shio-bundle/1":
        from .bundle import verify
        return verify(p, public_key, secret)
    if p.is_file() and p.suffix == ".jsonl" and p.name != "ledger.jsonl":
        from .chain import SignedChain
        ok, problems = SignedChain(p.parent, p.stem).verify(public_key, secret)
        return ok, [f"{p.name}: {len(SignedChain(p.parent, p.stem).entries())} entries"] + problems
    if p.is_file() and p.suffix == ".json":
        doc = json.loads(p.read_text())
        if doc.get("format") == "shio-card/1":
            from .card import verify
            ok, problems = verify(doc, public_key, secret)
            return ok, [f"agent card {doc['name']} sha256 {doc['sha256'][:16]}…"] + problems
        if str(doc.get("format", "")).startswith("shio-") and "sha256" in doc:
            from .assess import check_seal
            ok, problems = check_seal(doc, public_key, secret)
            return ok, [f"{doc['format']} sha256 {doc['sha256'][:16]}…"] + problems
    return None


# ---------------- registration ----------------
def register(sub):
    from .preflight.cli import register as preflight
    from .prd_cli import register as prd
    from ..harness.cli import register as harness
    preflight(sub)
    prd(sub)
    harness(sub)
    r = sub.add_parser("registry", help="agent cards: scan a manifest into a signed card, review it, check reviews")
    r.add_argument("action", choices=["scan", "review", "check"])
    r.add_argument("target", help="scan: the agent manifest (agent.json); review/check: the card")
    r.add_argument("-o", "--out")
    r.add_argument("--reviews", help="the folder holding the review (approval) log")
    r.add_argument("--as", dest="signer")
    r.add_argument("--role")
    r.add_argument("--meaning")
    r.add_argument("--reject", action="store_true")
    r.add_argument("--pubkey")
    r.add_argument("--secret")
    r.set_defaults(fn=_registry)

    a = sub.add_parser("assess", help="control proofs over a program, for every code path of its hash")
    a.add_argument("program", nargs="?")
    a.add_argument("--manifest", help="the agent manifest: model pins, packs, outcomes needing sign-off")
    a.add_argument("--proof", action="append", help="run only these proofs (repeatable)")
    a.add_argument("--pack", action="append", help="report these packs' lint controls (repeatable)")
    a.add_argument("-o", "--out")
    a.add_argument("--json", action="store_true")
    a.set_defaults(fn=_assess)

    p = sub.add_parser("pack", help="control packs: validate, list, show, OSCAL export, red-team suite, publish, install")
    p.add_argument("action", choices=["validate", "list", "show", "oscal", "redteam", "publish", "install"])
    p.add_argument("targets", nargs="*")
    p.add_argument("-o", "--out")
    p.add_argument("--no-fixtures", action="store_true", help="validate without running fixtures")
    p.add_argument("--index")
    p.add_argument("--store")
    p.add_argument("--publisher")
    p.add_argument("--to")
    p.add_argument("--pubkey")
    p.add_argument("--secret")
    p.set_defaults(fn=_pack)

    ad = sub.add_parser("adapters", help="conformance, pins and licences of an agent's adapters")
    ad.add_argument("action", choices=["check"])
    ad.add_argument("--manifest", required=True)
    ad.add_argument("--regulated", action="store_true", help="refuse unpinned adapters and dependencies")
    ad.set_defaults(fn=_adapters)

    li = sub.add_parser("licences", help="check installed dependencies against the licence policy (for CI)")
    li.add_argument("action", choices=["check"])
    li.add_argument("--policy", help="a licence policy file (default: the one Shio ships)")
    li.add_argument("--root", default="shio-lang")
    li.add_argument("--extra", action="append", help="also check this extra's dependencies (repeatable)")
    li.add_argument("--strict", action="store_true", help="exceptions counsel hasn't approved are failures")
    li.add_argument("-v", "--verbose", action="store_true")
    li.set_defaults(fn=_licences)

    ev = sub.add_parser("eval", help="run an eval suite: per-slice metrics, gates, regressions against a baseline")
    ev.add_argument("suite")
    ev.add_argument("--target", help="module:function (default: the suite's)")
    ev.add_argument("--baseline", help="an earlier result to compare against")
    ev.add_argument("--tolerance", type=float, default=0.0)
    ev.add_argument("--card", help="bind the result to the release this card describes")
    ev.add_argument("--junit", help="also write JUnit XML into this folder")
    ev.add_argument("-o", "--out")
    ev.set_defaults(fn=_eval)

    im = sub.add_parser("impact", help="replay recorded decisions under a new model or program; list what flips")
    im.add_argument("records", nargs="+")
    im.add_argument("--model", help="module:attribute of the new model, answering every read")
    im.add_argument("--swap", action="append", help="RECORDED_NAME=module:attribute: replace only the model recorded "
                                                   "under that name (repeatable)")
    im.add_argument("--replace", action="append", help="NAME=module:attribute: replace a model the program declares")
    im.add_argument("--program", help="a changed program to decide instead")
    im.add_argument("--path", help="a folder to import --model from")
    im.add_argument("--json", action="store_true")
    im.add_argument("--exit-code", action="store_true", help="exit 1 if any decision flips")
    im.set_defaults(fn=_impact)

    ef = sub.add_parser("effectiveness", help="per-check blocked, overturned and precision from reviewer labels")
    ef.add_argument("folder")
    ef.add_argument("--json", action="store_true")
    ef.set_defaults(fn=_effectiveness)

    mo = sub.add_parser("monitors", help="failure, override and drift (PSI) monitors over a recent window")
    mo.add_argument("folder")
    mo.add_argument("--today")
    mo.add_argument("--window-days", type=int, default=14)
    mo.add_argument("--baseline-days", type=int, default=56)
    mo.add_argument("--report", help="write a sealed monitoring report (for the reviewer's sign-off)")
    mo.add_argument("--json", action="store_true")
    mo.add_argument("--exit-code", action="store_true")
    mo.set_defaults(fn=_monitors)

    inc = sub.add_parser("incident", help="incidents as signed records in the decision ledger")
    inc.add_argument("action", choices=["open", "update", "list"])
    inc.add_argument("folder")
    inc.add_argument("id", nargs="?")
    inc.add_argument("--title")
    inc.add_argument("--severity", choices=["low", "moderate", "high", "critical"])
    inc.add_argument("--description")
    inc.add_argument("--record", action="append", help="a decision record the incident is about (repeatable)")
    inc.add_argument("--status", choices=["INVESTIGATING", "MITIGATED", "CLOSED"])
    inc.add_argument("--note")
    inc.add_argument("--as", dest="signer", default="")
    inc.set_defaults(fn=_incident)

    sc = sub.add_parser("safety-case", help="the clinical safety case: hazard log, controls and evidence")
    sc.add_argument("--agent", required=True)
    sc.add_argument("--pack", action="append", required=True)
    sc.add_argument("--records")
    sc.add_argument("--from", dest="start")
    sc.add_argument("--to", dest="end")
    sc.add_argument("--assessment")
    sc.add_argument("--eval", action="append")
    sc.add_argument("--approvals", action="append")
    sc.add_argument("-o", "--out", required=True)
    sc.set_defaults(fn=_safety)

    pd = sub.add_parser("policy-draft", help="plain-language policy -> draft checks and tests, with a trace and approvals")
    pd.add_argument("action", choices=["compile", "approve", "status", "export"])
    pd.add_argument("target", help="compile: the policy text; else: the drafts file")
    pd.add_argument("draft", nargs="?")
    pd.add_argument("--subject", default="item", help="the name the checks test (compile)")
    pd.add_argument("--approvals")
    pd.add_argument("--as", dest="signer")
    pd.add_argument("--role", default="policy_owner")
    pd.add_argument("--reject", action="store_true")
    pd.add_argument("-o", "--out")
    pd.set_defaults(fn=_policy_draft)

    rl = sub.add_parser("release", help="med.change: release status, sign-off and promotion")
    rl.add_argument("action", choices=["status", "approve", "promote"])
    rl.add_argument("card")
    rl.add_argument("--eval", action="append")
    rl.add_argument("--approvals", required=True)
    rl.add_argument("--promotions")
    rl.add_argument("--env")
    rl.add_argument("--as", dest="signer", default="")
    rl.add_argument("--role", default="release_manager")
    rl.add_argument("--reject", action="store_true")
    rl.add_argument("--pubkey")
    rl.set_defaults(fn=_release)

    cd = sub.add_parser("cds", help="med.cds: does the card fit its declared decision-support posture?")
    cd.add_argument("card")
    cd.set_defaults(fn=_cds)

    ce = sub.add_parser("cedar", help="Cedar policies: decide a request, or export as Cedar or Rego")
    ce.add_argument("action", choices=["check", "export"])
    ce.add_argument("policies")
    ce.add_argument("--principal", default='User::"anonymous"')
    ce.add_argument("--action", dest="action_ref", default='Action::"none"')
    ce.add_argument("--resource", default='Tool::"none"')
    ce.add_argument("--context")
    ce.add_argument("--entities")
    ce.add_argument("--to", choices=["cedar", "rego"], default="cedar")
    ce.add_argument("--package", default="shio.authz")
    ce.set_defaults(fn=_cedar)

    cr = sub.add_parser("credo", help="export a card or a bundle to Credo AI (dry run unless --send)")
    cr.add_argument("action", choices=["export"])
    cr.add_argument("target")
    cr.add_argument("--out", help="dry run: write payloads here")
    cr.add_argument("--send", action="store_true")
    cr.add_argument("--base-url")
    cr.add_argument("--tenant")
    cr.set_defaults(fn=_credo)

    co = sub.add_parser("console", help="the read-only web console and live monitor over records, cards, controls, "
                                        "gates and evidence")
    co.add_argument("--workspace", help="a folder with records/, cards/, reviews/, bundles/, evals/, gates/, policies/")
    co.add_argument("--demo", metavar="DIR", help="build a SYNTHETIC demo workspace in DIR (empty) and serve it")
    co.add_argument("--evals")
    co.add_argument("--gates")
    co.add_argument("--policies")
    co.add_argument("--pubkey", help="verify signatures with this public key")
    co.add_argument("--records")
    co.add_argument("--cards")
    co.add_argument("--bundles")
    co.add_argument("--reviews")
    co.add_argument("--pack", action="append")
    co.add_argument("--host", default="127.0.0.1")
    co.add_argument("--port", type=int, default=8765)
    co.set_defaults(fn=_console)
