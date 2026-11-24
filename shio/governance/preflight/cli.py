"""`shio preflight`: the pre-model gate from the command line.

    shio preflight check REQUEST.json --config compliance/ [--records r/] [--attestations a/]
    shio preflight attest KIND --owner ROLE --by NAME --issued D --expires D --document FILE --attestations a/
    shio preflight attestations --attestations a/ [--config compliance/]
    shio preflight coverage [--attestations a/] [-o coverage.md] [--json]
    shio preflight lint PATH... [--allow transport.py]
    shio preflight fixtures                         every gate control's fixtures and mutation tests
    shio preflight demo                             decisions over the SYNTHETIC fixture world
"""
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path


def _check(a):
    from .gate import Gate
    from .model import Request
    req = Request(**json.loads(Path(a.request).read_text()))
    gate = Gate.from_folder(a.config, records=a.records, attestations=a.attestations)
    d = gate.decide(req)
    print(json.dumps({"outcome": d.outcome.label, "destination": d.destination, "reasons": list(d.reasons),
                      "classes": sorted(c.value for c in d.classes), "hold": d.hold_id,
                      "approvers": sorted(d.approvers), "payload_sha256": d.payload_sha256}, indent=1))
    return 0 if d.sendable else 3


def _attest(a):
    from .attest import AttestationLedger
    sha = hashlib.sha256(Path(a.document).read_bytes()).hexdigest()
    aid = AttestationLedger(a.attestations).attest(a.kind, a.owner, a.by, a.issued, a.expires, sha, a.scope)
    print(f"{aid}: {a.kind} attested by {a.by} until {a.expires} (document {sha[:16]})")


def _attestations(a):
    from .attest import AttestationLedger
    from .gate import _spec_packs, attestation_controls
    ledger = AttestationLedger(a.attestations)
    kinds = sorted({c.kind for c in attestation_controls(_spec_packs())} | {x.kind for x in ledger.all()})
    worst = 0
    for kind, (state, att) in ledger.status(kinds, dt.date.today()).items():
        worst = max(worst, {"current": 0, "expiring": 0, "expired": 1, "missing": 1}[state])
        print(f"{state.upper():9} {kind}" + (f"  (by {att.signed_by}, expires {att.expires})" if att else ""))
    return worst


def _coverage(a):
    from . import coverage
    ledger = None
    if a.attestations:
        from .attest import AttestationLedger
        ledger = AttestationLedger(a.attestations)
    m = coverage.matrix(ledger=ledger)
    text = json.dumps(m, indent=1) if a.json else coverage.markdown(m)
    if a.out:
        Path(a.out).write_text(text)
        print(f"wrote {a.out}")
    else:
        print(text)


def _lint(a):
    from .bypass import lint
    found = lint(a.paths, a.allow or ())
    for f, line, mod in found:
        print(f"{f}:{line}: imports {mod} outside the pre-model gate's transport")
    print(f"{len(found)} bypass(es)" if found else "no model client reachable except through the gate")
    return 1 if found else 0


def _fixtures(a):
    from . import harness
    res = harness.run_all()
    bad = [r for r in res if not r.ok]
    for r in bad:
        print(f"FAIL {r.control} {r.fixture} ({r.kind}): {r.detail}")
    print(f"{len(res)} fixture and mutation checks over {len({r.control for r in res})} gate controls: "
          f"{len(res) - len(bad)} passed, {len(bad)} failed")
    return 1 if bad else 0


def _demo(a):
    from . import harness
    from .controls import RES_OK
    cases = [("a clinician summarises a referral", {}),
             ("the same request to a model with no agreement", {"destination": "general-llm"}),
             ("billing staff read clinical notes", {"role": "billing"}),
             ("analytics on text with identifiers", {"role": "analyst", "purpose": "operations",
                                                     "fields": {"metric": "wait"},
                                                     "text": "Mr Daniel Okoro waited 40 minutes on 03/04/2026."}),
             ("psychotherapy notes", {"text": "From the psychotherapy notes of the last session"}),
             ("research on a withdrawn participant", {**RES_OK, "subject": "P-602"}),
             ("a whole-record request without a reason", {"whole_record": True})]
    with harness.fixture_gate() as gate:
        for title, over in cases:
            d = gate.decide(harness.request(over))
            print(f"{d.outcome.label.upper():7} {title}\n        {d.explain()}")


def _bench(a):
    """NFR-4: the gate's decision time (excluding the model call), over the fixture world, recorded with a signer."""
    import platform
    import statistics
    import time
    from . import harness
    cases = {"allow": {}, "route": {"destination": "general-llm"}, "deny": {"role": "billing"},
             "redact": {"role": "analyst", "purpose": "operations", "fields": {"metric": "wait"},
                        "text": "Mr Daniel Okoro waited 40 minutes on 03/04/2026."}}
    out = {"format": "shio-gate-latency/1", "n": a.n, "python": platform.python_version(),
           "machine": platform.machine(), "note": "decision time including the signed record write; no model call",
           "outcomes": {}}
    with harness.fixture_gate() as gate:
        for name, over in cases.items():
            req = harness.request(over)
            gate.decide(req)
            ts = []
            for _ in range(a.n):
                t = time.perf_counter()
                gate.decide(req)
                ts.append((time.perf_counter() - t) * 1000)
            ts.sort()
            out["outcomes"][name] = {"p50_ms": round(statistics.median(ts), 3),
                                     "p95_ms": round(ts[int(0.95 * len(ts)) - 1], 3),
                                     "p99_ms": round(ts[int(0.99 * len(ts)) - 1], 3)}
    text = json.dumps(out, indent=1)
    if a.out:
        Path(a.out).write_text(text + "\n")
    print(text)


def _attack(a):
    from ..attack import scenarios
    if a.scenario == "all":
        out = scenarios.run_all(a.k, a.budget, a.seed)
    else:
        out = scenarios.SCENARIOS[a.scenario](a.k, a.budget, a.seed)
    text = json.dumps(out, indent=1, ensure_ascii=False)
    if a.out:
        Path(a.out).write_text(text + "\n")
    groups = out.get("phi", {}).get("by_identifier", {}) if a.scenario == "all" else out.get("by_identifier", {})
    for n, r in groups.items():
        print(f"phi {n:6} attack success {r['attack_success_mean']:.0%}  pass^{r['k']} {r['attack_pass_k']:.0%}")
    for key in ("amount", "recipient"):
        r = (out.get("args") or out).get(key)
        if r:
            print(f"args {key:9} attack success {r['attack_success_mean']:.0%}  pass^{r['k']} {r['attack_pass_k']:.0%}")
    return 1 if any(r["attack_success_mean"] for r in groups.values()) else 0


def _explain(a):
    from ..chain import SignedChain
    from .gate import explain
    folder = Path(a.records)
    es = [e for e in SignedChain(folder, "preflight").entries() if e.get("kind") == "preflight_decision"]
    pick = [e for e in es if e.get("request_sha256", "").startswith(a.request or "")] if a.request else es[-1:]
    if not pick:
        print("no such decision")
        return 1
    print(explain(pick[-1]))


def _quickstart(a):
    from ..quickstart import create
    folder = create(a.folder)
    print(f"wrote {folder}/agent.py, policy.json, README.md\nrun:  python {folder}/agent.py")


def _coverage_diff(a):
    from . import coverage
    out = coverage.diff(json.loads(Path(a.base).read_text()), json.loads(Path(a.head).read_text()))
    for x in out:
        print(f"REGRESSION {x}")
    print(f"{len(out)} control(s) removed or weakened" if out else "no control removed or weakened")
    return 1 if out else 0


def register(sub):
    p = sub.add_parser("preflight", help="the pre-model compliance gate: check requests, attestations, coverage, "
                                         "bypass lint, control fixtures")
    s = p.add_subparsers(dest="preflight_cmd", required=True)
    c = s.add_parser("check", help="decide one request (JSON) against a compliance folder")
    c.add_argument("request")
    c.add_argument("--config", required=True, help="folder with compliance.json, models.json, registries.json")
    c.add_argument("--records")
    c.add_argument("--attestations")
    c.set_defaults(fn=_check)
    t = s.add_parser("attest", help="record a signed attestation of an organisational duty")
    t.add_argument("kind")
    for k in ("owner", "by", "issued", "expires", "document", "attestations"):
        t.add_argument(f"--{k}", required=True)
    t.add_argument("--scope", default="*")
    t.set_defaults(fn=_attest)
    l2 = s.add_parser("attestations", help="current, expiring, expired and missing attestations")
    l2.add_argument("--attestations", required=True)
    l2.set_defaults(fn=_attestations)
    v = s.add_parser("coverage", help="the coverage matrix of every pack's controls")
    v.add_argument("--attestations")
    v.add_argument("-o", "--out")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=_coverage)
    n = s.add_parser("lint", help="fail if code imports a model SDK outside the gate's transport")
    n.add_argument("paths", nargs="+")
    n.add_argument("--allow", action="append")
    n.set_defaults(fn=_lint)
    s.add_parser("fixtures", help="run every gate control's fixtures and mutation tests").set_defaults(fn=_fixtures)
    s.add_parser("demo", help="decisions over the SYNTHETIC fixture world").set_defaults(fn=_demo)
    cd = s.add_parser("coverage-diff", help="INT-3: fail when a control was removed or weakened")
    cd.add_argument("base")
    cd.add_argument("head")
    cd.set_defaults(fn=_coverage_diff)
    e = s.add_parser("explain", help="DX-2: a recorded decision in plain language")
    e.add_argument("records", help="the folder holding preflight.jsonl")
    e.add_argument("--request", help="a request sha256 prefix (default: the last decision)")
    e.set_defaults(fn=_explain)
    q = sub.add_parser("quickstart", help="DX-1: a protected agent and a blocked attack, in seconds")
    q.add_argument("folder", nargs="?", default="shio-quickstart")
    q.set_defaults(fn=_quickstart)
    b = s.add_parser("bench", help="NFR-4: the gate's decision latency")
    b.add_argument("-n", type=int, default=500)
    b.add_argument("-o", "--out")
    b.set_defaults(fn=_bench)
    at = sub.add_parser("attack", help="EVAL-1: adaptive attacker against Shio's deterministic defences, with pass^k")
    at.add_argument("action", choices=["run"])
    at.add_argument("--scenario", choices=["all", "phi", "args"], default="all")
    at.add_argument("--k", type=int, default=5)
    at.add_argument("--budget", type=int, default=300)
    at.add_argument("--seed", type=int, default=11)
    at.add_argument("-o", "--out")
    at.set_defaults(fn=_attack)
