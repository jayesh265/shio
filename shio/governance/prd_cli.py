"""Commands for the product requirements' governance and enforcement features.

    shio inventory validate|check|graph registry.json [--format mermaid|dot|json]     GOV-1, GOV-6
    shio risk classify answers.json | shio risk register validate|seed FILE          GOV-3
    shio report controls --records r/ [--gates g/] | shio report reviewers --records r/   EVID-1, OVR-3
    shio doctor PATH [--policy out.json] [--registry registry.json]                  DX-3, GOV-2
    shio proxy --upstream URL [--policy argpolicy.json] [--compliance dir/]          INT-2
    shio temporal check rules.txt trace.json                                         CORE-3
"""
import json
import sys
from pathlib import Path


def _inventory(a):
    from . import inventory
    reg = inventory.load(a.registry)
    if a.action == "validate":
        probs = inventory.validate(reg)
    elif a.action == "check":
        probs = inventory.validate(reg) + inventory.check_code(reg)
    else:
        g = inventory.graph(reg)
        print({"mermaid": inventory.mermaid, "dot": inventory.dot}.get(a.format, lambda x: json.dumps(x, indent=1))(g))
        return 0
    for p in probs:
        print(p)
    print("registry OK" if not probs else f"{len(probs)} problem(s)")
    return 1 if probs else 0


def _risk(a):
    from . import risk
    if a.action == "classify":
        r = risk.classify(json.loads(Path(a.file).read_text()))
        print(json.dumps(r, indent=1))
        return 0
    if a.action == "seed":
        Path(a.file).write_text(json.dumps(risk.seed_register(a.owner or "unassigned"), indent=1))
        print(f"wrote {a.file}")
        return 0
    probs = risk.validate_register(risk.load(a.file), known_controls=risk.known_controls())
    for p in probs:
        print(p)
    print("register OK" if not probs else f"{len(probs)} problem(s)")
    return 1 if probs else 0


def _report(a):
    from . import oversight
    if a.action == "controls":
        from .packs import builtin, read
        r = oversight.control_report(a.records, a.gates, [read(p) for p in builtin().values()])
    else:
        r = oversight.reviewer_metrics(a.records)
    text = json.dumps(r, indent=1)
    if a.out:
        Path(a.out).write_text(text)
        print(f"wrote {a.out}")
    else:
        print(text)


def _doctor(a):
    from . import doctor
    r = doctor.examine(a.path)
    print(doctor.render(r))
    if a.policy:
        Path(a.policy).write_text(json.dumps(r["proposed_policy"], indent=1))
        print(f"wrote {a.policy}")
    if a.registry:
        from . import inventory
        cands = inventory.candidates(inventory.load(a.registry), r)
        print(f"{len(cands)} candidate(s) for the registry (a person triages; nothing is registered):")
        for c in cands:
            print(f"  {c['kind']:10} {c['name']:24} {c['where']}")
    return 1 if r["unguarded"] else 0


def _proxy(a):
    from .enforce.proxy import GuardProxy, serve
    policy = gate = None
    if a.policy:
        from .enforce.argpolicy import ArgPolicy
        policy = ArgPolicy.load(a.policy)
    if a.compliance:
        from .preflight import Gate
        gate = Gate.from_folder(a.compliance, records=a.records, attestations=a.attestations)
    srv = serve(GuardProxy(a.upstream, policy, gate, destination=a.destination), a.host, a.port)
    print(f"Shio proxy on http://{a.host}:{srv.server_address[1]}/v1 -> {a.upstream}  (Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def _temporal(a):
    from .enforce.temporal import Monitor
    m = Monitor(Path(a.rules).read_text())
    bad = 0
    for ev in json.loads(Path(a.trace).read_text()):
        v = m.gate(ev["tool"], float(ev["t"]))
        print(f"{'REFUSED' if v else 'ok':8} t={ev['t']:<8} {ev['tool']}" + (f"   ({'; '.join(v)})" if v else ""))
        bad += bool(v)
    return 1 if bad else 0


def register(sub):
    i = sub.add_parser("inventory", help="GOV-1: the registry as code (validate, check against code, graph)")
    i.add_argument("action", choices=["validate", "check", "graph"])
    i.add_argument("registry")
    i.add_argument("--format", choices=["json", "mermaid", "dot"], default="mermaid")
    i.set_defaults(fn=_inventory)
    r = sub.add_parser("risk", help="GOV-3: risk classification questionnaire and the risk register")
    r.add_argument("action", choices=["classify", "validate", "seed"])
    r.add_argument("file")
    r.add_argument("--owner")
    r.set_defaults(fn=_risk)
    rp = sub.add_parser("report", help="EVID-1 control evidence report; OVR-3 reviewer metrics")
    rp.add_argument("action", choices=["controls", "reviewers"])
    rp.add_argument("--records", required=True)
    rp.add_argument("--gates")
    rp.add_argument("-o", "--out")
    rp.set_defaults(fn=_report)
    d = sub.add_parser("doctor", help="DX-3: scan an agent repository for tools, unguarded side effects, SDKs, MCP")
    d.add_argument("path")
    d.add_argument("--policy", help="write a starting argument policy here")
    d.add_argument("--registry", help="list discoveries not yet in this registry")
    d.set_defaults(fn=_doctor)
    p = sub.add_parser("proxy", help="INT-2: an OpenAI-compatible proxy that applies the gates")
    p.add_argument("--upstream", required=True)
    p.add_argument("--policy")
    p.add_argument("--compliance")
    p.add_argument("--records")
    p.add_argument("--attestations")
    p.add_argument("--destination", help="the model profile requests are sent to")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.set_defaults(fn=_proxy)
    t = sub.add_parser("temporal", help="CORE-3: check a session trace against temporal rules")
    t.add_argument("action", choices=["check"])
    t.add_argument("rules")
    t.add_argument("trace")
    t.set_defaults(fn=_temporal)
