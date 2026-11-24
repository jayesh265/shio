"""Commands for durable runs and the harness (DUR-2, DUR-4, DUR-7, DUR-8, DUR-10, HAR-10, HAR-12).

    shio init coding|clinical-intake DIR
    shio runs list|show|verify [RUN] --db .shio/runs.db
    shio runs approve|reject RUN HOLD --by NAME --role ROLE --db ...
    shio runs resolve RUN KEY completed|not_done --by NAME [--result JSON] --db ...
    shio resume RUN --agent agent.py[:build]          resume on this machine (any worker can)
    shio worker --agent agent.py[:build] [--once]     take runnable runs, one lease at a time
    shio runs migrate RUN --agent agent.py --by NAME --reason TEXT
    shio hook claude-code [--policy P] [--rules R] [--ledger L]
"""
import datetime as dt
import importlib.util
import json
import sys
import time
from pathlib import Path


def _journal(db):
    from ..durable import Journal
    return Journal(db)


def _load_engine(spec, db=None):
    path, _, attr = spec.partition(":")
    sys.path.insert(0, str(Path(path).resolve().parent))
    s = importlib.util.spec_from_file_location("shio_agent_module", path)
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    build = getattr(mod, attr or "build")
    return build(db) if db else build()


def _fmt(t):
    return dt.datetime.fromtimestamp(t).isoformat(timespec="seconds") if t else "-"


def _runs(a):
    j = _journal(a.db)
    if a.action == "list":
        for r in j.runs(a.status):
            print(f"{r['id']:28} {r['workflow']:18} {r['status']:9} next timer {_fmt(r['wake_at']):19} "
                  f"{(r['note'] or '')[:60]}")
        return 0
    if not a.run:
        print("which run?")
        return 2
    if a.action == "show":
        from ..durable import Engine
        r = j.run(a.run)
        eng = Engine(j)
        ok, problems = j.verify(a.run)
        print(f"{r['id']}  workflow {r['workflow']}  program {r['program_sha256'][:12]}  status {r['status'].upper()}")
        print(f"  next timer: {_fmt(r['wake_at'])}   lease: {r['lease_owner'] or '-'} until {_fmt(r['lease_until'])}")
        print(f"  journal: {len(j.events(a.run))} events, {'verified' if ok else 'BROKEN: ' + '; '.join(problems)}")
        for h in eng.held(a.run):
            print(f"  HELD {h['kind']:15} step {h['op']} {h['tool']}  hold {h.get('hold_id') or h['key'][:12]}  "
                  f"{h.get('why', '')}")
        for e in j.events(a.run)[-12:]:
            print(f"    {e['seq']:4} {_fmt(e['time'])} {e['kind']:16} {e['name'] or ''}")
        return 0
    if a.action == "verify":
        ok, problems = j.verify(a.run)
        print("journal verified" if ok else "\n".join(problems))
        return 0 if ok else 1
    from ..durable import Engine
    eng = Engine(j)
    if a.action in ("approve", "reject"):
        (eng.approve if a.action == "approve" else eng.reject)(a.run, a.hold, a.by, a.role, channel="cli")
        print(f"{a.action}d {a.hold} on {a.run}; resume it with: shio resume {a.run} --agent <agent.py>")
    elif a.action == "resolve":
        eng.resolve(a.run, a.hold, a.outcome, a.by, json.loads(a.result) if a.result else None)
        print(f"resolved {a.hold} on {a.run} as {a.outcome}")
    elif a.action == "migrate":
        eng2 = _load_engine(a.agent, a.db)
        eng2.migrate(a.run, a.by, a.reason)
        print(f"{a.run} migrated to the current version (recorded in its journal)")
    return 0


def _resume(a):
    eng = _load_engine(a.agent, a.db)
    print(f"{a.run}: {eng.run(a.run)}")


def _worker(a):
    from ..durable import Worker
    eng = _load_engine(a.agent, a.db)
    w = Worker(eng, a.name)
    while True:
        done = w.drain()
        for rid, st in done:
            print(f"{w.name}: {rid} -> {st}")
        if a.once:
            return 0
        time.sleep(a.poll)


def _init(a):
    from .templates import create
    p = create(a.template, a.folder)
    print(f"wrote {p}\nrun:  cd {a.folder} && python agent.py")


def _hook(a):
    from ..adapters.claude_code import main
    return main(a.rest)


def register(sub):
    r = sub.add_parser("runs", help="durable runs: list, show, verify, approve, reject, resolve, migrate")
    r.add_argument("action", choices=["list", "show", "verify", "approve", "reject", "resolve", "migrate"])
    r.add_argument("run", nargs="?")
    r.add_argument("hold", nargs="?", help="approve/reject: the hold id; resolve: the call key")
    r.add_argument("outcome", nargs="?", choices=["completed", "not_done"])
    r.add_argument("--db", default=".shio/runs.db")
    r.add_argument("--status")
    r.add_argument("--by")
    r.add_argument("--role", default="operator")
    r.add_argument("--result")
    r.add_argument("--agent")
    r.add_argument("--reason", default="")
    r.set_defaults(fn=_runs)
    re_ = sub.add_parser("resume", help="DUR-2: resume a run from its journal")
    re_.add_argument("run")
    re_.add_argument("--agent", required=True, help="agent.py[:build], which registers the workflow")
    re_.add_argument("--db")
    re_.set_defaults(fn=_resume)
    w = sub.add_parser("worker", help="DUR-7: run runnable runs from the journal, holding leases")
    w.add_argument("--agent", required=True)
    w.add_argument("--db")
    w.add_argument("--name")
    w.add_argument("--once", action="store_true")
    w.add_argument("--poll", type=float, default=2.0)
    w.set_defaults(fn=_worker)
    i = sub.add_parser("init", help="HAR-12: a guarded, durable agent from a template, runnable offline")
    i.add_argument("template", choices=["coding", "clinical-intake"])
    i.add_argument("folder")
    i.set_defaults(fn=_init)
    h = sub.add_parser("hook", help="HAR-10: Shio Guard as a hook for another harness")
    h.add_argument("host", choices=["claude-code"])
    h.add_argument("rest", nargs="*")
    h.set_defaults(fn=_hook)
