"""Durable execution (DUR-1 to DUR-8, DUR-10): the brief's "done when" tests."""
import json
import subprocess
import sys
import threading

import pytest

from shio.durable import Crash, Engine, GateRefused, Journal, NonDeterminism, Policy, VersionMismatch, Worker
from shio.ledger import verify


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def six_step(eng, calls):
    def model(q):
        calls["model"] += 1
        return f"answer:{q}"

    def pay(amount, idempotency_key):
        calls["pay"] += 1
        calls.setdefault("keys", []).append(idempotency_key)
        return {"paid": amount}

    @eng.workflow("six")
    def six(ctx, inp):
        a = ctx.read("plan", model, "plan")
        r1 = ctx.act("pay", {"amount": 10}, pay)
        b = ctx.read("check", model, "check")
        ctx.wait(seconds=0)
        r2 = ctx.act("pay", {"amount": 20}, pay)
        c = ctx.read("summary", model, "summary")
        return [a, r1, b, r2, c]
    return six


def _expire_leases(j):
    j._db().__enter__().execute("UPDATE runs SET lease_until=0")


# ---------------- DUR-1 ----------------
def test_a_finished_runs_journal_reproduces_its_signed_record(tmp_path):
    pytest.importorskip("cryptography")
    from governance_helpers import keys
    signer, pub = keys(tmp_path / "k")
    calls = {"model": 0, "pay": 0}
    eng = Engine(Journal(tmp_path / "r.db", signer=signer), records=tmp_path / "rec", signer=signer)
    six_step(eng, calls)
    rid = eng.start("six", {"x": 1})
    assert eng.run(rid) == "completed"
    stored = json.loads((tmp_path / "rec" / f"{rid}.json").read_text())
    derived = eng.derive_record(rid)
    for k in ("integrity", "format"):
        stored.pop(k, None)
    derived.pop("format", None)
    assert json.dumps(stored, sort_keys=True) == json.dumps(derived, sort_keys=True)
    ok, report, _ = verify(tmp_path / "rec", pub)
    assert ok, report
    assert eng.journal.verify(rid, pub) == (True, [])
    db = eng.journal._db().__enter__()
    db.execute("UPDATE events SET payload='{\"value\": \"forged\"}' WHERE run_id=? AND kind='read_completed'", (rid,))
    assert not eng.journal.verify(rid, pub)[0]                             # an edited event breaks the chain


# ---------------- DUR-2, DUR-3 ----------------
def test_kill_at_every_step_boundary_repeats_no_model_call_or_side_effect(tmp_path):
    k = 0
    while True:
        k += 1
        calls = {"model": 0, "pay": 0}
        db = tmp_path / f"r{k}.db"
        eng = Engine(Journal(db), records=tmp_path / f"rec{k}")
        six_step(eng, calls)
        rid = eng.start("six", {})
        n = {"i": 0}

        def fault(kind, op, ctx, k=k):
            n["i"] += 1
            if n["i"] == k:
                raise Crash()
        eng.faults = fault
        try:
            first = eng.run(rid)
        except Crash:
            first = "crashed"
        if first == "completed":
            break
        eng2 = Engine(Journal(db), records=tmp_path / f"rec{k}")                # a new process, in effect
        six_step(eng2, calls)
        _expire_leases(eng2.journal)
        st = eng2.run(rid)
        if st == "held":                                                       # crashed between start and finish
            h = eng2.held(rid)
            assert h[0]["kind"] == "unknown_outcome"
            eng2.resolve(rid, h[0]["key"], "not_done", "M. Chen")
            st = eng2.run(rid)
        assert st == "completed", (k, st)
        assert calls["model"] == 3 and calls["pay"] == 2, (k, calls)          # nothing repeated
        assert len(set(calls["keys"])) == 2
        assert eng2.journal.verify(rid)[0]
    assert k >= 12                                                            # every boundary was a kill point


def test_crash_between_a_payment_and_its_record_never_pays_twice(tmp_path):
    paid = []

    def pay(amount):
        paid.append(amount)                     # the side effect happened...
        raise Crash()                           # ...and the process died before recording it

    def build():
        eng = Engine(Journal(tmp_path / "r.db"))

        @eng.workflow("pay")
        def wf(ctx, inp):
            return ctx.act("pay", {"amount": 99}, pay)
        return eng
    eng = build()
    rid = eng.start("pay", {})
    with pytest.raises(Crash):
        eng.run(rid)
    eng2 = build()
    _expire_leases(eng2.journal)
    assert eng2.run(rid) == "held" and paid == [99]
    h = eng2.held(rid)[0]
    assert h["kind"] == "unknown_outcome"
    eng2.resolve(rid, h["key"], "completed", "M. Chen", result={"paid": 99, "ref": "TX-1"})
    assert eng2.run(rid) == "completed" and paid == [99] and eng2.result(rid) == {"paid": 99, "ref": "TX-1"}


# ---------------- DUR-4 ----------------
class HoldGate:
    def decide(self, tool, args, approval=None):
        return ("run", f"approved by {approval['by']}") if approval else \
            ("hold", "needs a person", {"approvers": ["finance"], "deadline_seconds": 3 * 86400})

    def record(self, *a):
        pass


def test_a_run_held_overnight_resumes_after_an_approval_in_a_new_process(tmp_path):
    clock = Clock()
    sent = []

    def build():
        eng = Engine(Journal(tmp_path / "r.db"), clock=clock)

        @eng.workflow("refund")
        def wf(ctx, inp):
            return ctx.act("refund", {"amount": 400}, lambda amount: sent.append(amount) or "ok", gate=HoldGate())
        return eng
    eng = build()
    rid = eng.start("refund", {"requester": "dana"})
    assert eng.run(rid) == "held" and sent == []
    clock.t += 12 * 3600
    hold = eng.held(rid)[0]["hold_id"]
    r = subprocess.run([sys.executable, "-m", "shio.cli", "runs", "approve", rid, hold, "--by", "M. Chen", "--role",
                        "finance", "--db", str(tmp_path / "r.db")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert build().run(rid) == "completed" and sent == [400]
    ev = [e for e in Journal(tmp_path / "r.db").events(rid) if e["kind"] == "approved"][0]
    assert ev["payload"]["by"] == "M. Chen" and ev["payload"]["channel"] == "cli"


def test_approvals_need_the_role_four_eyes_and_deadlines_deny(tmp_path):
    clock = Clock()
    eng = Engine(Journal(tmp_path / "r.db"), clock=clock)

    @eng.workflow("refund")
    def wf(ctx, inp):
        try:
            return ctx.act("refund", {"amount": 400}, lambda amount: "ok", gate=HoldGate())
        except GateRefused as e:
            return f"refused: {e.why}"
    rid = eng.start("refund", {"requester": "dana"})
    eng.run(rid)
    hold = eng.held(rid)[0]["hold_id"]
    with pytest.raises(PermissionError, match="finance"):
        eng.approve(rid, hold, "M. Chen", "intern")
    with pytest.raises(PermissionError, match="four eyes"):
        eng.approve(rid, hold, "Dana", "finance")
    clock.t += 4 * 86400                                                      # past the three-day deadline
    eng.journal.set_status(rid, "runnable")
    assert eng.run(rid) == "completed" and "deadline" in eng.result(rid)


# ---------------- DUR-5 ----------------
def test_a_two_minute_wait_survives_a_restart_and_fires_once(tmp_path):
    clock = Clock()
    fired = []

    def build():
        eng = Engine(Journal(tmp_path / "r.db"), clock=clock)

        @eng.workflow("wait")
        def wf(ctx, inp):
            ctx.wait(seconds=120)
            fired.append(1)
            return "done"
        return eng
    rid = build().start("wait", {})
    assert build().run(rid) == "waiting"
    w = Worker(build(), "w1")
    assert w.run_once() is None                                               # not due yet
    clock.t += 121
    assert Worker(build(), "w2").run_once() == (rid, "completed") and fired == [1]
    assert Worker(build(), "w3").run_once() is None and fired == [1]


# ---------------- DUR-6 ----------------
def test_a_flaky_read_recovers_and_a_failing_act_is_held_with_its_error(tmp_path):
    n = {"read": 0}

    def flaky():
        n["read"] += 1
        if n["read"] < 3:
            raise ConnectionError("try again")
        return "ok"

    def broken(x):
        raise RuntimeError("payment API 500")
    eng = Engine(Journal(tmp_path / "r.db"), sleep=lambda s: None)

    @eng.workflow("w")
    def wf(ctx, inp):
        v = ctx.read("fetch", flaky, policy=Policy(retries=3, backoff=0.01))
        return v, ctx.act("pay", {"x": 1}, broken)
    rid = eng.start("w", {})
    assert eng.run(rid) == "held" and n["read"] == 3
    kinds = [e["kind"] for e in eng.journal.events(rid)]
    assert "act_failed" in kinds and eng.held(rid)[0]["kind"] == "unknown_outcome"
    failed = next(e for e in eng.journal.events(rid) if e["kind"] == "act_failed")
    assert "payment API 500" in failed["payload"]["error"]


# ---------------- DUR-7 ----------------
def test_two_workers_never_run_the_same_step_and_a_dead_workers_run_is_picked_up(tmp_path):
    executed = []
    lock = threading.Lock()

    def tool(i):
        with lock:
            executed.append(i)
        return i

    def build():
        eng = Engine(Journal(tmp_path / "r.db"))

        @eng.workflow("w")
        def wf(ctx, inp):
            return ctx.act("t", {"i": inp["i"]}, tool)
        return eng
    base = build()
    rids = [base.start("w", {"i": i}) for i in range(40)]
    workers = [Worker(build(), f"w{n}") for n in range(4)]
    threads = [threading.Thread(target=w.drain) for w in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(executed) == list(range(40))                                # each step ran exactly once
    assert all(base.journal.run(r)["status"] == "completed" for r in rids)
    # a worker that dies holding a lease: its run is picked up only after the lease expires
    clock = Clock()
    eng = Engine(Journal(tmp_path / "r2.db"), clock=clock)

    @eng.workflow("w")
    def wf2(ctx, inp):
        return ctx.act("t", {"i": 1}, lambda i: i)
    rid = eng.start("w", {})
    assert eng.journal.acquire("dead-worker", ttl=30, now=clock.t) == rid
    assert Worker(eng, "w2").run_once() is None
    clock.t += 31
    assert Worker(eng, "w2").run_once() == (rid, "completed")


# ---------------- DUR-8 ----------------
def test_a_run_started_before_a_program_change_finishes_on_the_old_version(tmp_path):
    clock = Clock()

    def v1(ctx, inp):
        ctx.wait(seconds=60)
        return "v1"

    def v2(ctx, inp):
        ctx.wait(seconds=60)
        return "v2"
    old = Engine(Journal(tmp_path / "r.db"), clock=clock)
    old.register(v1, "w", version="sha-v1")
    rid = old.start("w", {})
    assert old.run(rid) == "waiting"
    clock.t += 61
    new = Engine(Journal(tmp_path / "r.db"), clock=clock)
    new.register(v2, "w", version="sha-v2")
    with pytest.raises(VersionMismatch, match="pinned"):
        new.run(rid)
    _expire_leases(new.journal)
    assert old.run(rid) == "completed" and old.result(rid) == "v1"
    rid2 = old.start("w", {})
    old.run(rid2)
    new.migrate(rid2, "J. Ortiz", "move to v2")
    _expire_leases(new.journal)
    clock.t += 61
    assert new.run(rid2) == "completed" and new.result(rid2) == "v2"
    assert any(e["kind"] == "migrated" for e in new.journal.events(rid2))


def test_replay_is_exact_and_a_changed_program_is_caught(tmp_path):
    calls = {"model": 0, "pay": 0}
    eng = Engine(Journal(tmp_path / "r.db"))
    six_step(eng, calls)
    rid = eng.start("six", {})
    eng.run(rid)
    before = dict(calls)
    assert eng.replay(rid) == eng.result(rid) and calls == before             # no model or tool call
    eng.register(lambda ctx, inp: ctx.read("something-else", lambda: 1), "six", version=eng.journal.run(rid)[
        "program_sha256"])
    with pytest.raises(NonDeterminism):
        eng.replay(rid)


# ---------------- DUR-10 ----------------
def test_a_stuck_runs_state_held_call_and_next_timer_are_visible_from_the_cli(tmp_path):
    eng = Engine(Journal(tmp_path / "r.db"))

    @eng.workflow("refund")
    def wf(ctx, inp):
        return ctx.act("refund", {"amount": 400}, lambda amount: "ok", gate=HoldGate())
    rid = eng.start("refund", {})
    eng.run(rid)
    out = subprocess.run([sys.executable, "-m", "shio.cli", "runs", "show", rid, "--db", str(tmp_path / "r.db")],
                         capture_output=True, text=True).stdout
    assert "status HELD" in out and "HELD held" in out and "refund" in out and "next timer" in out
    lst = subprocess.run([sys.executable, "-m", "shio.cli", "runs", "list", "--db", str(tmp_path / "r.db")],
                         capture_output=True, text=True).stdout
    assert rid in lst and "held" in lst
