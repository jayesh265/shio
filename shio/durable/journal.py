"""DUR-1: the run journal. An append-only event history per run, in SQLite (standard library; Postgres is not built).

Tables:
  runs    id, workflow, program_sha256, input, status, wake_at, lease_owner, lease_until, created, updated
  events  run_id, seq, kind, op, name, key, payload, time, prev, sha256, signature   (PRIMARY KEY run_id, seq)

Events are hash-chained per run (each names the previous event's sha256) and signed when a signer is given, so
`verify(run_id)` detects an edited, removed or reordered event. The (run_id, seq) key means two writers can never
both append the same position: the second insert fails, which is the last line of defence behind leases (DUR-7).

Status: runnable | waiting (a timer: wake_at) | held (a person must act) | completed | failed.
"""
import json
import sqlite3
import threading
import time
from pathlib import Path

from ..ledger import GENESIS, sha256

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, workflow TEXT NOT NULL, program_sha256 TEXT NOT NULL, input TEXT NOT NULL,
  status TEXT NOT NULL, wake_at REAL, lease_owner TEXT, lease_until REAL, created REAL NOT NULL, updated REAL NOT NULL,
  note TEXT);
CREATE TABLE IF NOT EXISTS events (
  run_id TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, op INTEGER, name TEXT, key TEXT, payload TEXT,
  time REAL NOT NULL, prev TEXT NOT NULL, sha256 TEXT NOT NULL, key_id TEXT, signature TEXT,
  PRIMARY KEY (run_id, seq));
CREATE INDEX IF NOT EXISTS runs_status ON runs(status, wake_at);
"""
RUNNABLE = ("runnable", "waiting")


class JournalError(RuntimeError):
    pass


class LeaseLost(JournalError):
    pass


class Journal:
    def __init__(self, path, signer=None):
        self.path, self.signer = str(path), signer
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        with self._db() as db:
            db.executescript(SCHEMA)

    def _db(self):
        db = getattr(self._local, "db", None)
        if db is None:
            db = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA busy_timeout=30000")
            db.row_factory = sqlite3.Row
            self._local.db = db
        return _Tx(db)

    # ---------------- runs ----------------
    def create(self, run_id, workflow, program_sha, inp):
        now = time.time()
        with self._db() as db:
            db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (run_id, workflow, program_sha, json.dumps(inp, sort_keys=True, default=str), "runnable", None,
                        None, None, now, now, None))
        self.append(run_id, "run_started", payload={"workflow": workflow, "program_sha256": program_sha,
                                                    "input_sha256": sha256(inp)})

    def run(self, run_id):
        with self._db() as db:
            r = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if r is None:
            raise JournalError(f"no run {run_id}")
        d = dict(r)
        d["input"] = json.loads(d["input"])
        return d

    def runs(self, status=None):
        with self._db() as db:
            q = "SELECT * FROM runs" + (" WHERE status=?" if status else "") + " ORDER BY created"
            rows = db.execute(q, (status,) if status else ()).fetchall()
        return [dict(r) for r in rows]

    def set_status(self, run_id, status, wake_at=None, note=None, owner=None):
        with self._db() as db:
            q = "UPDATE runs SET status=?, wake_at=?, note=?, updated=? WHERE id=?"
            args = [status, wake_at, note, time.time(), run_id]
            if owner is not None:
                q += " AND lease_owner=?"
                args.append(owner)
            if db.execute(q, args).rowcount == 0 and owner is not None:
                raise LeaseLost(f"{run_id}: the lease was lost")

    def set_program(self, run_id, sha):
        with self._db() as db:
            db.execute("UPDATE runs SET program_sha256=?, updated=? WHERE id=?", (sha, time.time(), run_id))

    # ---------------- leases (DUR-7) ----------------
    def acquire(self, owner, ttl=30.0, run_id=None, now=None):
        """Take one runnable run (or run_id) whose lease is free or expired. Atomic: -> run id or None."""
        now = now or time.time()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                q = ("SELECT id FROM runs WHERE (status='runnable' OR (status='waiting' AND wake_at<=?)) "
                     "AND (lease_until IS NULL OR lease_until<?)")
                args = [now, now]
                if run_id:
                    q += " AND id=?"
                    args.append(run_id)
                row = db.execute(q + " ORDER BY updated LIMIT 1", args).fetchone()
                if row is None:
                    db.execute("COMMIT")
                    return None
                db.execute("UPDATE runs SET lease_owner=?, lease_until=? WHERE id=?", (owner, now + ttl, row["id"]))
                db.execute("COMMIT")
                return row["id"]
            except Exception:
                db.execute("ROLLBACK")
                raise

    def renew(self, run_id, owner, ttl=30.0):
        with self._db() as db:
            n = db.execute("UPDATE runs SET lease_until=? WHERE id=? AND lease_owner=?",
                           (time.time() + ttl, run_id, owner)).rowcount
        if n == 0:
            raise LeaseLost(f"{run_id}: {owner} no longer holds the lease")

    def release(self, run_id, owner):
        with self._db() as db:
            db.execute("UPDATE runs SET lease_owner=NULL, lease_until=NULL WHERE id=? AND lease_owner=?",
                       (run_id, owner))

    # ---------------- events ----------------
    def events(self, run_id):
        with self._db() as db:
            rows = db.execute("SELECT * FROM events WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d["payload"]) if d["payload"] else None
            out.append(d)
        return out

    def append(self, run_id, kind, op=None, name=None, key=None, payload=None, owner=None, t=None):
        """Append one event. With owner, the lease must still be theirs (checked in the same transaction)."""
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if owner is not None:
                    r = db.execute("SELECT lease_owner, lease_until FROM runs WHERE id=?", (run_id,)).fetchone()
                    if r is None or r["lease_owner"] != owner:
                        raise LeaseLost(f"{run_id}: {owner} no longer holds the lease")
                last = db.execute("SELECT seq, sha256 FROM events WHERE run_id=? ORDER BY seq DESC LIMIT 1",
                                  (run_id,)).fetchone()
                seq = last["seq"] + 1 if last else 0
                prev = last["sha256"] if last else GENESIS
                body = {"run_id": run_id, "seq": seq, "kind": kind, "op": op, "name": name, "key": key,
                        "payload": payload, "time": t if t is not None else time.time(), "prev": prev}
                h = sha256(body)
                kid = sig = None
                if self.signer is not None:
                    kid, sig = self.signer.key_id, self.signer.sign(h)
                db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                           (run_id, seq, kind, op, name, key, json.dumps(payload, sort_keys=True, default=str)
                            if payload is not None else None, body["time"], prev, h, kid, sig))
                db.execute("UPDATE runs SET updated=? WHERE id=?", (time.time(), run_id))
                db.execute("COMMIT")
                return {**body, "sha256": h}
            except Exception:
                db.execute("ROLLBACK")
                raise

    def verify(self, run_id, public_key=None, secret=None):
        """-> (ok, problems): every event's hash, the chain, and (with a key) every signature."""
        from ..ledger import _check_signature
        problems, prev = [], GENESIS
        for i, e in enumerate(self.events(run_id)):
            body = {k: e[k] for k in ("run_id", "seq", "kind", "op", "name", "key", "payload", "time", "prev")}
            if e["seq"] != i:
                problems.append(f"event {i}: sequence {e['seq']} out of order")
            if e["prev"] != prev:
                problems.append(f"event {i}: chain broken")
            if sha256(body) != e["sha256"]:
                problems.append(f"event {i}: edited")
            if public_key is not None or secret is not None:
                st = _check_signature({"sha256": e["sha256"], "key_id": e["key_id"], "signature": e["signature"]},
                                      public_key, secret)
                if st != "ok":
                    problems.append(f"event {i}: {st}")
            prev = e["sha256"]
        return not problems, problems


class _Tx:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        return self.db

    def __exit__(self, *a):
        return False
