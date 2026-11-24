"""HAR-7: scheduler and triggers. Cron and webhook triggers start agents; unattended runs hold every act.

  Cron("*/15 9-17 * * 1-5")   five fields (minute hour day-of-month month day-of-week) with *, lists, ranges and
                              steps; next(after) finds the next fire time
  Scheduler.add(...)          a job: name, cron, workflow, input. tick(now) starts each due job once per slot; the
                              slot is recorded in a signed chain first, so two schedulers (or a restart) never start
                              the same slot twice
  Webhook(secret)             verifies an HMAC-SHA256 signature over the body before starting a run; the payload goes
                              into the run as untrusted input, never as instructions
  unattended                  scheduled and webhook runs carry {"unattended": true}; an AgentLoop given unattended=True
                              holds every acts call unless an allow rule passes it, so a run nobody is watching stops in
                              hold at its first side effect
"""
import datetime as dt
import hashlib
import hmac
import json

from ..governance.chain import SignedChain


class CronError(ValueError):
    pass


def _field(spec, lo, hi):
    out = set()
    for part in spec.split(","):
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            step = int(s)
        if part == "*":
            a, b = lo, hi
        elif "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
        else:
            a = b = int(part)
        if a < lo or b > hi or a > b or step < 1:
            raise CronError(f"{spec!r} is out of range {lo}-{hi}")
        out.update(range(a, b + 1, step))
    return out


class Cron:
    def __init__(self, expr):
        f = expr.split()
        if len(f) != 5:
            raise CronError("a cron expression has five fields: minute hour day month weekday")
        self.expr = expr
        self.minute, self.hour, self.day, self.month = _field(f[0], 0, 59), _field(f[1], 0, 23), _field(f[2], 1, 31), \
            _field(f[3], 1, 12)
        self.weekday = {d % 7 for d in _field(f[4], 0, 7)}          # 0 and 7 are Sunday

    def matches(self, t):
        return (t.minute in self.minute and t.hour in self.hour and t.day in self.day and t.month in self.month
                and (t.isoweekday() % 7) in self.weekday)

    def next(self, after):
        t = (after + dt.timedelta(minutes=1)).replace(second=0, microsecond=0)
        for _ in range(366 * 24 * 60):
            if self.matches(t):
                return t
            t += dt.timedelta(minutes=1)
        raise CronError(f"{self.expr} never fires")


class Scheduler:
    def __init__(self, engine, folder, signer=None):
        self.engine, self.chain, self.signer = engine, SignedChain(folder, "schedule"), signer
        self.jobs = {}

    def add(self, name, cron, workflow, inp=None):
        self.jobs[name] = (Cron(cron), workflow, dict(inp or {}))

    def _fired(self):
        return {(e["job"], e["slot"]) for e in self.chain.entries() if e["kind"] == "fired"}

    def tick(self, now):
        """Start every job whose current minute matches and hasn't fired for this slot. -> [run ids]."""
        started = []
        slot_t = now.replace(second=0, microsecond=0)
        fired = self._fired()
        for name, (cron, wf, inp) in sorted(self.jobs.items()):
            slot = slot_t.isoformat()
            if not cron.matches(slot_t) or (name, slot) in fired:
                continue
            self.chain.append("fired", {"job": name, "slot": slot}, self.signer)        # first: at most once
            rid = self.engine.start(wf, {**inp, "unattended": True, "trigger": f"cron:{name}@{slot}"})
            self.chain.append("started", {"job": name, "slot": slot, "run_id": rid}, self.signer)
            started.append(rid)
        return started


class Webhook:
    def __init__(self, engine, workflow, secret):
        if len(secret) < 16:
            raise ValueError("a webhook secret needs at least 16 characters")
        self.engine, self.workflow, self.secret = engine, workflow, secret.encode()

    def sign(self, body):
        return "sha256=" + hmac.new(self.secret, body, hashlib.sha256).hexdigest()

    def receive(self, body, signature, request=None):
        """-> run id, or PermissionError for a bad signature. The payload is untrusted input."""
        if not hmac.compare_digest(self.sign(body), signature or ""):
            raise PermissionError("webhook signature does not match")
        try:
            payload = json.loads(body)
        except ValueError:
            payload = {"raw": body.decode(errors="replace")}
        return self.engine.start(self.workflow, {"request": request or "Handle the webhook event in the untrusted "
                                                                      "record.", "untrusted": payload,
                                                 "unattended": True, "trigger": "webhook"})
