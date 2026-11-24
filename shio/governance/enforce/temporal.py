"""CORE-3: temporal policies over a session, compiled to a deterministic monitor (no model in the loop).

    never send_email after read_inbox            once Y has happened, X is refused for the rest of the session
    require verify_identity before change_address  X is refused unless Y happened earlier in the session
    at most 3 issue_refund per 1h                X may happen at most N times in any sliding window (s, m, h, d)
    at most 1 delete_account per session         ... or in the whole session
    only within 10m after verify_identity: change_address   X is allowed only within T after the last Y

Lines starting with # are comments. Each rule compiles to a small state machine; Monitor.check(tool, t) answers
without changing state, and Monitor.observe(tool, t) records a call that ran. The decision for a call is a pure
function of the rules and the session's history, so it replays exactly (NFR-5). Rate windows use a deque per rule,
so checking is O(1) amortised.

Limits: rules name tools, not argument values (argument rules are CORE-2); one monitor is one session; a clock that
goes backwards is refused.
"""
import collections
import dataclasses
import re

UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
NAME = r"[A-Za-z_][\w.-]*"
GRAMMAR = [
    ("never_after", re.compile(rf"^never ({NAME}) after ({NAME})$")),
    ("require_before", re.compile(rf"^require ({NAME}) before ({NAME})$")),
    ("rate", re.compile(rf"^at most (\d+) ({NAME}) per (\d+)([smhd])$")),
    ("session_cap", re.compile(rf"^at most (\d+) ({NAME}) per session$")),
    ("within", re.compile(rf"^only within (\d+)([smhd]) after ({NAME}): ({NAME})$")),
]


class TemporalError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Rule:
    kind: str
    target: str            # the tool the rule restricts
    other: str = None      # the tool it depends on
    n: int = None
    window: float = None
    text: str = ""
    line: int = 0


def compile_rules(text):
    rules = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        for kind, rx in GRAMMAR:
            m = rx.match(line)
            if not m:
                continue
            g = m.groups()
            if kind == "never_after":
                rules.append(Rule(kind, g[0], g[1], text=line, line=i))
            elif kind == "require_before":
                rules.append(Rule(kind, g[1], g[0], text=line, line=i))
            elif kind == "rate":
                rules.append(Rule(kind, g[1], n=int(g[0]), window=int(g[2]) * UNITS[g[3]], text=line, line=i))
            elif kind == "session_cap":
                rules.append(Rule(kind, g[1], n=int(g[0]), text=line, line=i))
            else:
                rules.append(Rule(kind, g[3], g[2], window=int(g[0]) * UNITS[g[1]], text=line, line=i))
            break
        else:
            raise TemporalError(f"line {i}: {raw.strip()!r} is not a temporal rule. Write one of: never X after Y | "
                                f"require Y before X | at most N X per 10m | at most N X per session | "
                                f"only within 10m after Y: X")
    return rules


class Monitor:
    def __init__(self, rules):
        self.rules = compile_rules(rules) if isinstance(rules, str) else list(rules)
        self.seen = set()
        self.last = {}
        self.counts = collections.Counter()
        self.windows = {r: collections.deque() for r in self.rules if r.kind == "rate"}
        self.clock = float("-inf")

    def check(self, tool, t):
        """-> [violated rule texts] for calling `tool` at time t. Doesn't change state."""
        if t < self.clock:
            return ["the clock went backwards: refused"]
        out = []
        for r in self.rules:
            if r.target != tool:
                continue
            if r.kind == "never_after" and r.other in self.seen:
                out.append(r.text)
            elif r.kind == "require_before" and r.other not in self.seen:
                out.append(r.text)
            elif r.kind == "session_cap" and self.counts[tool] >= r.n:
                out.append(r.text)
            elif r.kind == "rate":
                dq = self.windows[r]
                live = sum(1 for x in dq if t - x < r.window)
                if live >= r.n:
                    out.append(r.text)
            elif r.kind == "within":
                if r.other not in self.last or t - self.last[r.other] > r.window:
                    out.append(r.text)
        return out

    def observe(self, tool, t):
        if t < self.clock:
            raise TemporalError("the clock went backwards")
        self.clock = t
        self.seen.add(tool)
        self.last[tool] = t
        self.counts[tool] += 1
        for r, dq in self.windows.items():
            if r.target == tool:
                dq.append(t)
            while dq and t - dq[0] >= r.window:
                dq.popleft()

    def gate(self, tool, t):
        """check, and if allowed, observe. -> violations (empty means it ran)."""
        v = self.check(tool, t)
        if not v:
            self.observe(tool, t)
        return v
