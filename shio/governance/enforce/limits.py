"""CORE-4 circuit breakers and kill switch; CORE-6 MCP definition pinning; CORE-7 detector plug-ins as signals.

Breakers. Stateful limits per scope (an agent, a session, a tenant): calls, spend, records touched, each over a
sliding window. A call that would exceed a limit trips the breaker: the trip is a signed record, and every later call
in that scope is refused until a named person resumes it (a signed sign-off; the person who tripped it can't). The
kill switch stops an agent at once, recorded with who and why; only a resume by a second person restarts it.

MCP pinning. When a person approves an MCP server, each tool's name, description and input schema are hashed and
pinned. Later listings are compared: a changed description or schema, or a new tool, is held until re-approved (the
"rug pull"); a removed tool is reported. Tool output is labelled untrusted by default.

Signals. A detector (jailbreak classifier, personal-data model, code scanner) returns a Signal: a score and a label,
recorded with its name and version. It never decides: a SignalRule does (score >= threshold -> hold or deny). A
detector that fails or exceeds its timeout follows the rule's fail-closed setting (hold or deny), never a pass.
"""
import collections
import concurrent.futures
import dataclasses
import hashlib
import json
import time

from ..chain import ChainError, SignedChain, _same_person


# ---------------- CORE-4 ----------------
class Breakers:
    def __init__(self, folder, limits, window=3600, signer=None, clock=time.time):
        """limits: {"calls": 100, "spend": 500.0, "records": 1000} per scope per window seconds."""
        self.chain, self.limits, self.window, self.signer, self.clock = SignedChain(folder, "breakers"), limits, \
            window, signer, clock
        self.usage = collections.defaultdict(collections.deque)      # scope -> deque[(t, {metric: amount})]

    def _state(self):
        tripped, killed = {}, {}
        for e in self.chain.entries():
            if e["kind"] == "trip":
                tripped[e["scope"]] = e
            elif e["kind"] == "kill":
                killed[e["scope"]] = e
            elif e["kind"] == "resume":
                tripped.pop(e["scope"], None)
                killed.pop(e["scope"], None)
        return tripped, killed

    def allow(self, scopes, usage):
        """scopes: ["agent:helpdesk", "session:abc", "tenant:t1"]; usage: {"calls": 1, "spend": 120}. -> (ok, why)."""
        tripped, killed = self._state()
        for s in scopes:
            if s in killed:
                return False, f"{s} was stopped by the kill switch ({killed[s]['reason']})"
            if s in tripped:
                return False, f"{s} breaker is open since {tripped[s]['why']}; a person must resume it"
        now = self.clock()
        for s in scopes:
            dq = self.usage[s]
            while dq and now - dq[0][0] >= self.window:
                dq.popleft()
            for metric, cap in self.limits.items():
                used = sum(u.get(metric, 0) for _, u in dq) + usage.get(metric, 0)
                if used > cap:
                    why = f"{metric} {used} over {cap} per {self.window}s"
                    self.chain.append("trip", {"scope": s, "why": why, "usage": usage}, self.signer)
                    return False, f"{s} breaker tripped: {why}"
        for s in scopes:
            self.usage[s].append((now, dict(usage)))
        return True, ""

    def kill(self, scope, by, reason):
        if not str(reason).strip():
            raise ChainError("the kill switch needs a reason")
        self.chain.append("kill", {"scope": scope, "by": by, "reason": reason}, self.signer)

    def resume(self, scope, by, role, note):
        tripped, killed = self._state()
        e = killed.get(scope) or tripped.get(scope)
        if e is None:
            raise ChainError(f"{scope} is not stopped")
        if e["kind"] == "kill" and _same_person(by, e["by"]):
            raise ChainError("maker-checker: whoever used the kill switch can't resume it")
        self.chain.append("resume", {"scope": scope, "by": by, "role": role, "note": note}, self.signer)
        self.usage.pop(scope, None)


# ---------------- CORE-6 ----------------
def tool_hash(tool):
    canon = {"name": tool.get("name"), "description": tool.get("description") or "",
             "inputSchema": tool.get("inputSchema") or tool.get("input_schema") or {}}
    return hashlib.sha256(json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class McpPins:
    def __init__(self, folder, signer=None):
        self.chain, self.signer = SignedChain(folder, "mcp-pins"), signer

    def approve(self, server, tools, by):
        self.chain.append("pin", {"server": server, "by": by, "tools": {t["name"]: tool_hash(t) for t in tools}},
                          self.signer)

    def pinned(self, server):
        pins = {}
        for e in self.chain.entries():
            if e.get("server") == server and e["kind"] == "pin":
                pins = e["tools"]
        return pins

    def check(self, server, tools):
        """-> {"hold": bool, "changed": [...], "new": [...], "removed": [...], "allowed": [tool names]}."""
        pins = self.pinned(server)
        now = {t["name"]: tool_hash(t) for t in tools}
        changed = sorted(n for n in now if n in pins and pins[n] != now[n])
        new = sorted(n for n in now if n not in pins)
        removed = sorted(n for n in pins if n not in now)
        return {"hold": bool(changed or new or not pins), "changed": changed, "new": new, "removed": removed,
                "allowed": sorted(n for n in now if pins.get(n) == now[n]), "unpinned_server": not pins}

    @staticmethod
    def label_output(result):
        return {"trust": "untrusted", "content": result}


# ---------------- CORE-7 ----------------
@dataclasses.dataclass(frozen=True)
class Signal:
    detector: str
    version: str
    score: float = None
    label: str = None
    error: str = None
    ms: float = 0.0


@dataclasses.dataclass(frozen=True)
class SignalRule:
    detector: str
    threshold: float
    outcome: str = "hold"             # what a high score means
    on_error: str = "deny"            # fail-closed setting: hold or deny

    def __post_init__(self):
        if self.on_error not in ("hold", "deny") or self.outcome not in ("hold", "deny"):
            raise ValueError("outcome and on_error must be hold or deny (a detector failure is never a pass)")


class Signals:
    def __init__(self, detectors, rules, timeout=2.0):
        """detectors: {name: (version, fn(text) -> float score or (score, label))}."""
        self.detectors, self.rules, self.timeout = detectors, rules, timeout
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(detectors)))

    def run(self, text):
        out = []
        futs = {n: self.pool.submit(fn, text) for n, (_, fn) in self.detectors.items()}
        for n, f in futs.items():
            t0 = time.perf_counter()
            try:
                r = f.result(timeout=self.timeout)
                score, label = (r if isinstance(r, tuple) else (r, None))
                out.append(Signal(n, self.detectors[n][0], float(score), label, ms=(time.perf_counter() - t0) * 1000))
            except concurrent.futures.TimeoutError:
                out.append(Signal(n, self.detectors[n][0], error="timeout"))
            except Exception as e:
                out.append(Signal(n, self.detectors[n][0], error=type(e).__name__))
        return out

    def decide(self, text):
        """-> (outcome allow|hold|deny, signals, reasons). The rules decide; signals are evidence."""
        sigs = self.run(text)
        by = {s.detector: s for s in sigs}
        rank = {"allow": 0, "hold": 1, "deny": 2}
        outcome, reasons = "allow", []
        for r in self.rules:
            s = by.get(r.detector)
            if s is None or s.error:
                o, why = r.on_error, f"{r.detector} {'missing' if s is None else s.error}: {r.on_error} (fail closed)"
            elif s.score >= r.threshold:
                o, why = r.outcome, f"{r.detector} score {s.score:.2f} >= {r.threshold}"
            else:
                continue
            reasons.append(why)
            outcome = max(outcome, o, key=rank.get)
        return outcome, sigs, reasons
