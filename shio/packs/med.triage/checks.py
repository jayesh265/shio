"""med.triage: the red-flag list runs in code before the model replies, with fixed emergency wording and an
out-of-scope refusal.

Red flags are matched with an Aho-Corasick automaton built once from every phrase in the list, so a message is
scanned in one pass, O(length of the message + matches), however long the list grows. A match preceded by a negation
in the same clause ("no chest pain", "denies shortness of breath") does not count.

TriageGate is what an agent wraps its model in: a red flag returns the fixed emergency wording and the model is never
called; an out-of-scope request returns the fixed refusal; only then may the model answer. In regulated use the gate
refuses to start unless the clinical safety lead has approved this exact list (its sha256, in an approval log).
"""
import hashlib
import json
import re
from collections import deque
from pathlib import Path

from shio.governance.verdict import Verdict

HERE = Path(__file__).resolve().parent
NEGATIONS = {"no", "not", "denies", "denied", "without", "never", "negative", "free"}
CLAUSE_BREAK = re.compile(r"[.;!?\n]|\bbut\b|\bhowever\b")


class AhoCorasick:
    """Multi-pattern matcher. Build: a trie of the patterns, then failure links by breadth-first search (each node's
    link points at the longest proper suffix of its path that is also a path in the trie), with outputs merged along
    the links. Search: one pass over the text."""

    def __init__(self, patterns):
        self.goto, self.fail, self.out = [{}], [0], [[]]
        for key, pattern in patterns:
            node = 0
            for ch in pattern:
                if ch not in self.goto[node]:
                    self.goto.append({})
                    self.fail.append(0)
                    self.out.append([])
                    self.goto[node][ch] = len(self.goto) - 1
                node = self.goto[node][ch]
            self.out[node].append((key, len(pattern)))
        queue = deque(self.goto[0].values())
        while queue:
            node = queue.popleft()
            for ch, child in self.goto[node].items():
                queue.append(child)
                f = self.fail[node]
                while f and ch not in self.goto[f]:
                    f = self.fail[f]
                self.fail[child] = self.goto[f].get(ch, 0) if self.goto[f].get(ch, 0) != child else 0
                self.out[child] = self.out[child] + self.out[self.fail[child]]

    def search(self, text):
        """-> [(key, start, end)] for every occurrence of every pattern."""
        node, hits = 0, []
        for i, ch in enumerate(text):
            while node and ch not in self.goto[node]:
                node = self.fail[node]
            node = self.goto[node].get(ch, 0)
            for key, n in self.out[node]:
                hits.append((key, i - n + 1, i + 1))
        return hits


def _norm(text):
    return " " + re.sub(r"[^a-z0-9]+", " ", str(text or "").lower()).strip() + " "


class RedFlags:
    def __init__(self, path=None):
        self.path = Path(path or HERE / "red-flags.json")
        raw = self.path.read_bytes()
        self.sha256 = hashlib.sha256(raw).hexdigest()
        d = json.loads(raw)
        self.status, self.flags, self.scope = d.get("status"), {f["id"]: f for f in d["flags"]}, d["scope"]
        self.emergency, self.refusal = d["emergency_wording"], d["out_of_scope_wording"]
        # whole words only: the patterns and the text are padded with spaces
        self.matcher = AhoCorasick([(f["id"], _norm(p)) for f in d["flags"] for p in f["phrases"]])
        self.out_of_scope = AhoCorasick([(p, _norm(p)) for p in self.scope["refuse"]])
        self.in_scope = AhoCorasick([(p, _norm(p)) for p in self.scope["topics"]])

    def matches(self, message):
        """-> [flag id] of every red flag in the message that is not negated, in order of appearance."""
        text = _norm(message)
        found = []
        for key, start, end in sorted(self.matcher.search(text), key=lambda h: h[1]):
            clause = CLAUSE_BREAK.split(text[:start])[-1].split()
            if set(clause[-4:]) & NEGATIONS:
                continue
            if key not in found:
                found.append(key)
        return found

    def scope_of(self, message):
        """-> "refuse" (asks for something out of scope), "in" (a topic in scope) or "out" (neither)."""
        text = _norm(message)
        if self.out_of_scope.search(text):
            return "refuse"
        return "in" if self.in_scope.search(text) else "out"


_flags = None


def flags():
    global _flags
    if _flags is None:
        _flags = RedFlags()
    return _flags


# ---------------- runtime checks ----------------
def no_red_flag(message, red_flags=None):
    """TRI-1: the message has no red flag (a negated mention doesn't count). When it fails, the agent must give the
    fixed emergency wording and must not call the model."""
    hits = (red_flags or flags()).matches(message)
    if hits:
        rf = red_flags or flags()
        return Verdict.fail("red flag: " + ", ".join(f"{h} ({rf.flags[h]['category']})" for h in hits), hits)
    return Verdict.ok("no red flag")


def in_scope(message, red_flags=None):
    """TRI-2: the request is one the agent may answer: it names a topic in scope and asks for nothing out of scope
    (a diagnosis, a prescription, a dose change)."""
    s = (red_flags or flags()).scope_of(message)
    if s == "refuse":
        return Verdict.fail("asks for something out of scope (diagnosis, prescribing or dosing)")
    if s == "out":
        return Verdict.fail("not about a topic this agent covers")
    return Verdict.ok("in scope")


# ---------------- the gate (not a check) ----------------
class TriageGate:
    """Red flags first, then scope, then the model. answer(message) -> {"route", "reply", "flags"}. The model's
    answer() is called only when there is no red flag and the request is in scope."""

    def __init__(self, model, red_flags=None, approvals=None, require_approval=False):
        self.model, self.red_flags = model, red_flags or flags()
        if require_approval:
            from shio.governance.chain import APPROVED, ApprovalLog
            log = approvals if isinstance(approvals, ApprovalLog) else ApprovalLog(approvals) if approvals else None
            state = log.status(self.red_flags.sha256, ["clinical_safety_lead"])[0] if log else "PENDING"
            if state != APPROVED:
                raise PermissionError(f"the red-flag list {self.red_flags.sha256[:12]} is not approved by the clinical "
                                      f"safety lead ({state}); the triage gate will not start")

    def answer(self, message):
        hits = self.red_flags.matches(message)
        if hits:
            return {"route": "EMERGENCY", "reply": self.red_flags.emergency, "flags": hits}
        scope = self.red_flags.scope_of(message)
        if scope != "in":
            return {"route": "OUT_OF_SCOPE", "reply": self.red_flags.refusal, "flags": []}
        return {"route": "MODEL", "reply": self.model(message), "flags": []}
