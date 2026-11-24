"""Human oversight as a limited resource: EVID-1 control evidence report, OVR-3 reviewer metrics, OVR-1 review queue.

control_report(records, gates)   per control: how often it ran and fired, how often a person overrode it (approved a
                                 decision the control flagged, or approved a held gate call), how often a person
                                 rejected what the control passed (a miss), and which enforced controls never fired
reviewer_metrics(records)        per reviewer: items decided, median minutes to decide, approval rate; agreement on
                                 items two reviewers decided
ReviewQueue                      held items ranked by risk and novelty, an hourly cap per reviewer, and an explicit
                                 overflow rule: "queue" keeps waiting items, "deny" refuses the lowest-risk overflow
                                 (recorded as such) so a flood of benign holds can't bury a risky one
"""
import dataclasses
import heapq
import itertools
import json
import math
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path


def _records(folder):
    from ..ledger import _entries
    folder = Path(folder)
    entries = _entries(folder)
    recs = {}
    for e in entries:
        if e.get("kind") == "record" and (folder / e["file"]).exists():
            recs[e["file"]] = json.loads((folder / e["file"]).read_text())
    return entries, recs


def _runs(rec):
    yield rec
    for c in rec.get("children", []):
        yield from _runs(c)


def control_report(records=None, gates=None, packs=None):
    stats = defaultdict(lambda: {"ran": 0, "fired": 0, "overridden": 0, "missed": 0, "source": set()})
    if records:
        entries, recs = _records(records)
        signoffs = defaultdict(list)
        for e in entries:
            if e.get("kind") == "signoff":
                signoffs[e["file"]].append(e.get("decision", "approved"))
        for f, rec in recs.items():
            decided = signoffs.get(f, [])
            approved, rejected = "approved" in decided, "rejected" in decided
            for run in _runs(rec):
                for c in run.get("checks", []):
                    if c.get("skipped"):
                        continue
                    for ctl in c.get("controls", []):
                        key = ctl.split("@")[0] + ":" + ctl.split(":")[-1] if "@" in ctl else ctl
                        s = stats[key]
                        s["ran"] += 1
                        s["source"].add("records")
                        if not c["passed"]:
                            s["fired"] += 1
                            s["overridden"] += approved and not rejected
                        elif rejected:
                            s["missed"] += 1
    if gates and (Path(gates) / "preflight.jsonl").exists():
        from .chain import SignedChain
        approvals = SignedChain(gates, "preflight-holds").entries()
        approved_holds = {e["subject"].get("title") for e in approvals if e.get("decision") == "approved"}
        for e in SignedChain(gates, "preflight").entries():
            if e.get("kind") != "preflight_decision":
                continue
            objected = {r["control"] for r in e.get("results", [])}
            for key in e.get("evaluated", []):
                if key not in objected:
                    stats[key]["ran"] += 1
                    stats[key]["source"].add("gate")
            for r in e.get("results", []):
                if r["control"].startswith("gate:"):
                    continue
                s = stats[r["control"]]
                s["ran"] += 1
                s["source"].add("gate")
                if r["outcome"] != "allow" and not r.get("advisory"):
                    s["fired"] += 1
                    s["overridden"] += r["outcome"] == "hold" and e.get("hold") in approved_holds
    enforced = set()
    if packs is not None:
        for p in packs:
            for c in p.controls:
                if any(pr.kind.value in ("gate", "runtime") for pr in c.proofs):
                    enforced.add(f"{p.id}:{c.id}")
    rows = [{"control": k, "ran": v["ran"], "fired": v["fired"], "fire_rate": round(v["fired"] / v["ran"], 4)
             if v["ran"] else None, "overridden": v["overridden"],
             "override_rate": round(v["overridden"] / v["fired"], 4) if v["fired"] else None, "missed": v["missed"],
             "source": sorted(v["source"])} for k, v in sorted(stats.items())]
    never = sorted(c for c in enforced if not stats.get(c, {}).get("fired"))
    never_ran = sorted(c for c in enforced if c not in stats)
    return {"format": "shio-control-report/1", "controls": rows, "never_fired": never, "never_ran": never_ran,
            "note": "A control that never fires is either unneeded here or never tested by real traffic; a high "
                    "override rate means people disagree with it. Both need a person to look."}


def reviewer_metrics(records):
    entries, recs = _records(records)
    by_reviewer, by_item = defaultdict(list), defaultdict(list)
    for e in entries:
        if e.get("kind") != "signoff":
            continue
        rec = recs.get(e["file"], {})
        asked = rec.get("ended") or rec.get("started")
        minutes = (e.get("time", 0) - asked) / 60 if asked and e.get("time") else None
        by_reviewer[e.get("signer")].append({"decision": e.get("decision", "approved"), "minutes": minutes})
        by_item[e["file"]].append(e.get("decision", "approved"))
    rows = []
    for who, xs in sorted(by_reviewer.items()):
        mins = [x["minutes"] for x in xs if x["minutes"] is not None]
        rows.append({"reviewer": who, "decided": len(xs), "median_minutes": round(statistics.median(mins), 1)
                     if mins else None, "approval_rate": round(sum(x["decision"] == "approved" for x in xs) / len(xs), 4),
                     "fast_approvals": sum(1 for x in xs if x["decision"] == "approved" and x["minutes"] is not None
                                           and x["minutes"] < 0.1)})
    multi = [d for d in by_item.values() if len(d) >= 2]
    agree = sum(len(set(d)) == 1 for d in multi)
    return {"reviewers": rows, "items_with_two_or_more": len(multi),
            "agreement": round(agree / len(multi), 4) if multi else None,
            "note": "fast_approvals counts approvals within six seconds of the request: possible rubber-stamping "
                    "(ASI-09)"}


# ---------------- OVR-1 ----------------
SEVERITY = {"deny": 3, "hold": 2, "redact": 1, "route": 1, "allow": 0}
CLASS_WEIGHT = {"psychotherapy": 3, "part2": 3, "genetic": 2, "minors": 2, "reproductive": 2, "phi": 1}


@dataclasses.dataclass
class Item:
    id: str
    tool: str
    signature: str                  # what makes two calls "the same kind": tool plus argument names, say
    created: float
    outcome: str = "hold"
    classes: tuple = ()
    amount: float = 0.0
    score: float = 0.0
    state: str = "waiting"          # waiting | assigned | denied-overflow


class ReviewQueue:
    def __init__(self, cap_per_hour=30, capacity=200, overflow="queue", history=()):
        if overflow not in ("queue", "deny"):
            raise ValueError("overflow must be queue or deny")
        self.cap, self.capacity, self.overflow = cap_per_hour, capacity, overflow
        self.seen = Counter(history)
        self._heap, self._items, self._served = [], {}, defaultdict(list)
        self._tie = itertools.count()
        self.denied = []

    def risk(self, it):
        novelty = 1.0 / (1.0 + self.seen[it.signature])
        return round(SEVERITY.get(it.outcome, 1) * 2 + sum(CLASS_WEIGHT.get(c, 0) for c in it.classes)
                     + math.log10(1 + max(it.amount, 0)) + 4 * novelty, 4)

    def add(self, it):
        it.score = self.risk(it)
        self.seen[it.signature] += 1
        self._items[it.id] = it
        heapq.heappush(self._heap, (-it.score, next(self._tie), it.id))
        if len(self._waiting()) > self.capacity and self.overflow == "deny":
            low = min(self._waiting(), key=lambda x: (x.score, -x.created))
            low.state = "denied-overflow"
            self.denied.append(low.id)
        return it.score

    def _waiting(self):
        return [i for i in self._items.values() if i.state == "waiting"]

    def next_for(self, reviewer, now=None):
        """The riskiest waiting item for this reviewer, or None if they reached their hourly cap."""
        now = now or time.time()
        recent = [t for t in self._served[reviewer] if now - t < 3600]
        self._served[reviewer] = recent
        if len(recent) >= self.cap:
            return None
        while self._heap:
            _, _, iid = heapq.heappop(self._heap)
            it = self._items[iid]
            if it.state == "waiting":
                it.state = "assigned"
                self._served[reviewer].append(now)
                return it
        return None

    def stats(self):
        st = Counter(i.state for i in self._items.values())
        return {"waiting": st["waiting"], "assigned": st["assigned"], "denied_overflow": st["denied-overflow"],
                "overflow_rule": self.overflow, "cap_per_hour": self.cap}
