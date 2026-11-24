"""med.monitor: subgroup and per-site metrics, and safety events as records.

Monitoring by subgroup needs each decision to say which subgroup and site it was for, in clear (a vault can be
erased; metrics must survive). Only coarse groups go there, and only values on the allowed list (slices.json): a
check vets them first, so free text or an identifier can't ride along. slices_recorded is listed in RECORDS_SLICES,
which tells the pack runtime to record the vetted groups on the decision when the check passes.
"""
import datetime as dt
import json
from collections import Counter, defaultdict
from pathlib import Path

from shio.governance.verdict import Verdict

HERE = Path(__file__).resolve().parent
RECORDS_SLICES = {"slices_recorded"}
HARM = ("none", "low", "moderate", "severe", "death")
EVENT_FIELDS = ("what", "when", "harm", "reported_by")


def allowed_slices():
    return json.loads((HERE / "slices.json").read_text())["groups"]


# ---------------- runtime checks ----------------
def slices_recorded(slices, allowed=None):
    """MON-1: the decision names its monitoring groups (site and subgroup), each from the allowed list."""
    allowed = allowed if allowed is not None else allowed_slices()
    if not isinstance(slices, dict) or not slices:
        return Verdict.fail("no monitoring groups given")
    bad = [f"{k}={v!r}" for k, v in slices.items() if k not in allowed or str(v) not in allowed[k]]
    missing = [k for k, spec in allowed.items() if spec and k not in slices and k in ("site",)]
    if bad:
        return Verdict.fail(f"groups not on the allowed list: {', '.join(bad)}")
    if missing:
        return Verdict.fail(f"required groups missing: {', '.join(missing)}")
    return Verdict.ok("monitoring groups recorded", tuple(sorted((k, str(v)) for k, v in slices.items())))


def safety_event_complete(event):
    """MON-2: a safety event says what happened, when, the harm, who reported it, and the decisions it concerns."""
    if not isinstance(event, dict):
        return Verdict.fail("a safety event is a set of fields")
    missing = [k for k in EVENT_FIELDS if not event.get(k)]
    if missing:
        return Verdict.fail(f"the safety event lacks {', '.join(missing)}")
    if event["harm"] not in HARM:
        return Verdict.fail(f"harm must be one of {', '.join(HARM)}")
    try:
        when = dt.datetime.fromisoformat(event["when"])
    except (TypeError, ValueError):
        return Verdict.fail("when must be a date and time")
    if when > dt.datetime.now() + dt.timedelta(minutes=5):
        return Verdict.fail("when is in the future")
    if not isinstance(event.get("records", []), list):
        return Verdict.fail("records must be a list of decision record files")
    return Verdict.ok("safety event complete")


# ---------------- helpers (not checks) ----------------
def subgroup_metrics(folder, groups=("site", "age_band", "sex"), min_n=5, gap=0.10):
    """{group: {value: {decisions, check_failure_rate, override_rate, outcomes}}} over the folder's decisions, and
    disparity flags where the check-failure rate differs by more than `gap` between values with at least min_n."""
    from shio.ledger import _entries, labels
    folder = Path(folder)
    entries = _entries(folder)
    rejected = {e["file"] for e in entries if e.get("kind") == "signoff" and e.get("decision") == "rejected"}
    wrong = {f for f, ls in labels(folder).items() if ls[-1]["verdict"] == "wrong"}
    acc = defaultdict(lambda: defaultdict(lambda: {"decisions": 0, "checks": 0, "failed": 0, "overridden": 0,
                                                   "outcomes": Counter()}))
    for e in entries:
        if e.get("kind") != "record" or not (folder / e["file"]).exists():
            continue
        rec = json.loads((folder / e["file"]).read_text())
        if rec.get("record_type", "decision") != "decision":
            continue
        out = rec.get("outcome")
        out = out.get("decided", out) if isinstance(out, dict) and out.get("status") == "PENDING" else out
        label = out.get("status") if isinstance(out, dict) else str(out)
        checks = [c for c in rec.get("checks", []) if not c.get("skipped") and c.get("reward", True)]
        for g in groups:
            v = (rec.get("slices") or {}).get(g)
            if v is None:
                continue
            a = acc[g][v]
            a["decisions"] += 1
            a["checks"] += len(checks)
            a["failed"] += sum(1 for c in checks if not c["passed"])
            a["overridden"] += e["file"] in rejected or e["file"] in wrong
            a["outcomes"][label] += 1
    result, flags = {}, []
    for g, values in acc.items():
        result[g] = {v: {"decisions": a["decisions"],
                         "check_failure_rate": round(a["failed"] / a["checks"], 4) if a["checks"] else None,
                         "override_rate": round(a["overridden"] / a["decisions"], 4),
                         "outcomes": dict(a["outcomes"])} for v, a in sorted(values.items())}
        rates = {v: m["check_failure_rate"] for v, m in result[g].items()
                 if m["decisions"] >= min_n and m["check_failure_rate"] is not None}
        if len(rates) >= 2 and max(rates.values()) - min(rates.values()) > gap:
            hi, lo = max(rates, key=rates.get), min(rates, key=rates.get)
            flags.append(f"{g}: check failures {rates[hi]:.0%} for {hi} vs {rates[lo]:.0%} for {lo}")
    return {"groups": result, "flags": flags}


def record_safety_event(folder, event, signer=None):
    """Write a safety event as a signed record in the decision ledger. Refused if incomplete."""
    import time
    import uuid
    from shio.ledger import _entries, write
    v = safety_event_complete(event)
    if not v:
        raise ValueError(v.detail)
    known = {e["file"] for e in _entries(Path(folder)) if e.get("kind") == "record"}
    missing = [r for r in event.get("records", []) if r not in known]
    if missing:
        raise ValueError(f"not records in this ledger: {', '.join(missing)}")
    now = time.time()
    rec = {"record_type": "safety_event", "agent": "safety_event", "started": now, "ended": now,
           "event": {k: event[k] for k in sorted(event)}, "outcome": {"status": "RECORDED", "harm": event["harm"]}}
    return write(rec, folder, f"safety-event-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}", signer=signer)
