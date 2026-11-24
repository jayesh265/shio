"""Monitors (D27): failure, override and drift rates, and incident records.

Over a window of recent decisions, against a baseline window before it:

  failure rate    model calls that gave no usable answer, as a share of model calls
  check failures  checks that failed, as a share of checks run
  override rate   decisions a person overturned (a rejected sign-off, or a reviewer's "wrong" label), as a share of
                  decisions
  drift           the population stability index (PSI) of the outcome mix and of each check's pass/fail mix, window
                  against baseline: sum over categories of (a - e) * ln(a / e). Above 0.2 is the usual "significant
                  shift" line; above 0.1, worth a look.

An alert can become an incident: a record in the same signed ledger as the decisions (record_type "incident"),
with the alert, the records it is about, who opened it and how severe it is. Closing or updating it is another
record that names it, so an incident's history can't be rewritten. A monitoring report is sealed, so the governance
reviewer can approve exactly what they reviewed (an approval of subject "monitoring").
"""
import datetime as dt
import json
import math
import time
import uuid
from collections import Counter
from pathlib import Path

from ..evidence import _outcome_label
from ..ledger import _entries, labels, write
from .assess import seal

PSI_ALERT, PSI_WATCH = 0.2, 0.1
DEFAULTS = {"failure_rate": 0.05, "override_rate": 0.10, "psi": PSI_ALERT, "min_decisions": 10}
SEVERITIES = ("low", "moderate", "high", "critical")


def psi(expected, actual, eps=1e-4):
    """Population stability index between two category counts. Categories missing on one side count as eps."""
    keys = set(expected) | set(actual)
    te, ta = sum(expected.values()), sum(actual.values())
    if not te or not ta:
        return 0.0
    total = 0.0
    for k in keys:
        e = max(expected.get(k, 0) / te, eps)
        a = max(actual.get(k, 0) / ta, eps)
        total += (a - e) * math.log(a / e)
    return round(total, 4)


def _runs(run):
    yield run
    for c in run.get("children", []):
        yield from _runs(c)


def _decided(outcome):
    if isinstance(outcome, dict) and outcome.get("status") == "PENDING" and "decided" in outcome:
        return outcome["decided"]
    return outcome


def window(folder, start, end):
    """Figures for decisions started from start to end (dates, inclusive)."""
    folder = Path(folder)
    entries = _entries(folder)
    rejected = {e["file"] for e in entries if e.get("kind") == "signoff" and e.get("decision") == "rejected"}
    wrong = {f for f, ls in labels(folder).items() if ls[-1]["verdict"] == "wrong"}
    out = {"decisions": 0, "reads": 0, "failures": 0, "checks": 0, "check_failures": 0, "overridden": 0,
           "outcomes": Counter(), "by_check": {}, "files": []}
    for e in entries:
        if e.get("kind") != "record" or not (folder / e["file"]).exists():
            continue
        rec = json.loads((folder / e["file"]).read_text())
        if rec.get("record_type", "decision") != "decision":
            continue
        day = dt.date.fromtimestamp(rec.get("started") or e.get("time", 0))
        if not start <= day <= end:
            continue
        out["decisions"] += 1
        out["files"].append(e["file"])
        out["outcomes"][f"{rec.get('agent')}: {_outcome_label(_decided(rec.get('outcome')))}"] += 1
        out["overridden"] += e["file"] in rejected or e["file"] in wrong
        for run in _runs(rec):
            for r in run.get("readings", []):
                out["reads"] += 1
                out["failures"] += r.get("raw") is None
            for c in run.get("checks", []):
                if c.get("skipped") or not c.get("reward", True):
                    continue
                key = f"{run.get('agent')}.{c['name']}"
                out["checks"] += 1
                out["check_failures"] += not c["passed"]
                out["by_check"].setdefault(key, Counter())["pass" if c["passed"] else "fail"] += 1
    return out


def _rate(n, d):
    return round(n / d, 4) if d else None


def monitor(folder, today=None, window_days=14, baseline_days=56, thresholds=None):
    """-> {"window", "baseline", "metrics", "alerts"}: the window's rates and drift against the baseline before it."""
    t = {**DEFAULTS, **(thresholds or {})}
    today = today or dt.date.today()
    w_start = today - dt.timedelta(days=window_days - 1)
    b_end = w_start - dt.timedelta(days=1)
    b_start = b_end - dt.timedelta(days=baseline_days - 1)
    w, b = window(folder, w_start, today), window(folder, b_start, b_end)
    metrics = {"decisions": w["decisions"], "baseline_decisions": b["decisions"],
               "failure_rate": _rate(w["failures"], w["reads"]),
               "check_failure_rate": _rate(w["check_failures"], w["checks"]),
               "override_rate": _rate(w["overridden"], w["decisions"]),
               "baseline_check_failure_rate": _rate(b["check_failures"], b["checks"]),
               "outcome_psi": psi(b["outcomes"], w["outcomes"]),
               "check_psi": {k: psi(b["by_check"].get(k, Counter()), v) for k, v in sorted(w["by_check"].items())}}
    alerts = []
    enough = w["decisions"] >= t["min_decisions"]

    def alert(kind, message, **detail):
        alerts.append({"kind": kind, "message": message, "severity": detail.pop("severity", "moderate"), **detail})

    if enough and metrics["failure_rate"] is not None and metrics["failure_rate"] > t["failure_rate"]:
        alert("failure_rate", f"{metrics['failure_rate']:.0%} of model calls gave no usable answer "
                              f"(threshold {t['failure_rate']:.0%})", value=metrics["failure_rate"], severity="high")
    if enough and metrics["override_rate"] is not None and metrics["override_rate"] > t["override_rate"]:
        alert("override_rate", f"people overturned {metrics['override_rate']:.0%} of decisions "
                               f"(threshold {t['override_rate']:.0%})", value=metrics["override_rate"])
    if enough and b["decisions"] >= t["min_decisions"]:
        if metrics["outcome_psi"] > t["psi"]:
            alert("drift", f"the outcome mix shifted: PSI {metrics['outcome_psi']} against the baseline "
                           f"(threshold {t['psi']})", value=metrics["outcome_psi"], severity="high",
                  baseline=dict(b["outcomes"]), window=dict(w["outcomes"]))
        for k, v in metrics["check_psi"].items():
            if v > t["psi"] and k in b["by_check"]:
                alert("check_drift", f"{k}: pass/fail mix shifted, PSI {v}", check=k, value=v)
    return {"source": "shio monitors", "folder": str(folder), "window": [w_start.isoformat(), today.isoformat()],
            "baseline": [b_start.isoformat(), b_end.isoformat()], "thresholds": t, "metrics": metrics,
            "alerts": alerts, "files": w["files"]}


def report(result, signer=None):
    """A sealed monitoring report: what the governance reviewer signs off (approval subject "monitoring")."""
    return seal({"format": "shio-monitoring/1", **{k: v for k, v in result.items() if k != "files"},
                 "records": result["files"], "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")},
                signer)


def _record(folder, kind, body, signer):
    now = time.time()
    rec = {"record_type": kind, "agent": kind, "started": now, "ended": now, **body}
    stem = f"{kind}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    return write(rec, folder, stem, use_vault=False, signer=signer)


def open_incident(folder, title, severity, opened_by, alert=None, records=(), description="", signer=None):
    """Open an incident as a signed record in the ledger. -> (incident id, record path)."""
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
    if not str(title).strip() or not str(opened_by).strip():
        raise ValueError("an incident needs a title and who opened it")
    known = {e["file"] for e in _entries(Path(folder)) if e.get("kind") == "record"}
    missing = [r for r in records if r not in known]
    if missing:
        raise ValueError(f"not records in this ledger: {', '.join(missing)}")
    iid = f"INC-{uuid.uuid4().hex[:8].upper()}"
    path = _record(folder, "incident", {"incident": iid, "title": title, "severity": severity, "opened_by": opened_by,
                                        "alert": alert, "records": list(records), "description": description,
                                        "outcome": {"status": "OPEN", "incident": iid}}, signer)
    return iid, path


def update_incident(folder, incident, status, by, note="", signer=None):
    """Update or close an incident: another signed record naming it."""
    if status not in ("INVESTIGATING", "MITIGATED", "CLOSED"):
        raise ValueError("status must be INVESTIGATING, MITIGATED or CLOSED")
    if incident not in {i["incident"] for i in incidents(folder)}:
        raise ValueError(f"no incident {incident} in this ledger")
    return _record(folder, "incident_update", {"incident": incident, "by": by, "note": note,
                                               "outcome": {"status": status, "incident": incident}}, signer)


def incidents(folder):
    """[{incident, title, severity, status, opened, records, history}] from the ledger, oldest first."""
    folder = Path(folder)
    out = {}
    for e in _entries(folder):
        if e.get("kind") != "record" or not (folder / e["file"]).exists():
            continue
        rec = json.loads((folder / e["file"]).read_text())
        if rec.get("record_type") == "incident":
            out[rec["incident"]] = {"incident": rec["incident"], "title": rec["title"], "severity": rec["severity"],
                                    "status": "OPEN", "opened_by": rec["opened_by"], "records": rec["records"],
                                    "opened": dt.datetime.fromtimestamp(rec["started"]).isoformat(timespec="minutes"),
                                    "history": [e["file"]]}
        elif rec.get("record_type") == "incident_update" and rec.get("incident") in out:
            out[rec["incident"]]["status"] = rec["outcome"]["status"]
            out[rec["incident"]]["history"].append(e["file"])
    return list(out.values())
