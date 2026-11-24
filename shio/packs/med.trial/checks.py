"""med.trial: eligibility from model-read facts, protocol deviations, adverse-event reporting clocks, blinding and the
consent version.

Eligibility criteria are a composite tree (All / Any / Not over Criterion leaves), built from the protocol file and
evaluated in code over the facts a model read. A fact the model could not read is unknown, and an unknown fact makes
a criterion unknown, which is never "eligible": the screener sends the chart to a person (fail safe, three-valued
logic: True, False, None).

Blinding: the arm a participant is allocated to must never reach a model. blinded() checks every text a read is
about to see for the arm labels and allocation codes, before the read runs.
"""
import abc
import datetime as dt
import json
import operator
import re
from pathlib import Path

from shio.governance.verdict import Verdict

HERE = Path(__file__).resolve().parent
OPS = {">=": operator.ge, "<=": operator.le, ">": operator.gt, "<": operator.lt, "==": operator.eq, "!=": operator.ne,
       "in": lambda a, b: a in b, "not in": lambda a, b: a not in b}


# ---------------- eligibility: a composite of criteria ----------------
class Node(abc.ABC):
    @abc.abstractmethod
    def evaluate(self, facts):
        """-> (True | False | None, [reasons]) ; None means a fact needed was unknown."""


class Criterion(Node):
    def __init__(self, cid, fact, op, value, text=""):
        if op not in OPS:
            raise ValueError(f"criterion {cid}: unknown operator {op!r}")
        self.id, self.fact, self.op, self.value, self.text = cid, fact, op, value, text

    def evaluate(self, facts):
        v = facts.get(self.fact)
        if v is None:
            return None, [f"{self.id}: {self.fact} unknown"]
        try:
            ok = OPS[self.op](v, self.value)
        except TypeError:
            return None, [f"{self.id}: {self.fact}={v!r} can't be compared with {self.value!r}"]
        return ok, [] if ok else [f"{self.id}: {self.text or f'{self.fact} {self.op} {self.value}'} (is {v!r})"]


class All(Node):
    def __init__(self, children):
        self.children = children

    def evaluate(self, facts):
        results = [c.evaluate(facts) for c in self.children]
        reasons = [r for _, rs in results for r in rs]
        if any(ok is False for ok, _ in results):
            return False, reasons
        return (None if any(ok is None for ok, _ in results) else True), reasons


class Any(Node):
    def __init__(self, children):
        self.children = children

    def evaluate(self, facts):
        results = [c.evaluate(facts) for c in self.children]
        if any(ok is True for ok, _ in results):
            return True, []
        reasons = [r for _, rs in results for r in rs]
        return (None if any(ok is None for ok, _ in results) else False), reasons


class Not(Node):
    def __init__(self, child, cid=""):
        self.child, self.id = child, cid

    def evaluate(self, facts):
        ok, reasons = self.child.evaluate(facts)
        if ok is None:
            return None, reasons
        return (not ok), ([] if ok is False else [f"{self.id or 'exclusion'} met: "
                                                  f"{getattr(self.child, 'text', '') or 'an exclusion criterion'}"])


def build(spec):
    """A protocol's criterion spec (JSON) -> a Node."""
    if "all" in spec:
        return All([build(s) for s in spec["all"]])
    if "any" in spec:
        return Any([build(s) for s in spec["any"]])
    if "not" in spec:
        return Not(build(spec["not"]), spec.get("id", ""))
    return Criterion(spec["id"], spec["fact"], spec["op"], spec["value"], spec.get("text", ""))


def protocol(path=None):
    return json.loads(Path(path or HERE / "fixture-protocol.json").read_text())


def tree(proto):
    """Inclusion criteria all hold, and no exclusion criterion holds."""
    return All([build(c) for c in proto["inclusion"]] + [Not(build(c), c.get("id", "")) for c in proto["exclusion"]])


# ---------------- runtime checks ----------------
def eligible(facts, proto=None):
    """TRL-1: the participant meets every inclusion criterion and no exclusion criterion, judged in code over the
    facts read from the chart. Unknown facts make the answer unknown, which fails (a person reviews)."""
    proto = proto or protocol()
    facts = facts if isinstance(facts, dict) else (facts.model_dump() if hasattr(facts, "model_dump") else {})
    ok, reasons = tree(proto).evaluate(facts)
    if ok is None:
        return Verdict.fail("eligibility unknown: " + "; ".join(r for r in reasons if "unknown" in r or "compared" in r),
                            reasons)
    if not ok:
        return Verdict.fail("not eligible: " + "; ".join(reasons), reasons)
    return Verdict.ok(f"eligible for {proto['id']}")


def blinded(texts, allocation):
    """TRL-2: no text a read will see contains the participant's arm or any allocation label or code. allocation:
    {"arm": "...", "labels": [...all arm names...], "codes": [...]}. Case and spacing don't hide a label."""
    needles = {str(x).lower() for x in [allocation.get("arm"), *allocation.get("labels", []), *allocation.get("codes", [])]
               if x}
    hits = []
    for i, t in enumerate(texts if isinstance(texts, (list, tuple)) else [texts]):
        flat = re.sub(r"[\s_-]+", " ", str(t or "").lower())
        squeezed = re.sub(r"[\s_-]+", "", str(t or "").lower())
        for n in needles:
            spaced = re.escape(re.sub(r"[\s_-]+", " ", n))
            if re.search(rf"(?<![a-z0-9]){spaced}(?![a-z0-9])", flat) or \
                    (len(n) >= 6 and re.sub(r"[\s_-]+", "", n) in squeezed):
                hits.append(i)
                break
    if hits:
        return Verdict.fail(f"allocation information in {len(hits)} text(s) a model would see: unblinding", hits)
    return Verdict.ok("no allocation information in what the model sees")


def no_deviations(visits, schedule):
    """TRL-3: every scheduled visit happened inside its window (days from baseline, plus or minus the window).
    visits: {"V1": "2026-03-01", ...} with "baseline"; schedule: {"V1": {"day": 14, "window": 3}, ...}."""
    try:
        base = dt.date.fromisoformat(visits["baseline"])
    except (KeyError, ValueError):
        return Verdict.fail("no baseline date, so visit windows can't be checked")
    out = []
    for name, rule in schedule.items():
        when = visits.get(name)
        if when is None:
            out.append(f"{name} missing")
            continue
        day = (dt.date.fromisoformat(when) - base).days
        if abs(day - rule["day"]) > rule["window"]:
            out.append(f"{name} on day {day}, window day {rule['day']} +/- {rule['window']}")
    if out:
        return Verdict.fail("protocol deviations: " + "; ".join(out), out)
    return Verdict.ok("every visit inside its window")


# reporting clocks, from when the sponsor became aware (ICH E2A: expedited reporting of SUSARs)
CLOCKS = {"sae_initial": dt.timedelta(hours=24), "susar_fatal": dt.timedelta(days=7),
          "susar_other": dt.timedelta(days=15)}


def ae_deadline(event):
    """-> (clock name, deadline) for an adverse event: {"serious", "unexpected", "related", "fatal_or_life_threatening",
    "aware": ISO datetime}."""
    aware = dt.datetime.fromisoformat(event["aware"])
    if event.get("serious") and event.get("unexpected") and event.get("related"):
        clock = "susar_fatal" if event.get("fatal_or_life_threatening") else "susar_other"
    elif event.get("serious"):
        clock = "sae_initial"
    else:
        return None, None
    return clock, aware + CLOCKS[clock]


def ae_reported_in_time(event, now=None):
    """TRL-4: a serious adverse event was (or can still be) reported before its clock runs out."""
    try:
        clock, deadline = ae_deadline(event)
    except (KeyError, ValueError):
        return Verdict.fail("the event has no awareness time, so its reporting clock can't be computed")
    if clock is None:
        return Verdict.ok("not serious: no expedited reporting clock")
    reported = event.get("reported")
    at = dt.datetime.fromisoformat(reported) if reported else (
        dt.datetime.fromisoformat(now) if isinstance(now, str) else now or dt.datetime.now())
    if at > deadline:
        return Verdict.fail(f"{clock.replace('_', ' ')} report {'made' if reported else 'still not made'} after its "
                            f"deadline {deadline.isoformat(timespec='minutes')}")
    return Verdict.ok(f"{clock.replace('_', ' ')} due by {deadline.isoformat(timespec='minutes')}"
                      + (": reported in time" if reported else ""))


def consent_current(version, proto=None):
    """TRL-5: the participant signed the consent version the protocol currently requires."""
    proto = proto or protocol()
    want = proto["consent_version"]
    if version is None:
        return Verdict.fail("no consent version on the chart")
    if str(version).strip().lower().lstrip("v") != str(want).strip().lower().lstrip("v"):
        return Verdict.fail(f"consent version {version} on file, protocol requires {want}: re-consent first")
    return Verdict.ok(f"consent version {want}")
