"""med.phi: Safe Harbor identifier removal, the approved-for-PHI model list, minimum-necessary fields, and the
expert-determination flag.

Deterministic code only: every detector here is a pattern, so the same text always gives the same verdict. Names in
free text can't be found reliably by patterns; known names (the patient's, from structured fields) are passed in, and
the probabilistic detector (the PHI reader adapter, D13) enters as a reader whose findings these checks then judge.

Verdicts never repeat an identifier's value: a failure says which kinds of identifier were found and how many, so a
check's explanation can't carry PHI into a record.
"""
import datetime as dt
import json
import re
from pathlib import Path

from shio.governance.verdict import Verdict

HERE = Path(__file__).resolve().parent
MONTHS = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?"
STREET = r"(?:street|st|avenue|ave|road|rd|lane|ln|drive|dr|boulevard|blvd|court|ct|way|place|pl|terrace|close)"

# (kind, pattern, replacement, anchored). Order matters: the more specific kinds run first, so an MRN isn't half-eaten
# as a phone number. An anchored pattern's group 1 is a label ("MRN: "), which is kept; only the value is replaced.
PATTERNS = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b"), "[EMAIL]", False),
    ("URL", re.compile(r"\b(?:https?://|www\.)\S+", re.I), "[URL]", False),
    ("IP", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "[IP]", False),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]", False),
    ("MRN", re.compile(r"(?i)\b((?:mrn|medical record(?: number| no\.?)?|hospital (?:number|no\.?)|nhs (?:number|no\.?))(?![a-z0-9])"
                       r"\s*[^\w\s]?\s*)[A-Z0-9](?:[A-Z0-9-]|\s(?=\d)){3,}[A-Z0-9]\b"), "[MRN]", True),
    ("HEALTH_PLAN", re.compile(r"(?i)\b((?:member|beneficiary|policy|insurance|plan)\s*(?:id|no\.?|number)(?![a-z0-9])\s*[:#]?\s*)"
                               r"[A-Z0-9-]{5,}\b"), "[PLAN-ID]", True),
    ("ACCOUNT", re.compile(r"(?i)\b((?:account|acct)(?![a-z])\s*(?:no\.?|number|#)?\s*[:#]?\s*)\d{4,}\b"), "[ACCOUNT]", True),
    ("LICENCE", re.compile(r"(?i)\b((?:licen[cs]e|certificate|dea|registration)\s*(?:no\.?|number|#)(?![a-z0-9])\s*[:#]?\s*)"
                           r"[A-Z0-9-]{5,}\b"), "[LICENCE]", True),
    ("DEVICE", re.compile(r"(?i)\b((?:serial(?: number| no\.?)?|device id|udi)(?![a-z0-9])\s*[:#]?\s*)[A-Z0-9-]{5,}\b"),
     "[DEVICE]", True),
    ("VEHICLE", re.compile(r"\b(?=[A-HJ-NPR-Z0-9]*\d)(?=[A-HJ-NPR-Z0-9]*[A-Z])[A-HJ-NPR-Z0-9]{17}\b"), "[VIN]", False),
    ("PHONE", re.compile(r"(?<![\w.-])(?:(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}|"
                         r"0\d{2,4}[ .-]\d{3}[ .-]?\d{3,4})(?![\w-]|\.\d)"), "[PHONE]", False),
    ("DATE", re.compile(r"(?i)\b(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|(?:19|20)\d{2}-\d{1,2}-\d{1,2}|"
                        rf"{MONTHS}\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}|\d{{1,2}}(?:st|nd|rd|th)?\s+{MONTHS},?\s+"
                        r"\d{4})\b"), "[DATE]", False),
    ("ADDRESS", re.compile(rf"\b\d{{1,5}}\s+(?:[A-Z][a-z]+\s+){{1,3}}(?i:{STREET})\b\.?"), "[ADDRESS]", False),
    ("AGE_OVER_89", re.compile(r"(?i)\b(?:9\d|1[0-2]\d)(?:[- ]?(?:years?|yrs?|y/?o)(?:[- ]old)?|-year-old)\b"),
     "90 or older", False),
    ("NAME", re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Mx)\.?\s+[A-Z][a-z]+(?:[- ][A-Z][a-z]+)?"), "[NAME]", False),
]
ZIP = re.compile(r"\b(\d{3})(\d{2})(?:-\d{4})?\b")
ZIP_CONTEXT = re.compile(r"(?i)\b(?:zip|postal|post code|postcode|[A-Z]{2})\s*[:,]?\s*$")
# three-digit ZIP prefixes whose areas hold 20,000 people or fewer (Safe Harbor: these become 000)
RESTRICTED_ZIP3 = {"036", "059", "063", "102", "203", "556", "692", "790", "821", "823", "830", "831", "878", "879",
                   "884", "890", "893"}


def _zips(text):
    """Five-digit ZIP codes that follow a state or a ZIP label: (start, end, replacement) spans."""
    out = []
    for m in ZIP.finditer(text):
        if ZIP_CONTEXT.search(text[max(0, m.start() - 12):m.start()]):
            prefix = m.group(1)
            out.append((m.start(), m.end(), "000" if prefix in RESTRICTED_ZIP3 else prefix + "XX"))
    return out


def find(text, known=()):
    """-> [(kind, start, end)] of every identifier in text, no overlaps, in order. known: names (or other values)
    that identify this person, from structured data, matched case-insensitively as whole words."""
    text = text or ""
    spans = []
    for name in sorted({k.strip() for k in known if k and len(k.strip()) >= 2}, key=len, reverse=True):
        for m in re.finditer(rf"(?i)(?<!\w){re.escape(name)}(?!\w)", text):
            spans.append(("KNOWN", m.start(), m.end()))
    for kind, pat, _, anchored in PATTERNS:
        for m in pat.finditer(text):
            spans.append((kind, m.end(1) if anchored else m.start(), m.end()))
    spans += [("ZIP", s, e) for s, e, _ in _zips(text)]
    # interval scheduling: sorted by start (longest first on ties), keep each span that starts after the last kept
    spans.sort(key=lambda x: (x[1], -(x[2] - x[1])))
    kept, end = [], -1
    for kind, s, e in spans:
        if s >= end:
            kept.append((kind, s, e))
            end = e
    return kept


def deidentify(text, known=()):
    """-> (text with every identifier replaced, [(kind, count)]). Label-anchored identifiers keep their label
    ("MRN: [MRN]"); ages over 89 become "90 or older"; ZIPs keep three digits, or 000 for small areas."""
    text = text or ""
    repl = {k: r for k, _, r, _ in PATTERNS}
    zips = {(s, e): r for s, e, r in _zips(text)}
    out, pos, counts = [], 0, {}
    for kind, s, e in find(text, known):
        out.append(text[pos:s])
        out.append("[NAME]" if kind == "KNOWN" else zips.get((s, e), "000") if kind == "ZIP" else repl[kind])
        counts[kind] = counts.get(kind, 0) + 1
        pos = e
    out.append(text[pos:])
    return "".join(out), sorted(counts.items())


def _summary(found):
    counts = {}
    for kind, _, _ in found:
        counts[kind] = counts.get(kind, 0) + 1
    return ", ".join(f"{n} {k.lower().replace('_', ' ')}" for k, n in sorted(counts.items()))


# ---------------- runtime checks ----------------
def no_identifiers(text, known=()):
    """PHI-1: the text holds none of the Safe Harbor identifiers this pack detects (and none of the known names)."""
    if isinstance(text, (dict, list)):
        text = json.dumps(text, ensure_ascii=False)
    found = find(str(text or ""), known)
    if found:
        return Verdict.fail(f"identifiers remain: {_summary(found)}", [k for k, _, _ in found])
    return Verdict.ok("no identifiers found")


def _load(name):
    return json.loads((HERE / name).read_text())


def approved_model(identity, approved=None):
    """PHI-2: the model is on the approved-for-PHI list, matched by kind, model and (when the list pins one) digest.
    A model whose name matches but whose weights differ is not approved."""
    entries = approved if approved is not None else _load("approved-models.json")["models"]
    ident = identity if isinstance(identity, dict) else (identity.identity() if hasattr(identity, "identity") else {})
    for e in entries:
        if e.get("kind") != ident.get("kind") or e.get("model") != (ident.get("model") or ident.get("name")):
            continue
        want = e.get("digest") or e.get("pinned")
        got = ident.get("digest") or ident.get("pinned")
        if want and want != got:
            return Verdict.fail(f"{e['model']} is approved only at {str(want)[:16]}, not {str(got)[:16]}")
        return Verdict.ok(f"{e['model']} approved for PHI ({e.get('basis', 'no basis recorded')})")
    return Verdict.fail(f"model {ident.get('model') or ident.get('name') or ident.get('kind')} is not approved for PHI")


def _field_names(data, prefix=""):
    if isinstance(data, dict):
        for k, v in data.items():
            name = f"{prefix}{str(k).strip().lower()}"
            yield name
            if isinstance(v, dict):
                yield from _field_names(v, name + ".")
    elif isinstance(data, (list, tuple, set)):
        for k in data:
            yield f"{prefix}{str(k).strip().lower()}"


def minimum_necessary(data, purpose, table=None):
    """PHI-3: only the fields the purpose needs are sent (data: a dict of fields, or a list of field names). Nested
    fields count by their full path, so a name tucked inside an allowed object is still caught."""
    purposes = table if table is not None else _load("minimum-necessary.json")["purposes"]
    if purpose not in purposes:
        return Verdict.fail(f"purpose {purpose!r} has no minimum-necessary field list")
    allowed = {f.lower() for f in purposes[purpose]}
    wild = {a[:-2] for a in allowed if a.endswith(".*")}       # "medications.*": anything inside medications
    extra = [n for n in dict.fromkeys(_field_names(data))
             if n not in allowed and not any(n.startswith(w + ".") for w in wild)]
    if extra:
        return Verdict.fail(f"fields beyond the minimum necessary for {purpose}: {', '.join(extra)}")
    return Verdict.ok(f"only the fields {purpose} needs")


def expert_determination(determination, today=None):
    """PHI-4: data released under the expert-determination method has a determination on file: who, when, the
    method, and an expiry date not yet passed. None means Safe Harbor is used instead, which PHI-1 checks."""
    if determination is None:
        return Verdict.fail("no expert determination on file: use Safe Harbor (PHI-1) instead")
    missing = [k for k in ("expert", "date", "method", "expires") if not determination.get(k)]
    if missing:
        return Verdict.fail(f"the expert determination lacks {', '.join(missing)}")
    today = today or dt.date.today()
    try:
        expires = dt.date.fromisoformat(determination["expires"])
    except ValueError:
        return Verdict.fail("the expert determination's expiry is not a date")
    if expires < (dt.date.fromisoformat(today) if isinstance(today, str) else today):
        return Verdict.fail(f"the expert determination expired on {expires}")
    return Verdict.ok(f"expert determination by {determination['expert']} valid until {expires}")


# ---------------- helpers (not checks) ----------------
class PhiGate:
    """Wraps a model so PHI reaches it only if it is approved: an unapproved model is refused before it is sent
    anything, the read comes back null, and its checks fail (fail safe). Its identity is the wrapped model's."""

    def __init__(self, model, approved=None):
        self.model, self.approved = model, approved
        self.name = getattr(model, "name", type(model).__name__)

    def identity(self):
        return self.model.identity() if hasattr(self.model, "identity") else {"kind": type(self.model).__name__}

    def propose(self, req):
        v = approved_model(self.identity(), self.approved)
        if not v:
            raise PermissionError(f"refused before sending PHI: {v.detail}")
        return self.model.propose(req)
