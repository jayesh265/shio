"""med.grounding: every claim has a quote in the source, every figure appears in the source, and required items are
not omitted.

The source is indexed once (normalised text, and its figures as (value, unit) pairs in a multiset), so checking a
summary is linear in its length. Quotes that sit inside instruction-like text in the source (a referral letter with
a hidden "ignore previous instructions...") do not count as grounding: the model may have obeyed them.
"""
import re
import unicodedata
from collections import Counter
from decimal import Decimal, InvalidOperation

from shio.governance.verdict import Verdict

MIN_QUOTE = 8
INSTRUCTION = re.compile(r"(?i)\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(instruction|rule|prompt|above|previous)s?\b|"
                         r"\b(system|assistant)\s*:|\byou are (an? )?(ai|assistant|language model)\b|"
                         r"\b(state|say|write|report) (that )?the patient (has|is|does)\b")
UNITS = {"mg": "mg", "milligram": "mg", "milligrams": "mg", "mcg": "mcg", "µg": "mcg", "ug": "mcg", "g": "g",
         "gram": "g", "grams": "g", "kg": "kg", "ml": "ml", "l": "l", "mmol/l": "mmol/l", "mmol/mol": "mmol/mol",
         "mg/dl": "mg/dl", "%": "%", "percent": "%", "bpm": "bpm", "mmhg": "mmhg", "cm": "cm", "mm": "mm",
         "units": "units", "unit": "units", "iu": "units", "year": "years", "years": "years", "yr": "years",
         "yrs": "years", "day": "days", "days": "days", "week": "weeks", "weeks": "weeks", "month": "months",
         "months": "months", "ml/min": "ml/min", "ml/min/1.73m2": "ml/min", "kg/m2": "kg/m2", "x": "x"}
FIGURE = re.compile(r"(?<![\w.])(\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?)\s*(" + "|".join(
    sorted(map(re.escape, UNITS), key=len, reverse=True)) + r")?(?![\w])", re.I)
NEGATIVE = {
    "allergies": re.compile(r"(?i)\b(no known (drug )?allerg\w*|nkda|nka|no allerg\w*|allergies:\s*(none|nil))\b"),
    "medications": re.compile(r"(?i)\b(no (regular |current )?medications?|medications?:\s*(none|nil)|not on any)\b"),
}
EMPTY = {"", "none", "nil", "n/a", "not documented", "none documented", "none known", "no known allergies", "nkda"}


def normalise(text):
    text = unicodedata.normalize("NFKC", str(text or "")).lower()
    text = text.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    text = re.sub(r"[‐-―]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def _number(text):
    try:
        return Decimal(text.replace(",", "")).normalize()
    except InvalidOperation:
        return None


def figures(text):
    """[(value, unit or None, as written)] for every figure in text. 1,000 and 1000 are the same value; 5.0 and 5 too."""
    out = []
    for m in FIGURE.finditer(str(text or "")):
        n = _number(m.group(1))
        if n is not None:
            out.append((n, UNITS.get((m.group(2) or "").lower()), m.group(0).strip()))
    return out


class SourceIndex:
    """A source prepared once for many lookups: its normalised text, its instruction-like spans, its figures."""

    def __init__(self, source):
        # lines are normalised one by one and joined with spaces, so a quote may run across a line break; sentence
        # boundaries are taken per line, so an instruction on one line never taints the next
        lines, self.sentences, pos = [], [], 0
        for raw in str(source or "").splitlines():
            line = normalise(raw)
            if not line:
                continue
            for m in re.finditer(r"[^.!?]+[.!?]?", line):
                self.sentences.append((pos + m.start(), pos + m.end()))
            lines.append(line)
            pos += len(line) + 1
        self.text = " ".join(lines)
        self.instructions = [(m.start(), m.end()) for m in INSTRUCTION.finditer(self.text)]
        self.figures = Counter((v, u) for v, u, _ in figures(source))
        self.values = Counter(v for v, _, _ in figures(source))

    def _in_instruction(self, start, end):
        for s, e in self.sentences:               # the sentence around an instruction is tainted, not just the match
            if s <= start < e or s < end <= e:
                if any(s <= a < e for a, _ in self.instructions):
                    return True
        return False

    def find_quote(self, quote):
        """-> 'ok', 'missing' or 'tainted' (found only inside instruction-like text)."""
        q = normalise(quote)
        if len(q) < MIN_QUOTE:
            return "missing"
        start, tainted = self.text.find(q), False
        while start != -1:
            if not self._in_instruction(start, start + len(q)):
                return "ok"
            tainted = True
            start = self.text.find(q, start + 1)
        return "tainted" if tainted else "missing"

    def has_figure(self, value, unit):
        return (self.figures[(value, unit)] > 0) if unit else self.values[value] > 0


def _index(source):
    return source if isinstance(source, SourceIndex) else SourceIndex(source)


def _claims(claims):
    for i, c in enumerate(claims or []):
        if isinstance(c, dict):
            yield i, c.get("text") or c.get("claim") or "", c.get("quote") or ""
        else:
            yield i, getattr(c, "text", "") or getattr(c, "claim", ""), getattr(c, "quote", "") or ""


# ---------------- runtime checks ----------------
def claims_quoted(claims, source):
    """GRD-1: every claim carries a quote found word for word (after normalising case, spacing and punctuation
    marks) in the source, outside any instruction-like text."""
    idx = _index(source)
    claims = list(_claims(claims))
    if not claims:
        return Verdict.fail("no claims: nothing in the output is tied to the source")
    bad = []
    for i, text, quote in claims:
        state = idx.find_quote(quote)
        if state != "ok":
            bad.append(f"claim {i + 1} ({'quote only inside an instruction in the source' if state == 'tainted' else 'no matching quote'})")
    if bad:
        return Verdict.fail(f"{len(bad)} of {len(claims)} claims ungrounded: {'; '.join(bad)}", bad)
    return Verdict.ok(f"all {len(claims)} claims quoted from the source")


def figures_in_source(text, source):
    """GRD-2: every figure in the output (a number, with its unit when it has one) appears in the source."""
    idx = _index(source)
    if isinstance(text, (list, tuple)):
        text = " ".join(map(str, text))
    elif isinstance(text, dict):
        text = " ".join(str(v) for v in text.values())
    missing = [w for v, u, w in figures(text) if not idx.has_figure(v, u)]
    if missing:
        return Verdict.fail(f"figures not in the source: {', '.join(dict.fromkeys(missing))}", missing)
    return Verdict.ok("every figure appears in the source")


def required_items(summary, source, required=("reason", "medications", "allergies")):
    """GRD-3: the required items are present. An item given as none or not documented passes only if the source
    says so too ("no known allergies"); otherwise it was omitted."""
    idx = _index(source)
    data = summary if isinstance(summary, dict) else getattr(summary, "__dict__", {}) or {}
    if hasattr(summary, "model_dump"):
        data = summary.model_dump()
    omitted = []
    for item in required:
        v = data.get(item)
        empty = v is None or (isinstance(v, (list, tuple, dict)) and not v) or \
            (isinstance(v, str) and normalise(v) in EMPTY)
        if not empty:
            continue
        neg = NEGATIVE.get(item)
        if neg is None or not neg.search(idx.text):
            omitted.append(item)
    if omitted:
        return Verdict.fail(f"required items omitted: {', '.join(omitted)}", omitted)
    return Verdict.ok("every required item is present or documented as none in the source")
