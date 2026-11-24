"""Step 1, classify: label the payload by data class, and find the identifiers a redaction would remove.

Three sources, combined: labels the caller declares, the registry's field classes (a field named in
registries.json `field_classes` carries that class), and detectors over free text, namely the med.phi identifier
patterns plus keyword detectors for the sensitive classes (SEN-15: a note that mentions a substance use programme
inside an ordinary visit summary). Anything unlabelled is treated as PHI. A detector that raises is not skipped: the
classifier raises, and the gate fails closed.

Detector recall is never assumed to be perfect (see med.phi's measured recall). That is why the destination and
attestation checks come first and the redaction path is a second layer.
"""
import re

from .model import DataClass

SENSITIVE_TERMS = {
    DataClass.PART2: ("substance use disorder", "opioid treatment program", "methadone clinic", "methadone maintenance",
                      "buprenorphine", "alcohol use disorder", "detox programme", "detox program", "42 cfr part 2",
                      "addiction treatment"),
    DataClass.PSYCHOTHERAPY: ("psychotherapy note", "psychotherapy notes", "therapy session notes",
                              "process notes", "session transcript"),
    DataClass.REPRODUCTIVE: ("abortion", "termination of pregnancy", "contraception", "ivf", "miscarriage",
                             "reproductive health"),
    DataClass.GENETIC: ("genetic test", "brca1", "brca2", "genome sequencing", "exome", "carrier screening",
                        "genotype", "family history of huntington"),
    DataClass.MINORS: ("minor patient", "aged 15", "aged 16", "aged 14", "paediatric patient", "pediatric patient",
                       "under 18", "parental consent"),
}


def _compile(terms):
    return re.compile(r"(?i)\b(?:" + "|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True)) + r")\b")


class Detector:
    """A detector labels text. Subclasses implement detect(text) -> {DataClass} and spans(text) -> [(kind, start,
    end)] for the identifiers a tokeniser would replace."""
    name = "detector"

    def detect(self, text):
        return set()

    def spans(self, text):
        return []


_LIB = []


def _phi_lib():
    """med.phi's checks module, loaded once per process (loading a pack hashes its folder)."""
    if not _LIB:
        from ..packs import load_pack
        _LIB.append(load_pack("med.phi").lib)
    return _LIB[0]


class PhiPatternDetector(Detector):
    """med.phi's Safe Harbor identifier patterns. Dates count as identifiers (except a bare year)."""
    name = "med.phi patterns"

    def __init__(self, known_names=()):
        self.lib = _phi_lib()
        self.known = list(known_names)

    def spans(self, text):
        return [(k, s, e) for k, s, e in self.lib.find(text or "", self.known)]

    def detect(self, text):
        return {DataClass.PHI} if self.spans(text) else set()


_HOMO = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g",
         "ո": "n", "ս": "u", "ⅼ": "l"}
_WORDS = {w: str(i) for i, w in enumerate(["zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
                                          "nine"])}
_INVIS = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]")


def _join_spaced(t):
    """'C a l l   4 1 5' -> 'Call 415'. The smallest gap between characters is the letter gap; anything wider is a
    word gap. Within a word, runs of single characters are joined."""
    runs = [len(r) for r in re.findall(r" +", t)]
    if not runs:
        return t
    from collections import Counter
    small = min(Counter(runs).most_common(), key=lambda kv: (-kv[1], kv[0]))[0]     # the most common gap
    out = []
    for seg in re.split(" {%d,}" % (small + 1), t):
        merged, run = [], []
        for tok in re.split(" {%d}" % small, seg):
            if len(tok) == 1:
                run.append(tok)
                continue
            if run:
                merged.append("".join(run))
                run = []
            if tok:
                merged.append(tok)
        if run:
            merged.append("".join(run))
        out.append(" ".join(merged))
    return " ".join(out)


def _fold(t):
    import unicodedata
    t = unicodedata.normalize("NFKC", t or "")
    t = _INVIS.sub("", t)
    t = "".join(_HOMO.get(ch, ch) for ch in t)
    t = "".join(str(unicodedata.digit(ch)) if ch.isdigit() and not ch.isascii() else ch for ch in t)
    t = re.sub(r"(?i)\b(" + "|".join(_WORDS) + r")\b", lambda m: _WORDS[m.group(1).lower()], t)
    t = re.sub(r"(?i)\s+(?:at|\(at\)|\[at\])\s+", "@", t)
    return re.sub(r"(?i)\s+(?:dot|\(dot\)|\[dot\])\s+", ".", t)


def deobfuscate(text, depth=2):
    """Variants of text with the usual disguises undone, for detection only (never sent): NFKC, invisible and bidi
    characters removed, homoglyphs folded, non-ASCII and spelled-out digits as digits, " at " / " dot " as @ and .,
    letter-by-letter spacing joined, separators between digits dropped, and base64 segments decoded and undone again
    (to `depth` levels, so a disguise inside base64 is undone too)."""
    import base64
    import unicodedata
    base = _INVIS.sub("", unicodedata.normalize("NFKC", text or ""))
    t = _fold(base)
    joined = _fold(_join_spaced(base))
    variants = [t, joined, re.sub(r"(?<=\d)[\s./_-]+(?=\d)", "", joined)]
    if depth > 0:
        for tok in re.findall(r"[A-Za-z0-9+/=._-]{12,}", base):
            cands = {re.sub(r"[^A-Za-z0-9+/]", "", tok), tok.replace("-", "+").replace("_", "/").replace(".", "")}
            for c in cands:
                try:  # lenient on purpose: base64 decodes in 4-character blocks, so a damaged string still leaks
                    raw = base64.b64decode(c + "=" * (-len(c) % 4), validate=False)
                except Exception:
                    continue
                dec = "".join(ch for ch in raw.decode("utf-8", errors="ignore") if ch.isprintable())
                if len(dec) >= 4 and sum(ch.isalnum() or ch == " " for ch in dec) >= 0.6 * len(dec):
                    variants += deobfuscate(dec, depth - 1)
    return [v for i, v in enumerate(variants) if v and v not in variants[:i]]


LONG_NUMBER = re.compile(r"(?<!\d)\d{9,12}(?!\d)")


class ObfuscationDetector(Detector):
    """Identifiers that only appear once disguises are undone (PHI-01 and PHI-07 in the spec: spelled-out and
    obfuscated forms). Finding one labels the text PHI; since its position in the original can't be mapped, the gate's
    second pass holds the request instead of trying to redact it."""
    name = "de-obfuscated identifiers"

    def __init__(self, base=None):
        self.base = base or PhiPatternDetector()

    def hidden(self, text):
        raw = {k for k, _, _ in self.base.spans(text or "") if k != "DATE"}
        found = set()
        for v in deobfuscate(text):
            found |= {k for k, _, _ in self.base.spans(v) if k != "DATE"}
            if LONG_NUMBER.search(v) and not LONG_NUMBER.search(text or ""):
                found.add("NUMBER")
        return found - raw

    def detect(self, text):
        return {DataClass.PHI} if self.hidden(text) else set()


class SensitiveTermDetector(Detector):
    name = "sensitive terms"

    def __init__(self, terms=None):
        self.rx = {c: _compile(t) for c, t in (terms or SENSITIVE_TERMS).items()}

    def detect(self, text):
        return {c for c, rx in self.rx.items() if rx.search(text or "")}


class Classifier:
    def __init__(self, detectors=None, field_classes=None, public_fields=()):
        self.detectors = list(detectors) if detectors is not None else [PhiPatternDetector(), ObfuscationDetector(),
                                                                        SensitiveTermDetector()]
        self.field_classes = {k: DataClass(v) for k, v in (field_classes or {}).items()}
        self.public = frozenset(public_fields)      # fields the registry declares carry no health data

    def classify(self, request):
        """-> (classes, unlabelled field names). Raises if a detector fails (the gate turns that into Deny)."""
        classes = set(request.labels)
        unlabelled = []
        for name, value in request.fields.items():
            if name in self.field_classes:
                classes.add(self.field_classes[name])
            elif name in self.public:
                pass
            elif value not in (None, "") and not isinstance(value, (bool, int, float)):
                unlabelled.append(name)
            classes |= self._detect(str(value)) if isinstance(value, str) else set()
        if request.text:
            found = self._detect(request.text)
            classes |= found if found else {DataClass.UNLABELLED}
        if unlabelled:
            classes.add(DataClass.UNLABELLED)
        if DataClass.UNLABELLED in classes:
            classes.add(DataClass.PHI)           # anything unlabelled is treated as PHI
        return frozenset(classes), tuple(unlabelled)

    def _detect(self, text):
        out = set()
        for d in self.detectors:
            out |= d.detect(text)                # an exception propagates: fail closed
        return out

    def spans(self, text):
        found = []
        for d in self.detectors:
            found += d.spans(text)
        return _merge(found)


def _merge(spans):
    """Overlapping spans merged, longest first wins: interval union over (start, end), sorted."""
    out = []
    for k, s, e in sorted(spans, key=lambda x: (x[1], -(x[2] - x[1]))):
        if out and s < out[-1][2]:
            if e > out[-1][2]:
                out[-1] = (out[-1][0], out[-1][1], e)
            continue
        out.append((k, s, e))
    return out


class TokenVault:
    """Consistent tokens for identifiers (PHI-04): the same value always gets the same token within one request, so
    the model can reason about "the same person" without learning who. The map lives here, in the caller's memory,
    never in the prompt, the trace or the record."""

    def __init__(self):
        self._by_value, self._by_token, self._count = {}, {}, {}

    def token(self, kind, value):
        key = (kind, value)
        if key not in self._by_value:
            n = self._count[kind] = self._count.get(kind, 0) + 1
            tok = f"[[{kind}-{n}]]"
            self._by_value[key], self._by_token[tok] = tok, value
        return self._by_value[key]

    def tokenise(self, text, spans):
        out, last = [], 0
        for kind, s, e in spans:
            out += [text[last:s], self.token(kind, text[s:e])]
            last = e
        return "".join(out + [text[last:]])

    def tokens(self):
        return set(self._by_token)

    def reinsert(self, template_fields, allowed):
        """PHI-05: real values go back only into fields the template allows, never inside the model's free text."""
        out = {}
        for k, v in template_fields.items():
            if k in allowed and isinstance(v, str) and v in self._by_token:
                out[k] = self._by_token[v]
            else:
                out[k] = v
        return out

    def __repr__(self):                          # never print the map
        return f"<TokenVault {len(self._by_token)} tokens>"
