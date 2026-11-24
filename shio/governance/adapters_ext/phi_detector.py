"""PHI and entity detectors as readers (D13).

A detector can be wrong in both directions, so it enters as a reader: what it finds is a Reading, sealed until a check
looks at it, exactly like a model's answer. Checks (med.phi) then decide what its findings mean.

  PatternPhiDetector   no dependencies: med.phi's identifier patterns plus a name heuristic (title-case word runs
                       that are not clinical vocabulary). Heuristic, so a reader.
  PresidioPhiDetector  Microsoft Presidio's analyzer (MIT), installed with shio-lang[presidio].

The answer is {"entities": [{"kind", "source", "start", "end"}]}: positions, never the text itself, so the reading
holds no more PHI than it must. measure_recall() reports recall per kind on an annotated fixture set.
"""
import json
import re
from pathlib import Path

from pydantic import BaseModel

from ..adapters import Dependency, Manifest, ReaderAdapter, TrustClass
from ..packs import load_pack

FIXTURES = Path(__file__).with_name("fixtures") / "phi_recall.json"
NOT_NAMES = {
    "the", "a", "an", "and", "or", "of", "to", "for", "in", "on", "with", "re", "dear", "dr", "doctor", "patient",
    "history", "medication", "medications", "allergies", "allergy", "diagnosis", "plan", "impression", "referral",
    "letter", "clinic", "hospital", "surgery", "department", "practice", "type", "diabetes", "mellitus", "chronic",
    "kidney", "disease", "heart", "failure", "blood", "pressure", "hypertension", "stage", "no", "known", "drug",
    "past", "medical", "social", "family", "examination", "results", "summary", "reason", "current", "regular",
    "yours", "sincerely", "thank", "you", "kind", "regards", "general", "practitioner", "consultant", "nurse",
    "metformin", "insulin", "aspirin", "atorvastatin", "ramipril", "amlodipine", "penicillin", "warfarin",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "nhs", "gp", "ckd", "copd",
    "hba1c", "egfr", "bmi", "ecg", "mri", "ct", "urgent", "routine", "clinical", "lab", "labs", "renal", "function",
}


class Entity(BaseModel):
    kind: str
    source: str = ""
    start: int
    end: int


class Findings(BaseModel):
    """What a PHI detector read: where identifiers are, never what they say."""
    entities: list[Entity] = []


NAME_RUN = re.compile(r"\b[A-Z][a-z]{1,}(?:[-'][A-Z][a-z]+)?(?:\s+[A-Z][a-z]{1,}(?:[-'][A-Z][a-z]+)?){1,2}\b")


class PatternPhiDetector(ReaderAdapter):
    manifest = Manifest("pattern-phi-detector", "0.1.0", TrustClass.READER, "MIT OR Apache-2.0",
                        "med.phi's identifier patterns plus a title-case name heuristic; no dependencies")
    schema = Findings

    def __init__(self, names=True):
        self.names = names
        self._phi = load_pack("med.phi").lib

    def detect(self, text):
        found = [{"kind": k, "start": s, "end": e} for k, s, e in self._phi.find(text)]
        if self.names:
            taken = [(f["start"], f["end"]) for f in found]
            for m in NAME_RUN.finditer(text):
                words = m.group(0).split()
                if any(w.lower().strip("'-") in NOT_NAMES for w in words):
                    continue
                if any(s < m.end() and m.start() < e for s, e in taken):
                    continue
                found.append({"kind": "NAME", "start": m.start(), "end": m.end()})
        return sorted(found, key=lambda f: f["start"])

    def read_request(self, req):
        """Scans the read's sources and, for a read that sees earlier readings, their values (a summary, say)."""
        out = []
        for src in req.sources:
            for f in self.detect(src.text or ""):
                out.append({**f, "source": src.name})
        for name, value in sorted((req.context or {}).items()):
            text = value if isinstance(value, str) else " ".join(_strings(value))
            out += [{**f, "source": f"seeing:{name}"} for f in self.detect(text)]
        return json.dumps({"entities": out})


def _strings(value):
    """Every string inside a JSON value, in order (keys left out: they are field names, not data)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


class PresidioPhiDetector(ReaderAdapter):
    """Presidio's AnalyzerEngine. Install with: pip install 'shio-lang[presidio]' (and a spaCy model)."""
    manifest = Manifest("presidio-phi-detector", "0.1.0", TrustClass.READER, "MIT OR Apache-2.0",
                        "Microsoft Presidio analyzer as a reader",
                        (Dependency("presidio-analyzer", "==2.2.358", "MIT"),), extra="presidio")
    schema = Findings
    KINDS = {"PERSON": "NAME", "PHONE_NUMBER": "PHONE", "EMAIL_ADDRESS": "EMAIL", "DATE_TIME": "DATE",
             "LOCATION": "ADDRESS", "US_SSN": "SSN", "IP_ADDRESS": "IP", "URL": "URL", "MEDICAL_LICENSE": "LICENCE"}

    def __init__(self, engine=None, language="en"):
        if engine is None:
            from presidio_analyzer import AnalyzerEngine
            engine = AnalyzerEngine()
        self.engine, self.language = engine, language

    def detect(self, text):
        return sorted(({"kind": self.KINDS.get(r.entity_type, r.entity_type), "start": r.start, "end": r.end}
                       for r in self.engine.analyze(text=text, language=self.language)), key=lambda f: f["start"])

    def read_request(self, req):
        return json.dumps({"entities": [{**f, "source": s.name} for s in req.sources for f in self.detect(s.text or "")]})


def measure_recall(detector, fixtures=FIXTURES):
    """-> {"overall": recall, "by_kind": {kind: {"found", "total", "recall"}}, "cases": n}. An annotated span counts as
    found when any detected span overlaps it (any kind: the question is whether it would be removed)."""
    cases = json.loads(Path(fixtures).read_text())["cases"]
    by_kind = {}
    for case in cases:
        text = case["text"]
        got = detector.detect(text)
        for span in case["spans"]:
            s = text.index(span["text"])
            e = s + len(span["text"])
            hit = any(g["start"] < e and s < g["end"] for g in got)
            k = by_kind.setdefault(span["kind"], {"found": 0, "total": 0})
            k["total"] += 1
            k["found"] += int(hit)
    total = sum(k["total"] for k in by_kind.values())
    found = sum(k["found"] for k in by_kind.values())
    for k in by_kind.values():
        k["recall"] = round(k["found"] / k["total"], 4)
    return {"overall": round(found / total, 4) if total else None, "by_kind": dict(sorted(by_kind.items())),
            "cases": len(cases), "spans": total}
