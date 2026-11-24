"""GOV-3: risk classification as code, and the risk register.

classify(answers) runs a questionnaire against the EU AI Act's structure and proposes a risk class with the
reasons behind it: prohibited (Article 5), high-risk (Annex III areas, or a safety component of a product under
Annex I such as a medical device), limited (Article 50 transparency), or minimal. It is a proposal for a lawyer to
check: every result says so, and an answer of "unsure" never lowers the class. Dates for high-risk obligations are
carried as the policy pack specification recorded them (stand-alone 2 Dec 2027, embedded in products 2 Aug 2028).

The register (risk-register.json, format shio-risk-register/1) holds risks, each with an owner, likelihood and
impact (1 to 5), the controls that treat it, a treatment (mitigate, transfer, accept, avoid) and, for accepted
risks, an expiry. validate_register() refuses an accepted risk with no expiry or owner, flags expired acceptances,
and flags mitigations that name controls no loaded pack has. AGENTIC_RISKS seeds a register from the OWASP agentic
list, mapped to sec.agent controls.
"""
import datetime as dt
import json
from pathlib import Path

QUESTIONS = {
    "social_scoring": "Does it score people's social behaviour or personal traits for treatment in unrelated contexts?",
    "manipulation": "Does it use subliminal, manipulative or deceptive techniques that distort behaviour and cause harm?",
    "exploits_vulnerability": "Does it exploit vulnerabilities of age, disability or social or economic situation?",
    "realtime_remote_biometric_id": "Real-time remote biometric identification in public spaces for law enforcement?",
    "emotion_recognition_work_school": "Emotion recognition in workplaces or education (not for medical or safety reasons)?",
    "biometric_categorisation_sensitive": "Biometric categorisation inferring race, politics, beliefs or sexual orientation?",
    "untargeted_face_scraping": "Building face recognition databases by untargeted scraping?",
    "predictive_policing_profiling": "Predicting crime risk of a person based solely on profiling?",
    "medical_device_component": "Is it, or is it a safety component of, a medical device or IVD under MDR/IVDR?",
    "other_annex_i_product": "Is it a safety component of another product under Annex I harmonisation law?",
    "annex_iii_area": "Which Annex III area, if any: biometrics, critical_infrastructure, education, employment, "
                      "essential_services, law_enforcement, migration, justice, or none",
    "triage_or_emergency": "Does it evaluate or classify emergency calls or establish priority in emergency triage?",
    "health_or_life_insurance": "Does it assess risk or price life or health insurance for individuals?",
    "narrow_procedural": "Article 6(3): does it only perform a narrow procedural task or prepare an assessment, "
                         "without replacing human assessment, and does it not profile people?",
    "interacts_with_people": "Does it interact directly with people, or generate text, audio, images or video?",
}
PROHIBITED = ("social_scoring", "manipulation", "exploits_vulnerability", "realtime_remote_biometric_id",
              "emotion_recognition_work_school", "biometric_categorisation_sensitive", "untargeted_face_scraping",
              "predictive_policing_profiling")
ANNEX_III = ("biometrics", "critical_infrastructure", "education", "employment", "essential_services",
             "law_enforcement", "migration", "justice")
DATES = {"high-risk (stand-alone)": "2027-12-02", "high-risk (embedded in a product)": "2028-08-02"}


def _yes(v):
    return v is True or str(v).lower() in ("yes", "true", "y")


def _unsure(v):
    return v is None or str(v).lower() in ("unsure", "unknown", "?")


def classify(answers):
    """-> {"class", "reasons", "applies_from", "needs_legal_review": True, "unanswered"}."""
    reasons, unanswered = [], [q for q in QUESTIONS if q not in answers]
    hit = [q for q in PROHIBITED if _yes(answers.get(q))]
    unsure_prohibited = [q for q in PROHIBITED if _unsure(answers.get(q)) and q in answers]
    if hit:
        return {"class": "prohibited", "reasons": [f"Article 5: {QUESTIONS[q]}" for q in hit],
                "applies_from": "2025-02-02", "needs_legal_review": True, "unanswered": unanswered}
    cls, applies = "minimal", None
    if _yes(answers.get("medical_device_component")) or _yes(answers.get("other_annex_i_product")):
        cls, applies = "high-risk", DATES["high-risk (embedded in a product)"]
        reasons.append("Article 6(1) and Annex I: a safety component of (or itself) a product under harmonisation "
                       "law, such as a medical device; high-risk if the product needs third-party conformity "
                       "assessment")
    area = str(answers.get("annex_iii_area") or "none").lower()
    essential = _yes(answers.get("triage_or_emergency")) or _yes(answers.get("health_or_life_insurance"))
    if area in ANNEX_III or essential:
        why = f"Annex III area: {area}" if area in ANNEX_III else \
            "Annex III point 5 (essential services): emergency triage or life and health insurance"
        if _yes(answers.get("narrow_procedural")) and cls != "high-risk":
            reasons.append(f"{why}, but the Article 6(3) exception was claimed: not high-risk only if documented "
                           f"and registered, and never when it profiles people")
            cls = "limited" if _yes(answers.get("interacts_with_people")) else "minimal"
        else:
            if cls != "high-risk":
                cls, applies = "high-risk", DATES["high-risk (stand-alone)"]
            reasons.append(why)
    if cls in ("minimal",) and _yes(answers.get("interacts_with_people")):
        cls = "limited"
        reasons.append("Article 50: it interacts with people or generates content, so transparency duties apply")
    if unsure_prohibited or (cls != "high-risk" and any(_unsure(answers.get(q)) and q in answers for q in
                                                        ("medical_device_component", "triage_or_emergency"))):
        reasons.append("some answers were 'unsure': the class shown is a floor, not a ceiling, until a lawyer "
                       "settles them")
    if not reasons:
        reasons.append("no answer places it in a regulated category")
    return {"class": cls, "reasons": reasons, "applies_from": applies, "needs_legal_review": True,
            "unanswered": unanswered,
            "note": "A proposal from a questionnaire, not a legal determination. A lawyer must review it."}


AGENTIC_RISKS = [
    ("ASI01", "Agent goal hijack by injected instructions", 4, 4, ["sec.agent:ASI-01"]),
    ("ASI02", "Tool misuse and exploitation", 4, 4, ["sec.agent:ASI-02"]),
    ("ASI03", "Identity and privilege abuse", 3, 4, ["sec.agent:ASI-03"]),
    ("ASI04", "Agentic supply chain compromise", 3, 5, ["sec.agent:ASI-04"]),
    ("ASI05", "Unexpected code execution", 2, 5, ["sec.agent:ASI-05"]),
    ("ASI06", "Memory and context poisoning", 3, 3, ["sec.agent:ASI-06"]),
    ("ASI07", "Insecure inter-agent communication", 2, 4, ["sec.agent:ASI-07"]),
    ("ASI08", "Cascading failures", 3, 3, ["sec.agent:ASI-08"]),
    ("ASI09", "Human-agent trust exploitation", 3, 4, ["sec.agent:ASI-09"]),
    ("ASI10", "Rogue or misaligned agents", 2, 5, ["sec.agent:ASI-10"]),
]
TREATMENTS = ("mitigate", "transfer", "accept", "avoid")


def seed_register(owner, today=None):
    today = today or dt.date.today()
    return {"format": "shio-risk-register/1", "as_of": today.isoformat(),
            "risks": [{"id": rid, "title": t, "owner": owner, "likelihood": li, "impact": im, "treatment": "mitigate",
                       "controls": c, "source": "OWASP Top 10 for Agentic Applications 2026"}
                      for rid, t, li, im, c in AGENTIC_RISKS]}


def score(r):
    return r["likelihood"] * r["impact"]


def validate_register(reg, today=None, known_controls=None):
    """-> [problems]."""
    today = today or dt.date.today()
    out = []
    if reg.get("format") != "shio-risk-register/1":
        return ["format must be 'shio-risk-register/1'"]
    ids = [r.get("id") for r in reg.get("risks", [])]
    out += [f"risk id {i} is used twice" for i in sorted({i for i in ids if ids.count(i) > 1})]
    for r in reg.get("risks", []):
        w = f"risk {r.get('id')}"
        if not r.get("owner"):
            out.append(f"{w}: needs an owner")
        for k in ("likelihood", "impact"):
            if not isinstance(r.get(k), int) or not 1 <= r[k] <= 5:
                out.append(f"{w}: {k} must be 1 to 5")
        if r.get("treatment") not in TREATMENTS:
            out.append(f"{w}: treatment must be one of {', '.join(TREATMENTS)}")
        if r.get("treatment") == "accept":
            if not r.get("expires"):
                out.append(f"{w}: an accepted risk needs an expiry date")
            elif dt.date.fromisoformat(r["expires"]) < today:
                out.append(f"{w}: its acceptance expired on {r['expires']}: review it")
            if not r.get("accepted_by"):
                out.append(f"{w}: an accepted risk needs who accepted it")
        if r.get("treatment") == "mitigate":
            if not r.get("controls"):
                out.append(f"{w}: a mitigated risk names the controls that mitigate it")
            elif known_controls is not None:
                out += [f"{w}: control {c} is in no loaded pack" for c in r["controls"] if c not in known_controls]
    return out


def known_controls():
    from .packs import builtin, read
    return {f"{p.id}:{c.id}" for p in (read(x) for x in builtin().values()) for c in p.controls}


def heatmap(reg):
    grid = [[[] for _ in range(5)] for _ in range(5)]
    for r in reg.get("risks", []):
        grid[5 - r["impact"]][r["likelihood"] - 1].append(r["id"])
    return grid


def load(path):
    return json.loads(Path(path).read_text())
