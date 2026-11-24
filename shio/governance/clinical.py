"""MED-3 calibrated clinical abstention, and MED-8 the patient-facing release gate.

Calibration. Every clinical read has an explicit "cannot tell, send to a clinician" answer. A reading is accepted only
when its confidence is at or above a threshold chosen per field (and domain) from reviewer labels, so that among the
readings accepted, the error rate is at most alpha with a stated confidence: the threshold is the lowest one whose
exact (Clopper-Pearson) upper bound on the error rate is <= alpha, tested in a fixed sequence from the most
confident down and stopping at the first failure (so testing many thresholds doesn't inflate the error). Too few labels, or no threshold meeting the bound,
means abstain on everything for that field: nothing is accepted on hope. Thresholds are a sealed, versioned document
(change it and its hash changes), and accept() cites the version it used.

The calibration holds for data like the calibration set. A conformal study of medical extraction found miscalibration
reversing direction between two clinical domains, so thresholds are keyed by domain and never transfer silently.

Release gate. A patient-facing answer is released only when: no red flag is present (med.triage's matcher on the
patient's message; a red flag always escalates to a person, and the answer leads with the emergency instruction);
the answer makes no dosing or diagnosis claim (those need clinician review); and every risk score the pack names is
under its threshold (two independent scores, as CareGuardAI does). Anything else is held for a clinician, with the
reason the patient-facing text will show.
"""
import datetime as dt
import math
import re

from .assess import seal


# ---------------- exact binomial bound ----------------
def _binom_cdf(k, n, p):
    if p <= 0:
        return 1.0
    if p >= 1:
        return 0.0 if k < n else 1.0
    total, term = 0.0, (1 - p) ** n
    for i in range(0, k + 1):
        if i > 0:
            term *= (n - i + 1) / i * p / (1 - p)
        total += term
    return min(1.0, total)


def upper_bound(errors, n, confidence=0.95):
    """Clopper-Pearson one-sided upper bound on an error rate: the p where P(X <= errors | n, p) = 1 - confidence."""
    if n == 0:
        return 1.0
    if errors >= n:
        return 1.0
    lo, hi = errors / n, 1.0
    for _ in range(60):
        mid = (lo + hi) / 2
        if _binom_cdf(errors, n, mid) > 1 - confidence:
            lo = mid
        else:
            hi = mid
    return hi


def calibrate(labels, alpha=0.05, confidence=0.95, min_accepted=30):
    """labels: [(confidence, correct)] from reviewers for one field and domain. -> the threshold document part."""
    pts = sorted(((float(c), bool(ok)) for c, ok in labels), key=lambda x: -x[0])
    best = None
    errors = 0
    for i, (c, ok) in enumerate(pts, 1):
        errors += not ok
        if i < min_accepted:
            continue
        if i < len(pts) and pts[i][0] == c:          # thresholds sit between distinct confidences
            continue
        ub = upper_bound(errors, i, confidence)
        if ub > alpha:
            break                                     # fixed-sequence testing: stop at the first failure
        best = {"threshold": c, "accepted": i, "errors": errors, "error_rate": round(errors / i, 4),
                "error_upper_bound": round(ub, 4)}
    n = len(pts)
    if best is None:
        return {"threshold": None, "abstain_all": True, "n": n, "coverage": 0.0,
                "why": f"no threshold keeps the error bound under {alpha} with {n} labels (need >= {min_accepted} "
                       f"accepted)"}
    return {**best, "abstain_all": False, "n": n, "coverage": round(best["accepted"] / n, 4)}


def thresholds(per_field, alpha=0.05, confidence=0.95, min_accepted=30, signer=None, source=""):
    """per_field: {(field, domain): [(confidence, correct)]} -> a sealed threshold document."""
    fields = {f"{f}@{d}": calibrate(v, alpha, confidence, min_accepted) for (f, d), v in sorted(per_field.items())}
    return seal({"format": "shio-thresholds/1", "alpha": alpha, "confidence": confidence,
                 "min_accepted": min_accepted, "calibrated": dt.date.today().isoformat(), "labels_from": source,
                 "fields": fields}, signer)


CANNOT_TELL = "cannot tell: send to a clinician"


def accept(doc, field, domain, confidence):
    """-> (accepted, reason). Unknown field or domain, abstain-all, or a low score: cannot tell."""
    t = doc["fields"].get(f"{field}@{domain}")
    if t is None:
        return False, f"{CANNOT_TELL} (no calibrated threshold for {field} in {domain}; thresholds do not transfer)"
    if t["abstain_all"] or confidence is None:
        return False, f"{CANNOT_TELL} ({t.get('why', 'no confidence given')})"
    if confidence < t["threshold"]:
        return False, f"{CANNOT_TELL} (confidence {confidence:.2f} below {t['threshold']:.2f}, thresholds " \
                      f"{doc['sha256'][:12]})"
    return True, f"accepted at {confidence:.2f} >= {t['threshold']:.2f} (error bound {t['error_upper_bound']}, " \
                 f"thresholds {doc['sha256'][:12]})"


# ---------------- MED-8 ----------------
DOSE = re.compile(r"(?i)\b\d+(?:\.\d+)?\s?(?:mg|mcg|µg|g|ml|mL|units?|iu|tablets?|puffs?|drops?)\b"
                  r"|\b(?:take|double|increase|decrease|stop taking|skip)\s+(?:your\s+)?(?:dose|tablet|medication|\w+ "
                  r"(?:tablets?|pills?))")
DIAGNOSIS = re.compile(r"(?i)\b(?:you (?:have|are suffering from|probably have|likely have|definitely have)|"
                       r"(?:this|it) (?:is|sounds like|looks like) (?:a |an )?(?:case of )?[a-z]+(?:itis|osis|oma|emia)|"
                       r"diagnos(?:is|ed|e) (?:is|of|with))")
EMERGENCY = "If this is an emergency, call your local emergency number now."


def release(patient_message, answer, scores=None, limits=None, red_flags=None):
    """-> {"release": bool, "action": release|escalate|hold, "reasons": [...], "patient_text": str}."""
    if red_flags is None:
        from .packs import load_pack
        rf = load_pack("med.triage").lib.flags()
        flags = [f"{h} ({rf.flags[h]['category']})" for h in rf.matches(patient_message)]
        emergency = rf.emergency
    else:
        flags, emergency = list(red_flags), EMERGENCY
    if flags:                                 # the emergency instruction first, never behind a question (TRI-05)
        return {"release": False, "action": "escalate", "reasons": [f"red flag: {f}" for f in flags],
                "patient_text": f"{emergency} A clinician has been asked to contact you."}
    reasons = []
    if DOSE.search(answer or ""):
        reasons.append("the answer makes a dosing claim: clinician review needed")
    if DIAGNOSIS.search(answer or ""):
        reasons.append("the answer makes a diagnosis claim: clinician review needed")
    for name, limit in (limits or {}).items():
        s = (scores or {}).get(name)
        if s is None:
            reasons.append(f"risk score {name} is missing: held (fail closed)")
        elif s >= limit:
            reasons.append(f"risk score {name} {s:.2f} is at or above {limit}")
    if reasons:
        return {"release": False, "action": "hold", "reasons": reasons,
                "patient_text": "A clinician will review this answer before it reaches you."}
    return {"release": True, "action": "release", "reasons": [], "patient_text": answer}
