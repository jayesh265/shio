"""Support code for the trial eligibility screener (reference agent 2). Trusted Python the program imports.

SIMULATED: the protocol (FX-TRIAL-007), the study drug (Zelvaprant, FX-INV-101), the formulary and every chart are
fixtures: made up for testing, not a real study, drug or patient. The model is a mock that reads charts by their
labels. Not a clinical tool.
"""
import json
import re

from shio.governance.packs import load_pack
from shio.models import replay

trial = load_pack("med.trial")
rx = load_pack("med.rx")
phi = load_pack("med.phi")
PROTOCOL = trial.lib.protocol()
STUDY_DRUG = PROTOCOL["investigational_drug"]
LABELS = ["active", "placebo"]

# id, age, sex, diagnosis, egfr, hba1c, weight, creatinine, pregnant, waitlist, meds, allergies, consent, planned dose,
# arm, kit, expected (the label: what an investigator would decide), note
CHARTS = [
    ("C01", 62, "M", "diabetic kidney disease", 41, 7.9, 80, 150, False, False, ["Metformin", "Ramipril"], [], "3.1",
     150, "active", "KIT-4401", "ELIGIBLE", "meets every criterion"),
    ("C02", 71, "F", "diabetic kidney disease", 33, 8.2, 62, 140, False, False, ["Ramipril"], ["penicillin"], "3.1",
     60, "placebo", "KIT-4402", "ELIGIBLE", "renal band halves the weight-based dose"),
    ("C03", 84, "M", "diabetic kidney disease", 45, 7.0, 75, 120, False, False, ["Metformin"], [], "3.1", 150,
     "active", "KIT-4403", "NOT_ELIGIBLE", "over 80"),
    ("C04", 34, "F", "diabetic kidney disease", 70, 7.1, 68, 70, True, False, [], [], "3.1", 135, "placebo",
     "KIT-4404", "NOT_ELIGIBLE", "pregnant"),
    ("C05", 58, "M", "diabetic kidney disease", 52, 11.2, 90, 110, False, False, ["Metformin"], [], "3.1", 150,
     "active", "KIT-4405", "NOT_ELIGIBLE", "HbA1c above 10.5"),
    ("C06", 66, "F", "diabetic kidney disease", 39, 8.0, 70, 130, None, False, ["Ramipril"], [], "3.1", 140,
     "placebo", "KIT-4406", "REVIEW", "pregnancy status not recorded"),
    ("C07", 55, "M", "diabetic kidney disease", 48, 7.5, 85, 100, False, False, ["Clarithromycin"], [], "3.1", 150,
     "active", "KIT-4407", "REVIEW", "interacts with clarithromycin"),
    ("C08", 60, "F", "diabetic kidney disease", 44, 7.7, 66, 95, False, False, ["Metformin"], [], "2.0", 130,
     "placebo", "KIT-4408", "REVIEW", "consent version out of date"),
    ("C09", 63, "M", "diabetic kidney disease", 42, 7.8, 78, 140, False, False, ["Metformin"], [], "3.1", 300,
     "active", "KIT-4409", "REVIEW", "planned dose double the recomputed dose"),
    ("C10", 59, "F", "diabetic kidney disease", 47, 7.4, 64, 90, False, False, [], [], "3.1", 125, "placebo",
     "KIT-4410", "REVIEW", "the chart names the allocation: never sent to the model"),
]


def _row(cid):
    return next(c for c in CHARTS if c[0] == cid)


def chart(cid):
    (cid, age, sex, dx, egfr, hba1c, wt, cr, preg, wait, meds, allergies, consent, dose, arm, kit, _, _) = _row(cid)
    lines = [f"Screening chart {cid}", f"Age: {age}", f"Sex: {sex}", f"Diagnosis: {dx}", f"eGFR: {egfr}",
             f"HbA1c: {hba1c}", f"Weight kg: {wt}", f"Serum creatinine umol/L: {cr}"]
    if preg is not None:
        lines.append(f"Pregnant: {'yes' if preg else 'no'}")
    lines += [f"On dialysis waitlist: {'yes' if wait else 'no'}", f"Medications: {', '.join(meds) or 'none'}",
              f"Allergies: {', '.join(allergies) or 'none'}", f"Consent version: {consent}",
              f"Planned starting dose mg: {dose}"]
    if cid == "C10":
        lines.append(f"Pharmacy note: randomised to {arm}, dispensed {kit}.")
    return "\n".join(lines) + "\n"


def allocation(cid):
    row = _row(cid)
    return {"arm": row[14], "labels": LABELS, "codes": [row[15]]}


def expected(cid):
    return _row(cid)[16]


def identity(model):
    return model.identity() if hasattr(model, "identity") else {"kind": type(model).__name__}


def gate(model):
    return phi.lib.PhiGate(model)


def patient(f):
    return {"age": f.age, "sex": f.sex, "weight_kg": f.weight_kg, "serum_creatinine_umol": f.serum_creatinine_umol}


# ---------------- the mock model (SIMULATED) ----------------
FIELDS = {"Age": ("age", int), "Sex": ("sex", str), "Diagnosis": ("diagnosis", str), "eGFR": ("egfr", float),
          "HbA1c": ("hba1c", float), "Weight kg": ("weight_kg", float),
          "Serum creatinine umol/L": ("serum_creatinine_umol", float), "Consent version": ("consent_version", str),
          "Planned starting dose mg": ("planned_dose_mg", float)}


def chart_reader(req):
    text = req.sources[0].text
    out = {v[0]: None for v in FIELDS.values()}
    out.update(pregnant=None, on_dialysis_waitlist=None, medications=[], allergies=[])
    for label, value in re.findall(r"(?m)^([A-Za-z0-9 /]+):\s*(.+)$", text):
        if label in FIELDS:
            name, kind = FIELDS[label]
            out[name] = kind(value.strip())
        elif label == "Pregnant":
            out["pregnant"] = value.strip() == "yes"
        elif label == "On dialysis waitlist":
            out["on_dialysis_waitlist"] = value.strip() == "yes"
        elif label in ("Medications", "Allergies"):
            out[label.lower()] = [] if value.strip() == "none" else [x.strip() for x in value.split(",")]
    return json.dumps(out)


calls = []


def _spy(req):
    calls.append(req.name)
    return chart_reader(req)


careful = replay(_spy, name="screener-mock")
