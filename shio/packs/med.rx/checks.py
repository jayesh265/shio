"""med.rx: a drug resolved to a standard code, the dose recomputed in code from weight, age and kidney function, and
interactions and allergies looked up.

Reference data (drug codes, dosing, interactions, allergy classes) is licensed in most places. This pack bundles none:
it ships a FIXTURE formulary of made-up codes (FX-...) so its checks and tests run, and `ReferenceData.load` refuses
any dataset that is not a fixture unless its manifest records that its licence was confirmed, by whom and when.

Data structures:
  - drugs are found by normalised name or synonym in a hash map (O(1) per lookup);
  - interactions are an undirected graph (adjacency sets keyed by code), so checking a new drug against n current
    drugs is O(n);
  - allergy classes are a tree (child -> parent), walked upward breadth-first, so a penicillin allergy blocks
    amoxicillin through the class it belongs to.
"""
import json
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from shio.governance.verdict import Verdict

HERE = Path(__file__).resolve().parent
SEVERE = ("contraindicated", "major")


class LicenceNotConfirmed(PermissionError):
    pass


def _norm(name):
    return re.sub(r"[^a-z0-9]+", " ", str(name or "").lower()).strip()


@dataclass
class ReferenceData:
    meta: dict
    drugs: dict              # code -> drug entry
    names: dict              # normalised name or synonym -> code
    interactions: dict       # code -> {other code: (severity, note)}
    parents: dict            # class or code -> parent class
    class_names: dict        # normalised class name ("penicillin") -> class id ("penicillins")

    @classmethod
    def load(cls, path=None):
        path = Path(path or HERE / "fixture-formulary.json")
        d = json.loads(path.read_text())
        meta = d.get("meta", {})
        if not meta.get("fixture"):
            lic = meta.get("licence") or {}
            if not (lic.get("confirmed") and lic.get("confirmed_by") and lic.get("date")):
                raise LicenceNotConfirmed(
                    f"{path.name}: reference data {meta.get('name', '?')} is not a fixture and its licence is not "
                    f"confirmed (meta.licence.confirmed, confirmed_by, date); confirm licensing before loading it")
        drugs, names = {}, {}
        for drug in d["drugs"]:
            drugs[drug["code"]] = drug
            for n in [drug["name"], *drug.get("synonyms", [])]:
                key = _norm(n)
                if key in names and names[key] != drug["code"]:
                    raise ValueError(f"{path.name}: name {n!r} is used by {names[key]} and {drug['code']}")
                names[key] = drug["code"]
        graph = {}
        for it in d.get("interactions", []):
            for a, b in ((it["a"], it["b"]), (it["b"], it["a"])):
                graph.setdefault(a, {})[b] = (it["severity"], it.get("note", ""))
        parents = dict(d.get("classes", {}))
        for drug in d["drugs"]:
            if drug.get("class"):
                parents[drug["code"]] = drug["class"]
        class_names = {_norm(k): v for k, v in d.get("class_names", {}).items()}
        class_names.update({_norm(c): c for c in set(d.get("classes", {})) | set(d.get("classes", {}).values()) if c})
        return cls(meta, drugs, names, graph, parents, class_names)

    def resolve(self, name):
        return self.names.get(_norm(name))

    def ancestors(self, node):
        """node and every class above it, nearest first (breadth-first up the class tree; guards against cycles)."""
        out, seen, queue = [], set(), deque([node])
        while queue:
            n = queue.popleft()
            if n in seen or n is None:
                continue
            seen.add(n)
            out.append(n)
            queue.append(self.parents.get(n))
        return out


_default = None


def data():
    global _default
    if _default is None:
        _default = ReferenceData.load()
    return _default


# ---------------- dose arithmetic ----------------
def creatinine_clearance(age, weight_kg, sex, serum_creatinine_umol):
    """Cockcroft-Gault, mL/min: (140 - age) x weight x (0.85 if female) / (0.814 x SCr in umol/L)."""
    if not all(isinstance(x, (int, float)) and x > 0 for x in (age, weight_kg, serum_creatinine_umol)):
        raise ValueError("age, weight and serum creatinine must be positive numbers")
    crcl = (140 - age) * weight_kg / (0.814 * serum_creatinine_umol)
    return round(crcl * (0.85 if str(sex).upper().startswith("F") else 1.0), 1)


def recompute_dose(drug_code, patient, ref=None):
    """-> {"dose_mg", "frequency", "crcl", "basis": [...], "contraindicated": reason or None}. Weight-based dosing is
    capped at the maximum; renal bands (lowest first) reduce or forbid the dose."""
    ref = ref or data()
    drug = ref.drugs[drug_code]
    rule = drug["dosing"]
    basis = []
    if patient.get("age") is not None and patient["age"] < rule.get("min_age", 0):
        return {"dose_mg": None, "frequency": None, "crcl": None, "basis": basis,
                "contraindicated": f"under the minimum age of {rule['min_age']}"}
    if "mg_per_kg" in rule:
        dose = rule["mg_per_kg"] * patient["weight_kg"]
        basis.append(f"{rule['mg_per_kg']} mg/kg x {patient['weight_kg']} kg = {dose:g} mg")
    else:
        dose = rule["dose_mg"]
        basis.append(f"fixed dose {dose:g} mg")
    if rule.get("max_mg") and dose > rule["max_mg"]:
        basis.append(f"capped at the maximum {rule['max_mg']:g} mg")
        dose = rule["max_mg"]
    crcl = None
    if drug.get("renal"):
        crcl = creatinine_clearance(patient["age"], patient["weight_kg"], patient.get("sex"),
                                    patient["serum_creatinine_umol"])
        basis.append(f"creatinine clearance {crcl:g} mL/min (Cockcroft-Gault)")
        for band in sorted(drug["renal"], key=lambda b: b["crcl_below"]):
            if crcl < band["crcl_below"]:
                if band.get("contraindicated"):
                    return {"dose_mg": None, "frequency": None, "crcl": crcl, "basis": basis,
                            "contraindicated": f"creatinine clearance {crcl:g} is below {band['crcl_below']} mL/min"}
                dose *= band["factor"]
                basis.append(f"x {band['factor']} for clearance below {band['crcl_below']} mL/min")
                break
    rounding = rule.get("round_mg", 1)
    dose = round(dose / rounding) * rounding
    return {"dose_mg": dose, "frequency": rule.get("frequency"), "crcl": crcl, "basis": basis,
            "contraindicated": None}


# ---------------- runtime checks ----------------
def drug_resolved(name, ref=None):
    """RX-1: the drug name resolves to exactly one standard code in the reference data."""
    ref = ref or data()
    code = ref.resolve(name)
    if code is None:
        return Verdict.fail(f"{name!r} does not resolve to a code in {ref.meta.get('name')}")
    return Verdict.ok(f"{name} is {code} ({ref.drugs[code]['name']})", [code])


def dose_matches(name, proposed_mg, patient, tolerance=0.10, ref=None):
    """RX-2: the proposed dose equals the dose recomputed in code (within the tolerance), and the drug is not
    contraindicated for this patient's age or kidney function."""
    ref = ref or data()
    code = ref.resolve(name)
    if code is None:
        return Verdict.fail(f"{name!r} is not a known drug, so its dose can't be checked")
    try:
        want = recompute_dose(code, patient, ref)
    except (KeyError, ValueError, TypeError) as e:
        return Verdict.fail(f"the dose can't be recomputed: {e}")
    if want["contraindicated"]:
        return Verdict.fail(f"{ref.drugs[code]['name']} is contraindicated: {want['contraindicated']}")
    if not isinstance(proposed_mg, (int, float)):
        return Verdict.fail("no proposed dose")
    if abs(proposed_mg - want["dose_mg"]) > tolerance * want["dose_mg"]:
        return Verdict.fail(f"proposed {proposed_mg:g} mg, recomputed {want['dose_mg']:g} mg ({'; '.join(want['basis'])})")
    return Verdict.ok(f"{proposed_mg:g} mg matches the recomputed {want['dose_mg']:g} mg")


def no_interactions(name, current, ref=None):
    """RX-3: no major or contraindicated interaction between the drug and any current medication."""
    ref = ref or data()
    code = ref.resolve(name)
    if code is None:
        return Verdict.fail(f"{name!r} is not a known drug, so interactions can't be checked")
    edges, hits, unknown = ref.interactions.get(code, {}), [], []
    for other in current or []:
        oc = ref.resolve(other)
        if oc is None:
            unknown.append(str(other))
            continue
        sev, note = edges.get(oc, (None, ""))
        if sev in SEVERE:
            hits.append(f"{ref.drugs[oc]['name']} ({sev}: {note})")
    if hits:
        return Verdict.fail(f"{ref.drugs[code]['name']} interacts with " + "; ".join(hits))
    if unknown:
        return Verdict.fail(f"current medications not in the reference data, so not checked: {', '.join(unknown)}")
    return Verdict.ok("no major interaction")


def no_allergy_conflict(name, allergies, ref=None):
    """RX-4: the drug is not, and is not in the class of, anything the patient is allergic to. An allergy recorded as
    a drug also rules out that drug's class (an amoxicillin allergy rules out other penicillins). An allergy the
    reference data doesn't know can't be checked, so it fails (a person looks)."""
    ref = ref or data()
    code = ref.resolve(name)
    if code is None:
        return Verdict.fail(f"{name!r} is not a known drug, so allergies can't be checked")
    lineage = set(ref.ancestors(code))
    unknown = []
    for allergy in allergies or []:
        node = ref.resolve(allergy) or ref.class_names.get(_norm(allergy))
        if node is None:
            unknown.append(str(allergy))
            continue
        candidates = [node] + ([ref.parents.get(node)] if node in ref.drugs else [])
        hit = next((n for n in candidates if n and n in lineage), None)
        if hit:
            return Verdict.fail(f"{ref.drugs[code]['name']} conflicts with the recorded allergy to {allergy} "
                                f"({'the same drug' if hit == code else hit})")
    if unknown:
        return Verdict.fail(f"allergies not in the reference data, so not checked: {', '.join(unknown)}")
    return Verdict.ok("no allergy conflict")
