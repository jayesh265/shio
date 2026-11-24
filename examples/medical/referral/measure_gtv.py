"""Measures the three free-text options (generate-then-verify, D16) on a labelled set built from the synthetic letters,
and writes results/gtv.json. Deterministic.

    python measure_gtv.py

SYNTHETIC: letters, texts and labels are written by engineers. The rates show how the options trade wrongful rejection
of good text against letting bad text through; they are not evidence about a real model. The team picks an option per
use from rates measured on a clinician-labelled set (docs/governance/D16-free-text-options.md).
"""
import json
import re
from pathlib import Path

import referral_support as s
from shio.governance import gtv

HERE = Path(__file__).resolve().parent


def fields(pid):
    return dict(re.findall(r"(?m)^(Reason for referral|History|Medication|Allergies|Results):\s*(.+?)\.?$",
                           s.letter(pid)))


def cases():
    out = []
    for pid, *_ in s.PATIENTS:
        f = fields(pid)
        faithful = [f"Referred for {f['Reason for referral']}.", f"History: {f['History']}.",
                    f"Medication: {f['Medication']}.", f"Results: {f['Results']}."]
        out.append({"id": f"{pid}-faithful", "source": s.letter(pid), "text": " ".join(faithful),
                    "sentences": [True] * 4,
                    "claims": [{"text": x, "quote": f[k], "good": True} for x, k in
                               zip(faithful, ["Reason for referral", "History", "Medication", "Results"])]})
        paraphrase = [f"The patient is being referred because of {f['Reason for referral'].lower()}.",
                      f"Relevant background includes {f['History'].lower()}.",
                      f"Current medication: {f['Medication']}."]
        out.append({"id": f"{pid}-paraphrased", "source": s.letter(pid), "text": " ".join(paraphrase),
                    "sentences": [True] * 3,
                    "claims": [{"text": paraphrase[0], "quote": "referred because of " + f["Reason for referral"].lower(),
                                "good": True},
                               {"text": paraphrase[2], "quote": f["Medication"], "good": True}]})
        wrong = re.sub(r"\d+(\.\d+)?", lambda m: str(round(float(m.group(0)) * 2 + 1)), f["Results"], count=1)
        invented = "The patient was started on insulin glargine 20 units at night last week."
        out.append({"id": f"{pid}-hallucinated", "source": s.letter(pid),
                    "text": f"Referred for {f['Reason for referral']}. Results: {wrong}. {invented}",
                    "sentences": [True, False, False],
                    "claims": [{"text": "reason", "quote": f["Reason for referral"], "good": True},
                               {"text": "results", "quote": wrong, "good": False},
                               {"text": "insulin", "quote": "insulin glargine 20 units at night", "good": False}]})
    return out


if __name__ == "__main__":
    cs = cases()
    result = {"note": "SYNTHETIC: engineer-written texts and labels on synthetic letters; not evidence about a real model.",
              "cases": len(cs), "min_coverage": 0.75, "options": gtv.measure(cs)}
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "gtv.json").write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps(result["options"], indent=1))
