"""Writes evals/eligibility.json from the fixture charts and their labels. Deterministic."""
import json
from pathlib import Path

import screener_support as s

HERE = Path(__file__).resolve().parent
NOTE = "SYNTHETIC: fixture protocol and charts; labels are an engineer's reading of the protocol, not an investigator's."

if __name__ == "__main__":
    cases = [{"id": c[0], "origin": c[17], "input": {"chart": c[0]}, "expect": {"status": c[16]},
              "slices": {"sex": c[2], "age_band": "65+" if c[1] >= 65 else "40-64" if c[1] >= 40 else "18-39"}}
             for c in s.CHARTS]
    suite = {"format": "shio-eval-suite/1", "suite": "eligibility", "note": NOTE, "target": "screener_evals:target",
             "slices": ["sex", "age_band"], "metrics": [{"name": "pass_rate"}, {"name": "max_slice_gap", "min_n": 2}],
             "gates": {"pass_rate": [">=", 0.95]}, "cases": cases}
    (HERE / "evals").mkdir(exist_ok=True)
    (HERE / "evals" / "eligibility.json").write_text(json.dumps(suite, indent=1) + "\n")
    print("wrote evals/eligibility.json")
