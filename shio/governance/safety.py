"""Clinical safety case generator, v1 (D24): hazard log, controls and evidence, rebuilt from records.

Every medical pack declares its hazards (severity and likelihood before controls) and which controls mitigate each.
The generator gathers, for one agent:

  hazard log    each hazard of each pack in use, with its initial risk from the risk matrix
  controls      each control that names the hazard, with its evidence (static proofs, checks in the records, evals,
                sign-offs: the same evidence a framework bundle uses), and each check's measured effectiveness
                from reviewer labels (blocked, overturned, precision)
  residual risk the likelihood lowered by one step for each control whose evidence is complete (never below 1);
                the stated method, for the clinical safety lead to accept, change or reject

The result is a DRAFT until the clinical safety lead approves its exact hash (an approval of subject "safety-case").
It never says a system is safe: it lays out the argument and the evidence for the person accountable to judge.
"""
import datetime as dt
import json
from pathlib import Path

from .assess import seal
from .bundle import EVIDENCED, _cited, _evidence, _signoffs
from .chain import ApprovalLog
from .effectiveness import measure
from .packs import read, resolve

FORMAT = "shio-safety-case/1"
SEVERITY = {1: "minor", 2: "significant", 3: "considerable", 4: "major", 5: "catastrophic"}
LIKELIHOOD = {1: "very low", 2: "low", 3: "medium", 4: "high", 5: "very high"}
# risk rating by [likelihood][severity], in the style of the DCB0129/DCB0160 matrix; confirm with the safety lead
MATRIX = {5: [3, 4, 4, 5, 5], 4: [2, 3, 3, 4, 5], 3: [2, 2, 3, 3, 4], 2: [1, 2, 2, 3, 4], 1: [1, 1, 2, 2, 3]}
ACCEPTABILITY = {1: "acceptable", 2: "acceptable", 3: "tolerable: reduce as far as reasonably practicable",
                 4: "unacceptable", 5: "unacceptable"}
METHOD = ("Initial risk: the pack's severity and likelihood, rated on the 5x5 matrix. Residual risk: the likelihood is "
          "lowered one step for each control whose evidence is complete (never below 1); severity is unchanged. "
          "This method is a starting point for the clinical safety lead, not a judgement.")


def rating(severity, likelihood):
    return MATRIX[likelihood][severity - 1]


def build(agent, packs, folder, start, end, assessment=None, evals=(), approvals=(), signer=None):
    """-> the sealed safety case. packs: ids or folders. assessment, evals: loaded documents (dicts)."""
    cited = _cited(folder, start, end) if folder else {}
    signoffs = _signoffs(folder, approvals, start, end)
    eff = measure(folder)["checks"] if folder else {}
    hazards = []
    for ref in packs:
        pack = read(resolve(ref))
        for h in pack.hazards:
            controls = []
            for c in pack.controls:
                if h["id"] not in c.hazards:
                    continue
                items = [_evidence(p, pack, assessment, cited, list(evals), signoffs, c.id) for p in c.proofs]
                status = EVIDENCED if all(s == EVIDENCED for s, _ in items) else \
                    "GAP" if any(s == "GAP" for s, _ in items) else "MISSING"
                checks = [p.target for p in c.proofs if p.kind.value == "runtime"]
                controls.append({"pack": pack.label(), "id": c.id, "title": c.title, "status": status,
                                 "evidence": [e for _, e in items],
                                 "effectiveness": {k: v for k, v in eff.items()
                                                   if any(k.endswith("." + ch) or f"{pack.id}@{pack.version}:{c.id}" in
                                                          v.get("controls", []) for ch in checks)}})
            sev, lik = int(h["severity"]), int(h["likelihood"])
            evidenced = sum(1 for c in controls if c["status"] == EVIDENCED)
            res_lik = max(1, lik - evidenced)
            r0, r1 = rating(sev, lik), rating(sev, res_lik)
            hazards.append({"id": h["id"], "title": h["title"], "pack": pack.label(),
                            "severity": sev, "severity_label": SEVERITY[sev], "likelihood": lik,
                            "likelihood_label": LIKELIHOOD[lik], "initial_risk": r0,
                            "controls": controls, "controls_evidenced": evidenced,
                            "residual_likelihood": res_lik, "residual_risk": r1,
                            "acceptability": ACCEPTABILITY[r1]})
    doc = {"format": FORMAT, "agent": agent, "status": "DRAFT: requires the clinical safety lead's review and approval",
           "period": [start.isoformat(), end.isoformat()], "records": str(folder) if folder else None,
           "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "method": METHOD,
           "hazards": hazards,
           "summary": {"hazards": len(hazards),
                       "unacceptable_residual": [h["id"] for h in hazards if h["residual_risk"] >= 4],
                       "tolerable_residual": [h["id"] for h in hazards if h["residual_risk"] == 3]}}
    return seal(doc, signer)


def approve(case, approvals, by, meaning="safety case reviewed", signer=None, reject=False):
    return ApprovalLog(approvals).record("safety-case", case["sha256"], by, "clinical_safety_lead", meaning,
                                         "rejected" if reject else "approved", signer=signer, title=case["agent"])


def markdown(case, approval_state=None):
    lines = [f"# Clinical safety case: {case['agent']}", "",
             f"**{approval_state or case['status']}** (sha256 `{case['sha256'][:16]}…`). Period {case['period'][0]} "
             f"to {case['period'][1]}.", "", f"Method: {case['method']}", "", "## Hazard log", "",
             "| Hazard | Severity | Likelihood | Initial | Controls evidenced | Residual | Acceptability |",
             "|---|---|---|---|---|---|---|"]
    for h in case["hazards"]:
        lines.append(f"| **{h['id']}** {h['title']} | {h['severity']} {h['severity_label']} | {h['likelihood']} "
                     f"{h['likelihood_label']} | {h['initial_risk']} | {h['controls_evidenced']}/{len(h['controls'])} | "
                     f"{h['residual_risk']} | {h['acceptability']} |")
    for h in case["hazards"]:
        lines += ["", f"## {h['id']}: {h['title']}", ""]
        for c in h["controls"]:
            lines.append(f"- **{c['pack']} {c['id']}** {c['title']}: {c['status']}")
            for e in c["evidence"]:
                lines.append(f"  - {e['proof']}: " + json.dumps({k: v for k, v in e.items() if k not in ('proof',
                                                                                                   'records')})[:200])
            for name, m in c["effectiveness"].items():
                p = f"{m['precision']:.0%}" if m["precision"] is not None else "not yet labelled"
                lines.append(f"  - effectiveness of {name}: ran {m['runs']}, blocked {m['blocked']}, upheld "
                             f"{m['upheld']}, overturned {m['overturned']}, precision {p}")
    lines += ["", "This document lays out hazards, controls and evidence. Whether the residual risk is acceptable is "
                  "the clinical safety lead's judgement, recorded as an approval of this document's hash.", ""]
    return "\n".join(lines)


def write(case, out, approvals=None):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    state = None
    if approvals:
        st, missing = ApprovalLog(approvals).status(case["sha256"], ["clinical_safety_lead"])
        state = f"{st}" + (f" (waiting for {', '.join(missing)})" if missing else "")
    (out / "safety-case.json").write_text(json.dumps(case, indent=1))
    (out / "safety-case.md").write_text(markdown(case, state))
    return out
