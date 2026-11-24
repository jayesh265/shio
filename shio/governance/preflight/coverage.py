"""The coverage matrix: the answer to "are all the compliance guidelines covered".

A source is covered only if it appears here. For every control in every pack:

  enforced   code checks it on every request (gate, runtime check) or at compile time (lint)
  measured   an eval in CI with a threshold
  attested   a current signed attestation (or a person's sign-off) is required
  planned    listed in the spec, not yet built: NOT covered

Packs built on voluntary frameworks (NIST AI RMF, ISO/IEC 42001, OWASP) are marked guidance, not legal duty. With an
attestation ledger, attested rows also say current, expiring, expired or missing.

How to read a claim: "this agent passed every enforced control in these packs and holds current attestations for the
rest". Never "this agent is HIPAA compliant": compliance is a property of the organisation, decided by regulators and
courts.
"""
import datetime as dt

GUIDANCE = frozenset({"sec.agent", "gov.iso42001", "gov.nist-ai-rmf"})
NOT_COVERED = ("FTC Health Breach Notification Rule", "TEFCA and information blocking", "CCPA and other US consumer law",
               "UK GDPR and the Data Protection Act 2018", "SOC 2 and HITRUST (evidence export only; Shio does not certify)")
CLAIM = ("This agent passed every enforced control in the listed packs and holds current attestations for the "
         "attested ones. It is not a statement that the organisation is compliant with any law.")


def classify(control):
    kinds = {p.kind.value for p in control.proofs}
    if control.planned or not kinds:
        return "planned"
    if kinds & {"gate", "runtime", "lint"}:
        return "enforced"
    if "eval" in kinds:
        return "measured"
    return "attested"


def matrix(packs=None, ledger=None, today=None):
    """-> {"rows": [...], "summary": {pack: {class: n}}, "not_covered": [...], "claim": str}."""
    from ..packs import builtin, read
    packs = packs if packs is not None else [read(p) for p in builtin().values()]
    today = today or dt.date.today()
    rows, summary = [], {}
    for p in sorted(packs, key=lambda x: x.id):
        for c in p.controls:
            cls = classify(c)
            row = {"pack": p.id, "version": p.version, "status": p.status, "control": c.id, "title": c.title,
                   "stage": c.stage, "on_fail": c.on_fail, "source": c.source or ", ".join(r.ref for r in c.refs),
                   "coverage": cls, "guidance": p.id in GUIDANCE,
                   "proofs": [pr.label() for pr in c.proofs]}
            att = [pr for pr in c.proofs if pr.kind.value == "attestation"]
            if att and ledger is not None:
                state, a = ledger.status([att[0].target], today)[att[0].target]
                row["attestation"] = {"kind": att[0].target, "state": state,
                                      "expires": a.expires.isoformat() if a else None}
            rows.append(row)
            summary.setdefault(p.id, {"enforced": 0, "measured": 0, "attested": 0, "planned": 0})[cls] += 1
    return {"rows": rows, "summary": summary, "not_covered": list(NOT_COVERED), "claim": CLAIM,
            "generated": today.isoformat()}


def markdown(m):
    lines = ["# Coverage matrix", "", m["claim"], "",
             "| Pack | Enforced | Measured | Attested | Planned (not covered) |", "|---|---:|---:|---:|---:|"]
    for pid, s in m["summary"].items():
        lines.append(f"| {pid}{' (guidance)' if pid in GUIDANCE else ''} | {s['enforced']} | {s['measured']} | "
                     f"{s['attested']} | {s['planned']} |")
    total = {k: sum(s[k] for s in m["summary"].values()) for k in ("enforced", "measured", "attested", "planned")}
    lines += [f"| **All packs** | **{total['enforced']}** | **{total['measured']}** | **{total['attested']}** | "
              f"**{total['planned']}** |", "", "## Not covered", ""]
    lines += [f"- {x}" for x in m["not_covered"]] + ["", "## Every control", "",
                                                     "| Pack | Control | Stage | On fail | Coverage | Source |",
                                                     "|---|---|---|---|---|---|"]
    for r in m["rows"]:
        cov = r["coverage"] + (f", {r['attestation']['state']}" if r.get("attestation") else "")
        lines.append(f"| {r['pack']} | {r['control']} {r['title']} | {r['stage'] or ''} | {r['on_fail'] or ''} | "
                     f"{cov} | {r['source']} |")
    return "\n".join(lines) + "\n"


RANK = {"enforced": 3, "measured": 2, "attested": 1, "planned": 0}


def diff(base, head):
    """INT-3: -> [regressions]: a control removed, or moved to a weaker class (enforced > measured > attested > planned)."""
    b = {(r["pack"], r["control"]): r["coverage"] for r in base["rows"]}
    h = {(r["pack"], r["control"]): r["coverage"] for r in head["rows"]}
    out = [f"{p}:{c} was removed" for (p, c) in sorted(set(b) - set(h))]
    out += [f"{p}:{c} weakened from {b[(p, c)]} to {h[(p, c)]}" for (p, c) in sorted(set(b) & set(h))
            if RANK[h[(p, c)]] < RANK[b[(p, c)]]]
    return out
