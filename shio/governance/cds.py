"""med.cds: the build fails if an agent card contradicts its declared decision-support posture (D30).

This module does not decide whether software is a medical device. It enforces, at build time, the constraints a team
adopted when it declared a posture for an agent, so the agent as built can't drift away from what was declared. The
constraints are worded as enforcement; whether a posture is the right one is for regulatory counsel.

Posture "hcp-decision-support" (declared in the agent manifest's decision_support block) adopts these constraints:

  CDS-1 audience       the card's audience is a healthcare professional ("clinician"), not a patient
  CDS-2 inputs         no read takes a medical image or a physiological signal (image(...) sources, or inputs the
                       manifest declares as image, signal or waveform)
  CDS-3 oversight      every outcome needs a person's sign-off (requires_signoff "*"), by a clinical role
  CDS-4 basis          the professional can review the basis: the manifest says basis is shown, and a grounding
                       pack (med.grounding) is in force, so every claim carries its quote from the source
  CDS-5 not urgent     the agent is not declared time-critical
  CDS-6 no actions     the agent declares no acting tool, other than ones the posture lists as allowed
"""

POSTURES = {"hcp-decision-support"}
SIGNAL_INPUTS = {"image", "signal", "waveform", "ecg", "eeg", "imaging"}


def check_posture(card):
    """-> a list of violations (empty when the card fits its declared posture)."""
    ds = card.get("decision_support") or {}
    posture = ds.get("posture")
    if not posture:
        return []
    if posture not in POSTURES:
        return [f"unknown posture {posture!r} (known: {', '.join(sorted(POSTURES))})"]
    out = []
    clinical = set(ds.get("clinical_roles") or ["clinician"])
    if card.get("audience") != "clinician":
        out.append(f"CDS-1: the card's audience is {card.get('audience')!r}; this posture requires a healthcare "
                   f"professional (\"clinician\")")
    images = [s for s in card.get("sources", []) if "image(" in str(s.get("from") or "")]
    if images:
        out.append("CDS-2: " + ", ".join(f"{s['agent']}.{s['read']} (line {s['line']})" for s in images)
                   + " read an image")
    declared = SIGNAL_INPUTS & {str(i).lower() for i in ds.get("inputs", [])}
    if declared:
        out.append(f"CDS-2: the manifest declares {', '.join(sorted(declared))} inputs")
    if card.get("requires_signoff") != "*":
        out.append("CDS-3: every outcome must need sign-off (requires_signoff: \"*\")")
    if not clinical & set(card.get("signoff_roles", [])):
        out.append(f"CDS-3: no signoff by a clinical role ({', '.join(sorted(clinical))}); the program's sign-off "
                   f"roles are {', '.join(card.get('signoff_roles', [])) or 'none'}")
    if not ds.get("shows_basis"):
        out.append("CDS-4: the posture requires that the basis for each output is shown (shows_basis: true)")
    if not any(p["id"] == "med.grounding" for p in card.get("packs", [])):
        out.append("CDS-4: med.grounding is not in force, so claims are not tied to quotes the professional can check")
    if ds.get("time_critical"):
        out.append("CDS-5: the agent is declared time-critical")
    allowed = set(ds.get("allowed_actions", []))
    acting = [t["name"] for t in card.get("tools", []) if t["mode"] == "acts" and t["name"] not in allowed]
    if acting:
        out.append(f"CDS-6: acting tools {', '.join(acting)} are not allowed under this posture")
    return out
