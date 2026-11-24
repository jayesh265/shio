"""Promotion gate (med.change, D29): a model digest and program hash are pinned, and a release is promoted only after
a regression run of exactly that release passed and a person in the release role signed it off.

A release is what the agent card pins: the program's sha256, each model's pin, each pack's version and hash. Its
sha256 is what everything binds to:

  - the regression eval must name the release in its subject (program sha256 and models) and meet its gates;
  - the sign-off is an approval of subject "promotion" of the release's sha256 (maker-checker: not its owner);
  - the promotion itself is an entry in a signed chain (promotions.jsonl), so which release is live, since when
    and on whose authority, is tamper-evident.

promote() raises PromotionBlocked with every reason when any of this is missing. Nothing is promoted halfway.
"""
import datetime as dt

from ..ledger import sha256
from .assess import check_seal
from .chain import APPROVED, ApprovalLog, SignedChain

ROLES = ("release_manager",)


class PromotionBlocked(RuntimeError):
    def __init__(self, reasons):
        self.reasons = list(reasons)
        super().__init__("promotion blocked: " + "; ".join(self.reasons))


def release_of(card):
    """The release a card describes: program hash, model pins, pack versions."""
    models = {m["name"]: {k: m.get(k) for k in ("kind", "model", "name", "digest", "pinned", "declared") if m.get(k)}
              for m in card["models"]}
    rel = {"agent": card["name"], "program_sha256": card["program"]["sha256"], "models": models,
           "packs": {p["id"]: {"version": p["version"], "sha256": p["sha256"]} for p in card.get("packs", [])},
           "card_sha256": card["sha256"]}
    rel["sha256"] = sha256({k: v for k, v in rel.items() if k != "card_sha256"})
    return rel


def subject_of(card):
    """The subject an eval run of this release records (shio eval --card)."""
    rel = release_of(card)
    return {"release_sha256": rel["sha256"], "program_sha256": rel["program_sha256"], "models": rel["models"]}


def readiness(card, evals, approvals, roles=ROLES, public_key=None, secret=None):
    """-> (ready, reasons it is not, release)."""
    rel = release_of(card)
    reasons = []
    unpinned = [m["name"] for m in card["models"] if not m.get("pinned")]
    if unpinned:
        reasons.append(f"models not pinned: {', '.join(unpinned)}")
    runs = [e for e in evals if e.get("suite") == "regression"]
    if not runs:
        reasons.append("no regression run")
    else:
        matching = [e for e in runs if (e.get("subject") or {}).get("release_sha256") == rel["sha256"]]
        if not matching:
            reasons.append("no regression run of this release (the runs supplied evaluated a different program or "
                           "model)")
        else:
            latest = matching[-1]
            ok, problems = check_seal(latest, public_key, secret)
            if not ok:
                reasons.append("the regression run's result is not intact: " + "; ".join(problems))
            if latest.get("gate_failures"):
                reasons.append("the regression run did not meet its gates: " + "; ".join(latest["gate_failures"]))
            if latest.get("passed", 0) < latest.get("cases", 0) and not latest.get("gates"):
                reasons.append(f"the regression run failed {latest['cases'] - latest['passed']} cases")
    state, missing = ApprovalLog(approvals).status(rel["sha256"], list(roles))
    if state != APPROVED:
        reasons.append(f"sign-off {state.lower()}" + (f": needs {', '.join(missing)}" if missing else ""))
    return not reasons, reasons, rel


def approve(card, approvals, by, role="release_manager", meaning="release approved for promotion", signer=None,
            reject=False):
    rel = release_of(card)
    return ApprovalLog(approvals).record("promotion", rel["sha256"], by, role, meaning,
                                         "rejected" if reject else "approved", makers=[card.get("owner", "")],
                                         signer=signer, title=f"{card['name']} {rel['sha256'][:12]}")


def promote(card, evals, approvals, promotions, environment, by, roles=ROLES, signer=None, impact=None,
            public_key=None, secret=None):
    """Promote a release to an environment, or raise PromotionBlocked. -> the promotion entry."""
    ready, reasons, rel = readiness(card, evals, approvals, roles, public_key, secret)
    if not ready:
        raise PromotionBlocked(reasons)
    prev = current(promotions, card["name"], environment)
    body = {"agent": card["name"], "environment": environment, "release": rel, "by": by,
            "previous": prev["release"]["sha256"] if prev else None,
            "regression": [e.get("sha256") for e in evals if (e.get("subject") or {}).get("release_sha256") == rel["sha256"]
                           and e.get("suite") == "regression"][-1],
            "impact": impact.get("summary") if isinstance(impact, dict) else None,
            "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    return SignedChain(promotions, "promotions").append("promotion", body, signer)


def current(promotions, agent, environment):
    """The live release of an agent in an environment, or None."""
    live = [e for e in SignedChain(promotions, "promotions").entries()
            if e.get("agent") == agent and e.get("environment") == environment]
    return live[-1] if live else None
