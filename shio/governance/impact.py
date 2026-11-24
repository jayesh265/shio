"""Change-impact replay (D17): replay recorded decisions against a new model, program or policy version and list
exactly the decisions that flip.

Each record is re-run from its recorded inputs (shio.replay). With a new model, every read is answered by that model
instead of the recorded answer; with a new program, the current source decides; with new policies, the tables in
force are used. The outcome, the rules and the checks are compared with what was recorded. A decision flips when its
outcome changes; check changes are listed too, because a check that starts failing is an early warning even when the
outcome holds.

Nothing is written to the ledger: impact analysis is a question, not a decision.
"""
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..evidence import _outcome_label
from ..replay import replay_detail


@dataclass
class Item:
    file: str
    status: str                  # FLIPPED | UNCHANGED | CHECKS_CHANGED | NOT_REPLAYED
    recorded: object = None
    now: object = None
    diffs: list = field(default_factory=list)
    detail: str = ""

    def as_dict(self):
        return {"file": self.file, "status": self.status, "recorded": self.recorded, "now": self.now,
                "diffs": self.diffs, "detail": self.detail}


def _decided(outcome):
    """The decision itself: a PENDING outcome is judged by what was decided, waiting for a person."""
    if isinstance(outcome, dict) and outcome.get("status") == "PENDING" and "decided" in outcome:
        return outcome["decided"]
    return outcome


def run(records, model=None, models=None, program=None, policies=None, at=None, swap=None):
    """records: record file paths. model: answers every read. swap: {recorded model name: new model}, replacing only
    those models (an agent with an LLM and a detector swaps the LLM). -> {"items", "summary", "change"}."""
    items = []
    for path in records:
        path = Path(path)
        d = replay_detail(path, program, allow_changed=program is not None, policies=policies, at=at, model=model,
                          models=models, swap=swap)
        if not d["replayed"]:
            items.append(Item(path.name, "NOT_REPLAYED", detail="; ".join(d["lines"])))
            continue
        rec_out = _decided((d["recorded"] or {}).get("outcome"))
        if d.get("error"):
            items.append(Item(path.name, "FLIPPED", _outcome_label(rec_out), "error", [d["error"]],
                              "the agent failed under the change"))
            continue
        now_out = _decided(d["now"].get("outcome"))
        changed = json.dumps(rec_out, sort_keys=True, default=str) != json.dumps(now_out, sort_keys=True, default=str)
        status = "FLIPPED" if changed else ("CHECKS_CHANGED" if d["diffs"] else "UNCHANGED")
        items.append(Item(path.name, status, rec_out, now_out, [x.strip() for x in d["diffs"]]))
    summary = {s: sum(1 for i in items if i.status == s) for s in ("FLIPPED", "CHECKS_CHANGED", "UNCHANGED",
                                                                    "NOT_REPLAYED")}
    change = {"model": _ident(model), "models": {k: _ident(v) for k, v in (models or {}).items()} or None,
              "swap": {k: _ident(v) for k, v in (swap or {}).items()} or None,
              "program": str(program) if program else None, "policies": getattr(policies, "where", None)}
    return {"items": items, "summary": summary, "change": change, "records": len(items)}


def _ident(m):
    if m is None:
        return None
    from ..core import model_identity
    return model_identity(m)


def report(result):
    s = result["summary"]
    lines = [f"change-impact replay over {result['records']} recorded decisions: {s['FLIPPED']} flipped, "
             f"{s['CHECKS_CHANGED']} with changed checks, {s['UNCHANGED']} unchanged, {s['NOT_REPLAYED']} not replayed"]
    for i in result["items"]:
        if i.status == "FLIPPED":
            lines.append(f"  FLIPPED {i.file}: {_outcome_label(i.recorded)} -> {_outcome_label(i.now)}")
        elif i.status == "CHECKS_CHANGED":
            lines.append(f"  checks changed {i.file}: " + "; ".join(i.diffs[:3]))
        elif i.status == "NOT_REPLAYED":
            lines.append(f"  not replayed {i.file}: {i.detail[:160]}")
    return "\n".join(lines)


def as_json(result):
    return {**result, "items": [i.as_dict() for i in result["items"]]}
