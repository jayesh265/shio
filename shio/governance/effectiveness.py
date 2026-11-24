"""Control effectiveness from reviewer labels (D18): for each check, how often it blocked, how often reviewers
overturned the block, and its precision.

A reviewer labels a recorded decision right or wrong (`shio label`). A label's note may name the checks it is about
(`checks: claims_quoted, figures_in_source`); otherwise it is about every check that failed in that decision.

Per check (agent.check):
  runs         times it ran (not skipped)
  blocked      times it failed
  upheld       blocked, in a decision a reviewer labelled right (the block was correct)
  overturned   blocked, in a decision a reviewer labelled wrong (a false alarm)
  precision    upheld / (upheld + overturned), when any block was labelled
  missed       passed, in a decision labelled wrong where the label names this check (it should have caught it)
  unlabelled   blocks no reviewer has looked at yet
"""
import json
import re
from collections import defaultdict
from pathlib import Path

from ..ledger import _entries, labels

NAMED = re.compile(r"(?i)\bchecks?\s*[:=]\s*([\w ,.-]+)")


def _named(note):
    m = NAMED.search(note or "")
    return {x.strip() for x in m.group(1).split(",") if x.strip()} if m else None


def _runs(run):
    yield run
    for c in run.get("children", []):
        yield from _runs(c)


def measure(folder):
    """-> {"checks": {name: {...}}, "decisions": n, "labelled": n}."""
    folder = Path(folder)
    verdicts = {f: ls[-1] for f, ls in labels(folder).items()}       # the current label of each record
    stats = defaultdict(lambda: {"runs": 0, "blocked": 0, "upheld": 0, "overturned": 0, "missed": 0, "unlabelled": 0,
                                 "controls": set()})
    decisions = labelled = 0
    for e in _entries(folder):
        if e.get("kind") != "record" or not (folder / e["file"]).exists():
            continue
        rec = json.loads((folder / e["file"]).read_text())
        if rec.get("record_type", "decision") != "decision":
            continue
        decisions += 1
        lab = verdicts.get(e["file"])
        labelled += lab is not None
        named = _named(lab.get("note")) if lab else None
        for run in _runs(rec):
            for c in run.get("checks", []):
                if c.get("skipped") or not c.get("reward", True):
                    continue
                key = f"{run.get('agent')}.{c['name']}"
                s = stats[key]
                s["runs"] += 1
                s["controls"].update(c.get("controls", []))
                about = named is None or c["name"] in named or key in named
                if not c["passed"]:
                    s["blocked"] += 1
                    if lab is None or not about:
                        s["unlabelled"] += 1
                    elif lab["verdict"] == "right":
                        s["upheld"] += 1
                    else:
                        s["overturned"] += 1
                elif lab is not None and lab["verdict"] == "wrong" and named is not None and about:
                    s["missed"] += 1
    out = {}
    for key, s in sorted(stats.items()):
        judged = s["upheld"] + s["overturned"]
        out[key] = {**{k: v for k, v in s.items() if k != "controls"}, "controls": sorted(s["controls"]),
                    "precision": round(s["upheld"] / judged, 4) if judged else None,
                    "block_rate": round(s["blocked"] / s["runs"], 4) if s["runs"] else None}
    return {"checks": out, "decisions": decisions, "labelled": labelled}


def report(m):
    lines = [f"control effectiveness over {m['decisions']} decisions ({m['labelled']} labelled by reviewers)",
             f"  {'check':<44} {'runs':>5} {'blocked':>8} {'upheld':>7} {'overturned':>10} {'precision':>9}"]
    for name, s in m["checks"].items():
        p = f"{s['precision']:.0%}" if s["precision"] is not None else "-"
        lines.append(f"  {name:<44} {s['runs']:>5} {s['blocked']:>8} {s['upheld']:>7} {s['overturned']:>10} {p:>9}")
    return "\n".join(lines)
