"""Re-run a recorded decision and show it comes out the same.

The program is loaded again (its sha256 must match the record, unless changed programs are allowed, which turns
replay into impact analysis: "what would the current rules have decided?"). Every model call is answered with the
raw answer the record holds, matched by the read's name and key in order, and every input is rebuilt from the
record. Then the checks, rules and outcome are compared with what was recorded.
"""
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import datetime as dt

from . import core
from .core import Source
from .ledger import load_vault, merge
from .policy import PolicyError


class Divergence(Exception):
    pass


class RecordedModel:
    """Answers each read with the raw answer the record holds for it."""

    def __init__(self, record):
        self.name = "replay of record"
        self.queues = defaultdict(list)
        for r in sorted(_all(record, "readings"), key=lambda r: (r.get("seq") is None, r.get("seq") or 0)):
            self.queues[(r["name"], json.dumps(r["request"].get("meta", {}).get("key"), default=str))].append(r)
        self.used = 0

    def identity(self):
        return {"kind": "replay", "name": self.name}

    def propose(self, req):
        q = self.queues.get((req.name, json.dumps(req.meta.get("key"), default=str)))
        if not q:
            raise Divergence(f"the program asked for a read '{req.name}' (key {req.meta.get('key')!r}) "
                             "that the record does not have")
        r = q.pop(0)
        self.used += 1
        if r.get("raw") is None:            # the model call failed when recorded: fail the same way
            raise RuntimeError(r.get("error") or "no answer was recorded")
        return r["raw"]


def _all(run, field):
    out = list(run.get(field, []))
    for c in run.get("children", []):
        out += _all(c, field)
    return out


def _decode(x, model):
    if isinstance(x, list):
        return [_decode(v, model) for v in x]
    if isinstance(x, dict):
        if "$source" in x:
            return Source(**x["$source"])
        if "$model" in x:            # model may pick per recorded identity (change-impact swaps one model, not all)
            return model(x["$model"]) if callable(model) and not hasattr(model, "propose") else model
        if "$tuple" in x:
            return tuple(_decode(v, model) for v in x["$tuple"])
        if "$dict" in x:
            return {_decode(k, model): _decode(v, model) for k, v in x["$dict"]}
        if "$opaque" in x:
            raise Divergence(f"an input was not recordable ({x['$opaque'][:80]}), so this decision cannot be replayed")
        if "$vault" in x:
            raise Divergence("the record's inputs are in a vault that has been erased")
        return {k: _decode(v, model) for k, v in x.items()}
    return x


def _summary(run):
    checks = [(c["name"], json.dumps(c.get("key"), default=str), c["passed"], bool(c.get("skipped")))
              for c in _all(run, "checks")]
    rules = [(r["name"], json.dumps(r.get("key"), default=str), json.dumps(r["outcome"], sort_keys=True, default=str))
             for r in _all(run, "rules")]
    return checks, rules, json.dumps(run.get("outcome"), sort_keys=True, default=str)


def _dropped_classes(node):
    """Classes of the fields a record holds only as a drop marker."""
    if isinstance(node, dict):
        if "$dropped" in node:
            yield node.get("class")
            return
        for v in node.values():
            yield from _dropped_classes(v)
    elif isinstance(node, list):
        for v in node:
            yield from _dropped_classes(v)


def replay(record_path, program=None, allow_changed=False, policies=None, at=None, jurisdiction=None):
    """-> (reproduced: bool, report lines). Decision tables come from the record (the values it used), unless
    `policies` (a policy.Store) is given: then the tables in force on `at` (default: the decision's date) are used,
    for the record's jurisdiction (or `jurisdiction`, to see what another regulator's limits would have decided),
    which shows what a proposed or new limit would have decided."""
    d = replay_detail(record_path, program, allow_changed, policies, at, jurisdiction)
    return d["reproduced"], d["lines"]


def _failed(lines, record=None):
    return {"reproduced": False, "replayed": False, "lines": lines, "recorded": record, "now": None, "diffs": []}


def replay_detail(record_path, program=None, allow_changed=False, policies=None, at=None, jurisdiction=None,
                  model=None, models=None, swap=None):
    """replay(), as data: {reproduced, replayed, lines, recorded, now, diffs}. replayed is False when the decision
    could not be re-run at all (an erased vault, a missing program...).

    model: answer every read with this model instead of the recorded answers (an agent's model parameters become it),
    which is change-impact analysis for a new model. models: {name: model} replaces models the program declares at
    the top level (`model clerk = ...`). swap: {recorded model name: new model} replaces only the agent inputs whose
    recorded identity has that name (its "model" or "name"); the other models answer from the record."""
    from . import load
    record_path = Path(record_path)
    record = json.loads(record_path.read_text())
    if record.get("vault"):
        vault = load_vault(record_path, record)
        if vault is None:
            return _failed([f"{record_path.name}: its vault was erased, so the model's answers are gone; "
                            "the record still shows what was decided and why"])
        record = merge(record, vault)
    dropped = sorted({c for c in _dropped_classes(record)})
    if dropped:
        return _failed([f"{record_path.name}: {', '.join(dropped)} {'was' if len(dropped) == 1 else 'were'} dropped "
                        "under the data policy (written nowhere), so the inputs and the model's answers cannot be "
                        "rebuilt; the record still shows what was decided and why"], record)
    prog = record.get("program") or {}
    path = Path(program or prog.get("path", ""))
    if not path.exists():
        return _failed([f"program {path} not found; pass --program"], record)
    sha = hashlib.sha256(path.read_text().encode()).hexdigest()
    changed = sha != prog.get("sha256")
    if changed and not allow_changed:
        return _failed([f"{path.name} has changed since this decision (sha256 {sha[:12]} now, "
                        f"{str(prog.get('sha256'))[:12]} recorded); pass --allow-changed to see what the current "
                        "program would decide"], record)
    mod = load(path)
    fn = getattr(mod, record["agent"], None)
    if fn is None:
        return _failed([f"agent {record['agent']} is not in {path.name}"], record)
    recorded_model = RecordedModel(record)
    answering = model if model is not None else recorded_model
    if swap:
        def answering(ident, _swap=dict(swap), _default=answering):
            return _swap.get((ident or {}).get("model") or (ident or {}).get("name"), _default)
    try:
        args = _decode(record["inputs"].get("args", []), answering)
        kwargs = _decode(record["inputs"].get("kwargs", {}), answering)
    except Divergence as e:
        return _failed([str(e)], record)
    for name, m in (models or {}).items():
        if not hasattr(mod, name):
            return _failed([f"{path.name} declares no model {name!r} to replace"], record)
        setattr(mod, name, m)
    saved = {k: core._config.get(k) for k in ("table_override", "as_of", "policies", "jurisdiction")}
    scope = jurisdiction or record.get("jurisdiction")
    if policies is not None:
        try:
            scope = policies.require_jurisdiction(scope, f"replaying {record_path.name} under {policies.where or 'them'}")
        except PolicyError as e:
            return _failed([str(e)], record)
    core._config["jurisdiction"] = scope
    if policies is None:
        core._config["table_override"] = {t["name"]: {"stamp": {k: v for k, v in t.items() if k != "used"},
                                                      "rows": t.get("used") or {}}
                                          for t in record.get("tables") or []}
    else:
        core._config["table_override"] = None
        core._config["policies"] = policies
        core._config["as_of"] = at or dt.date.fromtimestamp(record.get("started") or 0)
    as_of = core._config["as_of"]
    fn.replaying = True
    try:
        fn(*args, **kwargs)
    except Divergence as e:
        return _failed([f"diverged: {e}"], record)
    except PolicyError as e:
        return _failed([f"diverged: {e} (the program now reads a table value the decision did not)"], record)
    except Exception as e:           # a new model or program that crashes the agent: that is the impact
        return {**_failed([f"the agent raised {type(e).__name__}: {e}"], record), "replayed": True,
                "error": f"{type(e).__name__}: {e}"}
    finally:
        fn.replaying = False
        core._config.update(saved)
    now = json.loads(json.dumps(core.last_run["run"].to_dict(), default=str))
    (c0, r0, o0), (c1, r1, o1) = _summary(record), _summary(now)
    used = {t["name"]: t for t in now.get("tables") or []}
    table_note = [f"  table {t['name']!r}: recorded v{t['version']}, now v{used[t['name']]['version']}"
                  for t in record.get("tables") or [] if t["name"] in used and used[t["name"]]["version"] != t["version"]]
    lines = [f"replayed {record_path.name} with {path.name}" + (" (CHANGED since the decision)" if changed else "")
             + (f" under the policies in force on {as_of}" + (f" for {scope}" if scope else "")
                if policies is not None else ""),
             (f"  {recorded_model.used} recorded model answers used" if model is None and not swap else
              f"  answered by {', '.join(sorted(swap)) + ' swapped' if swap else getattr(model, 'name', type(model).__name__)}"
              f" instead of the recorded answers")
             + f", {len(c1)} checks, {len(r1)} rules"] + table_note
    diffs = []
    if c0 != c1:
        for a, b in zip(c0, c1):
            if a != b:
                diffs.append(f"  check {a[0]}[{a[1]}]: recorded passed={a[2]}, now passed={b[2]}")
        if len(c0) != len(c1):
            diffs.append(f"  {len(c0)} checks recorded, {len(c1)} now")
    if r0 != r1:
        for a, b in zip(r0, r1):
            if a != b:
                diffs.append(f"  rule {a[0]}[{a[1]}]: recorded {a[2][:120]}, now {b[2][:120]}")
    if o0 != o1:
        diffs.append(f"  outcome: recorded {o0[:200]}, now {o1[:200]}")
    leftover = sum(len(q) for q in recorded_model.queues.values()) if model is None and not swap else 0
    if leftover:
        diffs.append(f"  {leftover} recorded model answers were not asked for")
    lines += diffs or ["  REPRODUCED: same checks, same rules, same outcome"]
    return {"reproduced": not diffs, "replayed": True, "lines": lines, "recorded": record, "now": now,
            "diffs": diffs, "outcome_changed": o0 != o1}
