"""The eval harness (D14): subgroup slices, regression suites and red-team suites, in CI.

A suite is a JSON file:

    {"format": "shio-eval-suite/1", "suite": "regression", "target": "module:function",
     "slices": ["sex", "age_band", "site"],
     "metrics": [{"name": "pass_rate"}, {"name": "max_slice_gap", "min_n": 3},
                 {"name": "hallucination_caught", "kind": "label_rate", "label": "hallucinated",
                  "field": "rejected", "value": true}],
     "gates": {"pass_rate": [">=", 0.95]},
     "cases": [{"id": "...", "input": {...}, "expect": {"status": "REVIEW"}, "slices": {"sex": "F"},
                "labels": {"good": true}}]}

The target is called with each case's input and returns an outcome (a dict). A case passes when every key in its
expect matches the outcome (dotted paths reach into nested dicts). Metrics are computed over all cases and per slice;
a run fails if a gate is not met, or, against a baseline result, if a metric falls by more than the tolerance or a
case that passed now fails.

Red-team suites are derived from packs: every adversarial fixture of every runtime check becomes a case, so a pack's
own attacks run in CI against the pack's code (derive_redteam). Agent-level red-team suites (a referral letter with
hidden instructions) are ordinary suites with suite "redteam".

Results are sealed (hashed, and signed with the ledger's key) so an evidence bundle can attach them.
"""
import abc
import datetime as dt
import importlib
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .assess import seal

FORMAT, SUITE_FORMAT = "shio-eval/1", "shio-eval-suite/1"
OPS = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b, ">": lambda a, b: a > b, "<": lambda a, b: a < b,
       "==": lambda a, b: a == b}
LOWER_IS_BETTER = {"max_slice_gap", "wrongful_rejection", "failure_rate"}


class EvalError(ValueError):
    pass


@dataclass(frozen=True)
class Case:
    id: str
    input: dict
    expect: dict = field(default_factory=dict)
    slices: dict = field(default_factory=dict)
    labels: dict = field(default_factory=dict)
    origin: str = ""


@dataclass
class CaseResult:
    case: Case
    outcome: object
    passed: bool
    detail: str = ""


def _get(obj, path):
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        else:
            obj = getattr(obj, part, None)
    return obj


def matches(expect, outcome):
    """-> (passed, why). Every expected key (a dotted path) equals the outcome's value there."""
    for k, want in expect.items():
        got = _get(outcome, k)
        if got != want:
            return False, f"{k}: expected {want!r}, got {got!r}"
    return True, ""


# ---------------- metrics (strategies) ----------------
class Metric(abc.ABC):
    def __init__(self, name, **params):
        self.name, self.params = name, params

    @abc.abstractmethod
    def compute(self, results):
        """-> float or None (None: not computable on these results)."""


class PassRate(Metric):
    def compute(self, results):
        return sum(r.passed for r in results) / len(results) if results else None


class FailureRate(Metric):
    def compute(self, results):
        return 1 - sum(r.passed for r in results) / len(results) if results else None


class MaxSliceGap(Metric):
    """The largest difference in pass rate between two values of any slice attribute (each with at least min_n
    cases): how unevenly the agent performs across subgroups."""

    def compute(self, results):
        min_n = self.params.get("min_n", 3)
        gap = 0.0
        for attr, groups in slice_rates(results).items():
            rates = [g["pass_rate"] for g in groups.values() if g["n"] >= min_n]
            if len(rates) >= 2:
                gap = max(gap, max(rates) - min(rates))
        return round(gap, 6)


class LabelRate(Metric):
    """Of the cases labelled `label` (true), the share whose outcome has `field` == `value`. E.g. hallucinated cases
    the checks rejected (a catch rate), or good cases they rejected (a wrongful-rejection rate)."""

    def compute(self, results):
        label, fld, value = self.params["label"], self.params["field"], self.params.get("value", True)
        pool = [r for r in results if r.case.labels.get(label)]
        if not pool:
            return None
        return sum(1 for r in pool if _get(r.outcome, fld) == value) / len(pool)


METRICS = {"pass_rate": PassRate, "failure_rate": FailureRate, "max_slice_gap": MaxSliceGap, "label_rate": LabelRate}


def metric(spec):
    kind = spec.get("kind", spec["name"])
    if kind not in METRICS:
        raise EvalError(f"unknown metric kind {kind!r} (known: {', '.join(METRICS)})")
    return METRICS[kind](spec["name"], **{k: v for k, v in spec.items() if k not in ("name", "kind")})


def slice_rates(results, attrs=None):
    """{attribute: {value: {n, passed, pass_rate}}}."""
    out = defaultdict(lambda: defaultdict(lambda: {"n": 0, "passed": 0}))
    for r in results:
        for attr, value in r.case.slices.items():
            if attrs is None or attr in attrs:
                g = out[attr][str(value)]
                g["n"] += 1
                g["passed"] += int(r.passed)
    return {a: {v: {**g, "pass_rate": round(g["passed"] / g["n"], 6)} for v, g in sorted(vs.items())}
            for a, vs in sorted(out.items())}


# ---------------- suites ----------------
@dataclass
class Suite:
    name: str
    cases: list
    target: str = None
    metrics: list = field(default_factory=lambda: [{"name": "pass_rate"}])
    slices: list = field(default_factory=list)
    gates: dict = field(default_factory=dict)
    path: Path = None

    @classmethod
    def load(cls, path):
        path = Path(path)
        d = json.loads(path.read_text())
        if d.get("format") != SUITE_FORMAT:
            raise EvalError(f"{path}: format must be {SUITE_FORMAT!r}")
        ids = [c["id"] for c in d["cases"]]
        dup = sorted({i for i in ids if ids.count(i) > 1})
        if dup:
            raise EvalError(f"{path}: case ids used twice: {', '.join(dup)}")
        cases = [Case(c["id"], c.get("input", {}), c.get("expect", {}), c.get("slices", {}), c.get("labels", {}),
                      c.get("origin", "")) for c in d["cases"]]
        return cls(d["suite"], cases, d.get("target"), d.get("metrics") or [{"name": "pass_rate"}],
                   d.get("slices", []), d.get("gates", {}), path)


def resolve_target(ref, base=None):
    """'module:function' -> the function. The module is looked for next to the suite file, then in the folder above
    it (suites usually sit in an evals/ folder beside the code they test), then on the normal import path."""
    if callable(ref):
        return ref
    if not ref:
        raise EvalError("the suite names no target and none was given (--target module:function)")
    mod, _, fn = ref.partition(":")
    for folder in ([Path(base), Path(base).parent] if base is not None else []):
        if (folder / f"{mod.split('.')[0]}.py").exists() or (folder / mod.split(".")[0]).is_dir():
            if str(folder.resolve()) not in sys.path:
                sys.path.insert(0, str(folder.resolve()))
            break
    obj = importlib.import_module(mod)
    for part in fn.split("."):
        obj = getattr(obj, part)
    return obj


def run(suite, target=None, signer=None, subject=None):
    """Run a suite. -> the sealed result. subject: what was evaluated ({"program_sha256", "models", "card_sha256"}),
    which binds the result to one release, so a promotion can require a run of exactly what it promotes."""
    from .. import __version__
    fn = resolve_target(target or suite.target, suite.path.parent if suite.path else None)
    results = []
    for case in suite.cases:
        try:
            outcome = fn(case.input)
            ok, why = matches(case.expect, outcome)
        except Exception as e:           # a target that crashes on a case has failed that case
            outcome, ok, why = {"error": f"{type(e).__name__}: {e}"}, False, f"raised {type(e).__name__}: {e}"
        results.append(CaseResult(case, outcome, ok, why))
    metrics = {}
    for spec in suite.metrics:
        v = metric(spec).compute(results)
        if v is not None:
            metrics[spec["name"]] = round(v, 6)
    gates, gate_fail = {}, []
    for name, (op, thr) in suite.gates.items():
        v = metrics.get(name)
        ok = v is not None and OPS[op](v, thr)
        gates[name] = {"op": op, "threshold": thr, "value": v, "ok": ok}
        if not ok:
            gate_fail.append(f"{name} = {v} (needs {op} {thr})")
    doc = {"format": FORMAT, "suite": suite.name, "shio": __version__,
           "target": target if isinstance(target, str) else (suite.target or getattr(fn, "__qualname__", "?")),
           "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
           "cases": len(results), "passed": sum(r.passed for r in results), "metrics": metrics,
           "slices": slice_rates(results, suite.slices or None), "gates": gates, "gate_failures": gate_fail,
           "results": [{"id": r.case.id, "passed": r.passed, "detail": r.detail, "slices": r.case.slices,
                        "origin": r.case.origin} for r in results]}
    if subject:
        doc["subject"] = subject
    return seal(doc, signer)


def compare(result, baseline, tolerance=0.0):
    """-> [regressions]: metrics that moved the wrong way by more than tolerance, and cases that passed in the
    baseline and fail now."""
    out = []
    for name, base in baseline.get("metrics", {}).items():
        now = result.get("metrics", {}).get(name)
        if now is None:
            out.append(f"metric {name}: in the baseline ({base}) but not computed now")
            continue
        worse = (now - base) if name in LOWER_IS_BETTER else (base - now)
        if worse > tolerance:
            out.append(f"metric {name}: {base} -> {now}")
    before = {r["id"]: r["passed"] for r in baseline.get("results", [])}
    for r in result.get("results", []):
        if before.get(r["id"]) and not r["passed"]:
            out.append(f"case {r['id']}: passed in the baseline, fails now ({r['detail']})")
    return out


# ---------------- red-team cases from packs ----------------
def derive_redteam(*pack_refs):
    """A red-team suite from packs: every adversarial fixture of every runtime check, as a case whose target runs that
    check (pack_check_target). Cases are named pack/check/fixture, so a failure says exactly which attack got through."""
    from .packs import _fixture_cases, read, resolve
    cases = []
    for ref in pack_refs:
        pack = read(resolve(ref))
        for c in pack.controls:
            for p in c.proofs_of("runtime"):
                if p.param("pack"):
                    continue
                fixtures, _ = _fixture_cases(pack, p.target, p)
                for f in fixtures or []:
                    if f.get("kind") != "adversarial":
                        continue
                    cid = f"{pack.id}/{p.target}/{f['id']}"
                    if any(x.id == cid for x in cases):
                        continue
                    cases.append(Case(cid, {"pack": str(pack.path), "check": p.target, "args": f.get("args", []),
                                            "kwargs": f.get("kwargs", {})}, {"passed": f.get("expect")},
                                      {"pack": pack.id, "control": c.id}, {}, f"{pack.label()} {c.id}"))
    return Suite("redteam", cases, None, [{"name": "pass_rate"}], ["pack"], {"pass_rate": [">=", 1.0]})


def pack_check_target(inp):
    """The target for derived red-team cases: run the named check of the named pack."""
    from .packs import load_pack
    rt = load_pack(inp["pack"])
    return {"passed": getattr(rt, inp["check"])(*inp["args"], **inp["kwargs"]).passed}


def report(result, regressions=()):
    lines = [f"eval {result['suite']}: {result['passed']}/{result['cases']} cases passed"]
    lines += [f"  {k}: {v}" for k, v in result["metrics"].items()]
    for attr, groups in result["slices"].items():
        lines.append(f"  by {attr}: " + ", ".join(f"{v} {g['pass_rate']:.0%} (n={g['n']})" for v, g in groups.items()))
    lines += [f"  FAILED case {r['id']}: {r['detail']}" for r in result["results"] if not r["passed"]][:20]
    lines += [f"  GATE NOT MET: {g}" for g in result["gate_failures"]]
    lines += [f"  REGRESSION: {r}" for r in regressions]
    return "\n".join(lines)
