"""shio assess: static controls and control proofs (D8).

A control proof is a property shown for every code path of one program hash, by analysing the program the compiler
produced, independently of the compiler's own checks (so a compiler bug that let something through would show here).
Each proof states its scope: it holds for the Shio code of that program; Python modules the program imports are
trusted and not analysed, and are listed with their hashes so a reviewer knows exactly what was trusted.

Proofs (each a StaticProof registered by id; packs name them in `lint` proofs):

  readings-through-rules  a model's reading reaches an action or an agent's result only through a check, a when or a
                          rule: in every agent body, every use of a reading is an argument to one of those, to a later
                          read's `seeing` context, or to the loop that splits it into items
  tools-gated             every `acts` tool call is inside a rule (so it goes through the gate)
  models-pinned           every read's model is pinned to an exact version: a declared model with digest=/pinned=, or
                          an agent parameter the agent manifest pins for the deployment (replay models count as
                          simulated, and the result says so)
  regulated-mode          the program declares `regulated`, so it compiled under the regulated scan and, at run time,
                          refuses to run unrecorded, unsigned or with an unpinned model
  signoff-required        the outcomes the agent manifest says need a person are covered by an unconditional signoff
  no-reflection           no reflection routes (locals, getattr on frames, ...) anywhere in the compiled program
  pack-wired              every runtime check of every pack the manifest names is called from a check in the program

For each proof there are negative tests (tests/test_governance_assess.py): the proof fails when the program breaks it.
"""
import abc
import ast
import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

PROVEN, FAILED, NOT_APPLICABLE = "PROVEN", "FAILED", "NOT_APPLICABLE"
FORMAT = "shio-assessment/1"
GATED_CALLS = ("__shio_check_", "__shio_when_", "__shio_rule_")


@dataclass
class Finding:
    line: int
    message: str


@dataclass
class ProofResult:
    proof: str
    status: str
    findings: list = field(default_factory=list)
    covered: int = 0             # sites the proof examined (reads, reading uses, tool calls...)
    notes: list = field(default_factory=list)

    def as_dict(self):
        return {"proof": self.proof, "status": self.status, "covered": self.covered, "notes": self.notes,
                "findings": [{"line": f.line, "message": f.message} for f in self.findings]}


class Program:
    """A compiled .shio program, as the proofs see it: source, hash, the compiler's map, the compiled Python and its
    AST with each node's .shio line."""

    def __init__(self, path, source, py, lines, meta):
        self.path, self.source, self.py, self.lines, self.meta = Path(path), source, py, lines, meta
        self.sha256 = hashlib.sha256(source.encode()).hexdigest()
        self.tree = ast.parse(py)
        self.parents = {}
        for node in ast.walk(self.tree):
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node

    @classmethod
    def load(cls, path):
        from ..compiler import _compile
        path = Path(path)
        src = path.read_text()
        py, lines, c = _compile(src, str(path))
        return cls(path, src, py, lines, c.meta)

    @classmethod
    def from_python(cls, py, meta=None, path="<python>", source=None):
        """For negative tests: a compiled program edited by hand, to show a proof catches what the compiler would."""
        return cls(path, source if source is not None else py, py, [0] * (py.count("\n") + 2),
                   meta or {"agents": [], "models": [], "tools": [], "regulated": False, "types": [], "codes": {}})

    def line(self, node):
        n = getattr(node, "lineno", 0)
        return self.lines[n - 1] if 0 < n <= len(self.lines) and self.lines[n - 1] else n

    def agents(self):
        """The compiled agent functions (decorated with __shio.agent)."""
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    "__shio.agent" in ast.unparse(d) for d in node.decorator_list):
                yield node

    def functions(self, prefix):
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(prefix):
                yield node

    def enclosing_function(self, node):
        while node in self.parents:
            node = self.parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
        return None

    def dependencies(self):
        from .. import program_identity
        return program_identity(self.path, self.source).get("dependencies", {}) if self.path.exists() else {}


def _call_name(call):
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f"{ast.unparse(f.value)}.{f.attr}"
    return ""


def _is_read(value):
    if isinstance(value, ast.Await):
        value = value.value
    return isinstance(value, ast.Call) and _call_name(value) in ("__shio.read", "__shio.aread", "__shio.core.read")


# ---------------- proofs ----------------
PROOFS = {}


class StaticProof(abc.ABC):
    id = None
    title = None
    scope = ("Holds for the Shio code of this program hash on every path through its compiled agents, checks and "
             "rules. Imported Python modules are trusted, not analysed, and listed with their hashes.")

    @abc.abstractmethod
    def prove(self, program, manifest):
        """-> ProofResult"""

    def result(self, status, findings=(), covered=0, notes=()):
        return ProofResult(self.id, status, list(findings), covered, list(notes))


def proof(cls):
    PROOFS[cls.id] = cls()
    return cls


def _reading_names(fn):
    names = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and _is_read(node.value):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        elif isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(node.iter, ast.Call) and \
                _call_name(node.iter) == "__shio.each":
            names |= {n.id for n in ast.walk(node.target) if isinstance(n, ast.Name)}
    return names


@proof
class ReadingsThroughRules(StaticProof):
    id = "readings-through-rules"
    title = "A model's reading reaches actions and results only through checks and rules"

    def prove(self, program, manifest):
        findings, covered = [], 0
        for fn in program.agents():
            readings = _reading_names(fn)
            for node in ast.walk(fn):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in readings:
                    covered += 1
                    why = self._judge(program, node, readings)
                    if why:
                        findings.append(Finding(program.line(node), f"agent {fn.name}: reading '{node.id}' {why}"))
        if not covered and not any(True for _ in program.agents()):
            return self.result(NOT_APPLICABLE, notes=["the program has no agents"])
        return self.result(FAILED if findings else PROVEN, findings, covered)

    @staticmethod
    def _judge(program, name, readings):
        """None if this use of a reading is one the boundary allows, else what is wrong with it."""
        node, parent = name, program.parents.get(name)
        if isinstance(parent, ast.Call) and node in parent.args:          # f(r)
            call = _call_name(parent)
            if call.startswith(GATED_CALLS) or call == "__shio.each":
                return None
            return f"is passed to {call or 'a call'}() outside a check or rule"
        if isinstance(parent, ast.keyword):
            call = program.parents.get(parent)
            cname = _call_name(call) if isinstance(call, ast.Call) else ""
            if cname.startswith(GATED_CALLS):
                return None
            return f"is passed as {parent.arg}= to {cname or 'a call'}() outside a check or rule"
        if isinstance(parent, ast.Dict) and node in parent.values:        # context={'r': r} of a later read
            kw = program.parents.get(parent)
            call = program.parents.get(kw)
            if isinstance(kw, ast.keyword) and kw.arg == "context" and isinstance(call, ast.Call) and _is_read(call):
                return None
        if isinstance(parent, ast.Tuple) and isinstance(program.parents.get(parent), (ast.For, ast.AsyncFor)):
            return None if all(isinstance(e, ast.Name) and e.id in readings for e in parent.elts) else \
                "is mixed with plain values in a loop"
        return f"is used in plain code ({type(parent).__name__.lower()}: {ast.unparse(parent)[:60]})"


@proof
class ToolsGated(StaticProof):
    id = "tools-gated"
    title = "Every acting tool call is made from a rule, through the gate"

    def prove(self, program, manifest):
        acts = {t["name"] for t in program.meta.get("tools", []) if t.get("mode") == "acts"}
        if not acts:
            return self.result(NOT_APPLICABLE, notes=["the program declares no acts tools"])
        findings, covered = [], 0
        for node in ast.walk(program.tree):
            if isinstance(node, ast.Call) and _call_name(node) == "__shio.tool_call" and len(node.args) >= 2 and \
                    isinstance(node.args[1], ast.Constant) and node.args[1].value in acts:
                covered += 1
                fn = program.enclosing_function(node)
                if fn is None or not fn.name.startswith("__shio_rule_"):
                    findings.append(Finding(program.line(node), f"acts tool {node.args[1].value} is called from "
                                                                f"{fn.name if fn else 'module level'}, not a rule"))
        return self.result(FAILED if findings else PROVEN, findings, covered)


def _pinned_expr(expr):
    return "digest=" in expr or "pinned=" in expr


@proof
class ModelsPinned(StaticProof):
    id = "models-pinned"
    title = "Every model call is to a model pinned to an exact version"

    def prove(self, program, manifest):
        declared = {m["name"]: m["expr"] for m in program.meta.get("models", [])}
        pins = (manifest or {}).get("models", {})
        findings, notes, covered, simulated = [], [], 0, set()
        for fn in program.agents():
            params = {a.arg for a in fn.args.args + fn.args.kwonlyargs}
            for node in ast.walk(fn):
                if not (isinstance(node, ast.Call) and _call_name(node) in ("__shio.read", "__shio.aread")):
                    continue
                covered += 1
                by = next((k.value for k in node.keywords if k.arg == "by"), None)
                where = program.line(node)
                while isinstance(by, ast.Call) and len(by.args) == 1 and not by.keywords and \
                        isinstance(by.func, ast.Name) and by.func.id not in declared:
                    notes.append(f"agent {fn.name}: the model is wrapped by {by.func.id}(), which passes on the "
                                 f"wrapped model's identity; the pin is the wrapped model's")
                    by = by.args[0]       # a wrapper such as a PHI gate: the model inside is what must be pinned
                if isinstance(by, ast.Name) and by.id in declared:
                    expr = declared[by.id]
                    if expr.startswith("replay("):
                        simulated.add(by.id)
                    elif not _pinned_expr(expr):
                        findings.append(Finding(where, f"agent {fn.name}: model {by.id} = {expr[:60]} has no "
                                                       f"digest= or pinned="))
                elif isinstance(by, ast.Name) and by.id in params:
                    pin = pins.get(by.id)
                    if not pin:
                        findings.append(Finding(where, f"agent {fn.name}: model parameter '{by.id}' is not pinned in "
                                                       f"the agent manifest (models.{by.id})"))
                    elif pin.get("kind") == "replay":
                        simulated.add(by.id)
                    elif not (pin.get("digest") or pin.get("pinned")):
                        findings.append(Finding(where, f"agent {fn.name}: models.{by.id} in the manifest has no "
                                                       f"digest or pinned version"))
                else:
                    findings.append(Finding(where, f"agent {fn.name}: the model of this read "
                                                   f"({ast.unparse(by) if by is not None else 'none'}) can't be "
                                                   f"traced to a pinned declaration"))
        if simulated:
            notes.append(f"SIMULATED: {', '.join(sorted(simulated))} {'is a replay' if len(simulated) == 1 else 'are replays'}"
                         f" (mock models): pinned by construction, not a real model")
        if not covered:
            return self.result(NOT_APPLICABLE, notes=["the program makes no model calls"])
        return self.result(FAILED if findings else PROVEN, findings, covered, notes)


@proof
class RegulatedMode(StaticProof):
    id = "regulated-mode"
    title = "The program runs in regulated mode"

    def prove(self, program, manifest):
        if program.meta.get("regulated"):
            return self.result(PROVEN, covered=1, notes=["compiled under the regulated scan; at run time every "
                                                         "decision is recorded and signed, and only pinned models "
                                                         "are called"])
        return self.result(FAILED, [Finding(1, "the program does not declare `regulated`")], 1)


def _returned_labels(fn):
    """String outcome labels a rule function can return: a string constant, or a dict literal's status-like key."""
    from ..core import _labels
    out = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and node.value is not None:
            v = node.value
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                out.append((v.value, node))
            elif isinstance(v, ast.Dict):
                for k, val in zip(v.keys, v.values):
                    if isinstance(k, ast.Constant) and isinstance(val, ast.Constant) and isinstance(val.value, str) \
                            and _labels({k.value: val.value}):
                        out.append((val.value, node))
    return out


@proof
class SignoffRequired(StaticProof):
    id = "signoff-required"
    title = "Outcomes that need a person cannot be decided without one"

    def prove(self, program, manifest):
        need = (manifest or {}).get("requires_signoff")
        if not need:
            return self.result(NOT_APPLICABLE, notes=["the agent manifest names no outcome that needs sign-off"])
        target = (manifest or {}).get("agent")
        agents = {a["name"]: a for a in program.meta.get("agents", [])}
        findings, covered = [], 0
        for name, a in agents.items():
            if target and name != target:
                continue
            unconditional = {s["label"] for s in a.get("signoffs", []) if not s.get("when")}
            for fn in program.functions(f"__shio_rule_{name}_"):
                for label, node in _returned_labels(fn):
                    if need != "*" and label not in need:
                        continue
                    covered += 1
                    if "*" not in unconditional and label not in unconditional:
                        findings.append(Finding(program.line(node), f"agent {name}: outcome {label} can be returned "
                                                                    f"without an unconditional signoff"))
            if need == "*" and "*" not in unconditional and not covered:
                findings.append(Finding(a["line"], f"agent {name}: every outcome needs sign-off, but there is no "
                                                   f"`signoff * by role ...`"))
        return self.result(FAILED if findings else PROVEN, findings, covered)


@proof
class NoReflection(StaticProof):
    id = "no-reflection"
    title = "No reflection route can reach a reading's value"

    def prove(self, program, manifest):
        from ..compiler import REFLECTION_ATTRS, REFLECTION_NAMES
        findings, covered = [], 0
        for node in ast.walk(program.tree):
            if not program.line(node):
                continue
            if isinstance(node, ast.Name) and node.id in REFLECTION_NAMES:
                findings.append(Finding(program.line(node), f"uses {node.id}"))
            elif isinstance(node, ast.Attribute):
                covered += 1
                if node.attr in REFLECTION_ATTRS:
                    findings.append(Finding(program.line(node), f"uses .{node.attr}"))
        return self.result(FAILED if findings else PROVEN, findings, covered)


@proof
class PackWired(StaticProof):
    id = "pack-wired"
    title = "Every runtime check of the packs in use is called from a check"

    def prove(self, program, manifest):
        from .packs import read, resolve
        refs = (manifest or {}).get("packs", [])
        if not refs:
            return self.result(NOT_APPLICABLE, notes=["the agent manifest names no packs"])
        called = set()
        for fn in [*program.functions("__shio_check_"), *program.functions("__shio_when_")]:
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    called.add(node.func.attr)
        findings, covered = [], 0
        for ref in refs:
            pack = read(resolve(ref.get("id") if isinstance(ref, dict) else ref))
            for check, controls in pack.runtime_checks().items():
                if check in (ref.get("skip", []) if isinstance(ref, dict) else []):
                    continue
                covered += 1
                if check not in called:
                    findings.append(Finding(1, f"{pack.label()} check {check} (controls {', '.join(controls)}) is "
                                               f"not called from any check"))
        return self.result(FAILED if findings else PROVEN, findings, covered)


@proof
class DependenciesPinned(StaticProof):
    id = "dependencies-pinned"
    title = "Every adapter is pinned (exact versions and implementation hash) and every local module is hashed"

    def prove(self, program, manifest):
        from .adapters import Registry
        items = (manifest or {}).get("adapters") or []
        findings, notes = [], []
        reg = Registry.from_manifest(items)
        for adapter, pin in reg.entries:
            m, actual = adapter.manifest, type(adapter).implementation_sha256()
            if m.unpinned():
                findings.append(Finding(1, f"adapter {m.name}: unpinned {', '.join(m.unpinned())}"))
            if not pin:
                findings.append(Finding(1, f"adapter {m.name}: no implementation hash pinned in the agent manifest"))
            elif pin != actual:
                findings.append(Finding(1, f"adapter {m.name}: pinned {pin[:16]}…, implementation is {str(actual)[:16]}…"))
        deps = program.dependencies()
        notes.append(f"{len(deps)} local module{'s' if len(deps) != 1 else ''} hashed into every record: "
                     + (", ".join(sorted(deps)) or "none"))
        return self.result(FAILED if findings else PROVEN, findings, len(reg.entries) + len(deps), notes)


@proof
class CdsPosture(StaticProof):
    id = "cds-posture"
    title = "The agent as built fits its declared decision-support posture (med.cds)"

    def prove(self, program, manifest):
        if not (manifest or {}).get("decision_support"):
            return self.result(NOT_APPLICABLE, notes=["the agent manifest declares no decision-support posture"])
        from .card import scan
        from .cds import check_posture
        card, _ = scan({**manifest, "decision_support": None}, regulated_check=False)
        card["decision_support"] = manifest["decision_support"]
        violations = check_posture(card)
        return self.result(FAILED if violations else PROVEN, [Finding(1, v) for v in violations], 6,
                           ["enforces the constraints the team adopted for the declared posture; it is not a "
                            "regulatory determination"])


# ---------------- the assessment ----------------
def assess(program_path, manifest=None, proofs=None, signer=None, packs=()):
    """Run the proofs over a program. -> the assessment (a dict, hashed and signed if a signer is given).

    proofs: the proof ids to run (default: every registered proof). packs: pack folders or ids whose controls with
    lint proofs are reported against the results, so an auditor sees control -> proof -> status."""
    from .. import __version__
    from .packs import ProofKind, read, resolve
    program = program_path if isinstance(program_path, Program) else Program.load(program_path)
    ids = list(proofs or PROOFS)
    results = {i: PROOFS[i].prove(program, manifest) for i in ids}
    controls = []
    for ref in [*packs, *((manifest or {}).get("packs", []))]:
        pack = read(resolve(ref.get("id") if isinstance(ref, dict) else ref))
        for c in pack.controls:
            for p in c.proofs_of(ProofKind.LINT):
                r = results.get(p.target) or PROOFS[p.target].prove(program, manifest)
                results.setdefault(p.target, r)
                controls.append({"pack": pack.label(), "pack_sha256": pack.sha256, "control": c.id,
                                 "title": c.title, "proof": p.target, "status": r.status})
    out = {"format": FORMAT, "shio": __version__,
           "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
           "program": {"path": str(program.path), "sha256": program.sha256, "regulated": bool(program.meta.get(
               "regulated")), "trusted_modules": program.dependencies()},
           "manifest_sha256": _sha(manifest) if manifest else None,
           "scope": StaticProof.scope,
           "proofs": [{**r.as_dict(), "title": PROOFS[r.proof].title} for r in results.values()],
           "controls": controls}
    out["summary"] = {s: sum(1 for r in results.values() if r.status == s) for s in (PROVEN, FAILED, NOT_APPLICABLE)}
    return seal(out, signer)


def _sha(obj):
    from ..ledger import sha256
    return sha256(obj)


def seal(doc, signer=None):
    """Hash a governance document (everything but its own hash and signature) and sign the hash."""
    from ..ledger import sha256
    body = {k: v for k, v in doc.items() if k not in ("sha256", "key_id", "signature")}
    doc = {**body, "sha256": sha256(body)}
    if signer is not None:
        doc.update(key_id=signer.key_id, signature=signer.sign(doc["sha256"]))
    return doc


def check_seal(doc, public_key=None, secret=None):
    """-> (ok, problems) for a sealed document: its hash, and its signature (required when a key is given)."""
    from ..ledger import _check_signature, sha256
    problems = []
    body = {k: v for k, v in doc.items() if k not in ("sha256", "key_id", "signature")}
    if sha256(body) != doc.get("sha256"):
        problems.append("edited: its content no longer matches its sha256")
    state = _check_signature(doc, public_key, secret)
    if state.startswith("BAD") or ((public_key is not None or secret is not None) and state != "ok"):
        problems.append(f"signature: {state}")
    return not problems, problems


def report(assessment):
    lines = [f"assessment of {Path(assessment['program']['path']).name} "
             f"(sha256 {assessment['program']['sha256'][:12]})"]
    for p in assessment["proofs"]:
        lines.append(f"  {p['status']:<15} {p['proof']}: {p['title']} ({p['covered']} sites)")
        lines += [f"      line {f['line']}: {f['message']}" for f in p["findings"]]
        lines += [f"      note: {n}" for n in p["notes"]]
    for c in assessment["controls"]:
        lines.append(f"  control {c['pack']} {c['control']} <- {c['proof']}: {c['status']}")
    s = assessment["summary"]
    lines.append(f"{s[PROVEN]} proven, {s[FAILED]} failed, {s[NOT_APPLICABLE]} not applicable")
    lines.append("scope: " + assessment["scope"])
    return "\n".join(lines)


def load_manifest(path):
    return json.loads(Path(path).read_text()) if path else None
