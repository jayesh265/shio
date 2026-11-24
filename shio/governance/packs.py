"""Control packs: the format (D2), the validator, the loader and the runtime (D7).

A pack is a folder:

    pack.json      what it is: id, version, effective date, licence, status and review, frameworks, controls
    checks.py      the deterministic checks its runtime proofs name (optional for packs with no runtime proofs)
    fixtures/      for every runtime check: passing, failing and at least one adversarial case
    README.md      what the pack covers and, under a "Limits" heading, what it does not

Each control says what is required (its requirement text, in the pack's own words), where that comes from (framework
references), and how Shio proves it, by one or more proofs of six kinds:

    lint         a static proof over the program (shio assess), e.g. "models-pinned"
    runtime      a check in checks.py that runs inside the agent; the record cites the pack version and the control
    eval         an eval suite's metric meets a threshold (shio eval)
    signoff      a person in a named role signs off
    gate         a control the pre-model gate enforces on every request (shio.governance.preflight); it ships its own
                 pass, fail and adversarial fixtures and a mutation test, and the validator runs them
    attestation  an organisational duty code can't perform: the gate requires a current signed attestation of this
                 kind (owner role, validity) before health data leaves

A control may also say its stage (P before the model call, O on its output, A before an action, R in records, X an
organisational attestation) and what happens when it fails (on_fail: deny, hold, redact, route or "route or deny").
A control the spec lists but Shio does not enforce yet is "planned": true, with no proof. Only draft and research
packs may carry planned controls, and the coverage matrix shows them as not yet built.

A pack is identified by its id, version and sha256: the hash covers every file in the folder (a Merkle-style hash
over the sorted file hashes), so a checks.py edited without a new version is a different pack, and a loader pinned
to a hash refuses it. Packs are dated: `effective` is the day the version takes effect, and a record cites the version
in force, so a later rule change never rewrites history.

No compliance labels without review: a pack whose text claims compliance or certification must be `reviewed`, with
counsel (and, for med.* packs, the clinical safety lead) named in its review block. The validator enforces it.
"""
import datetime as dt
import enum
import hashlib
import importlib.util
import json
import re
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .verdict import Verdict

FORMAT = "shio-pack/1"
BUILTIN = Path(__file__).resolve().parent.parent / "packs"
ID = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*$")
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$")
CONTROL_ID = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*-\d+[a-z]?$")
CLAIM = re.compile(r"(?i)\b(compliant|compliance with|certified|conforms? to|satisfies the requirements)\b")
STATUSES = ("draft", "research", "reviewed", "retired")


class PackError(ValueError):
    pass


class ProofKind(str, enum.Enum):
    LINT = "lint"
    RUNTIME = "runtime"
    EVAL = "eval"
    SIGNOFF = "signoff"
    GATE = "gate"
    ATTESTATION = "attestation"


STAGES = ("P", "O", "A", "R", "X")
ON_FAIL = ("deny", "hold", "redact", "route", "route or deny")


@dataclass(frozen=True)
class Ref:
    framework: str
    ref: str


@dataclass(frozen=True)
class Proof:
    kind: ProofKind
    target: str                  # lint: proof id; runtime: check name; eval: suite; signoff: role
    params: tuple = ()           # (key, value) pairs: metric, threshold, fixtures...

    def param(self, key, default=None):
        return dict(self.params).get(key, default)

    def label(self):
        if self.kind is ProofKind.EVAL:
            return f"eval {self.target}: {self.param('metric')} {self.param('op', '>=')} {self.param('threshold')}"
        if self.kind is ProofKind.SIGNOFF and self.param("subject"):
            return f"signoff {self.target} of a {self.param('subject')}"
        return f"{self.kind.value} {self.target}"


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    requirement: str
    refs: tuple
    proofs: tuple
    hazards: tuple = ()
    stage: str = None
    on_fail: str = None
    planned: bool = False
    source: str = None               # citation, e.g. "45 CFR 164.502(b)"

    def proofs_of(self, kind):
        return [p for p in self.proofs if p.kind is ProofKind(kind)]


@dataclass
class Pack:
    id: str
    name: str
    version: str
    effective: dt.date
    licence: str
    status: str
    review: dict
    frameworks: dict
    controls: tuple
    description: str = ""
    limits: str = ""
    hazards: tuple = ()
    checks_file: str = None
    path: Path = None
    sha256: str = None
    raw: dict = field(default_factory=dict, repr=False)

    def control(self, cid):
        for c in self.controls:
            if c.id == cid:
                return c
        raise PackError(f"{self.id} v{self.version} has no control {cid}")

    def stamp(self):
        """What a record cites: exactly which pack decided."""
        return {"id": self.id, "version": self.version, "effective": self.effective.isoformat(),
                "sha256": self.sha256, "status": self.status}

    def label(self):
        return f"{self.id}@{self.version}"

    def raw_control(self, cid):
        return next((c for c in self.raw.get("controls", []) if c.get("id") == cid), {})

    def runtime_checks(self):
        """{check name: [control ids]} for every runtime proof this pack's own checks.py implements."""
        out = {}
        for c in self.controls:
            for p in c.proofs_of("runtime"):
                if not p.param("pack"):
                    out.setdefault(p.target, []).append(c.id)
        return out


# ---------------- reading ----------------
def tree_sha256(folder):
    """sha256 over (relative path, file sha256) for every file under folder, sorted: any change to any file, or a file
    added or removed, changes it. Bytecode caches are left out."""
    folder = Path(folder)
    rows = []
    for f in sorted(folder.rglob("*")):
        if f.is_file() and "__pycache__" not in f.parts and not f.name.startswith("."):
            rows.append(f"{f.relative_to(folder).as_posix()}\0{hashlib.sha256(f.read_bytes()).hexdigest()}")
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()


def _proof(d, where):
    try:
        kind = ProofKind(d.get("kind"))
    except ValueError:
        raise PackError(f"{where}: proof kind must be one of {', '.join(k.value for k in ProofKind)}, "
                        f"not {d.get('kind')!r}") from None
    target = {"lint": "proof", "runtime": "check", "eval": "suite", "signoff": "role", "gate": "control",
              "attestation": "attestation"}[kind.value]
    if not d.get(target):
        raise PackError(f"{where}: a {kind.value} proof needs \"{target}\"")
    params = tuple(sorted((k, v if not isinstance(v, list) else tuple(v)) for k, v in d.items()
                          if k not in ("kind", target)))
    return Proof(kind, d[target], params)


def parse(d, path=None):
    """pack.json content -> Pack. Raises PackError on anything malformed (structure only; validate() does the rest)."""
    where = str(path or "<pack>")
    if d.get("format") != FORMAT:
        raise PackError(f"{where}: format must be {FORMAT!r}")
    for k in ("id", "name", "version", "effective", "licence", "status", "controls"):
        if k not in d:
            raise PackError(f"{where}: missing \"{k}\"")
    try:
        effective = dt.date.fromisoformat(d["effective"])
    except (TypeError, ValueError):
        raise PackError(f"{where}: effective must be a date (YYYY-MM-DD), not {d['effective']!r}") from None
    controls = []
    for i, c in enumerate(d["controls"]):
        cw = f"{where}: control {c.get('id', i)}"
        for k in ("id", "title", "requirement") + (() if c.get("planned") else ("proof",)):
            if not c.get(k):
                raise PackError(f"{cw}: missing \"{k}\"")
        proofs = c.get("proof") or []
        proofs = proofs if isinstance(proofs, list) else [proofs]
        controls.append(Control(c["id"], c["title"], c["requirement"],
                                tuple(Ref(r["framework"], r["ref"]) for r in c.get("refs", [])),
                                tuple(_proof(p, cw) for p in proofs), tuple(c.get("hazards", [])),
                                c.get("stage"), c.get("on_fail"), bool(c.get("planned")), c.get("source")))
    return Pack(d["id"], d["name"], d["version"], effective, d["licence"], d["status"], d.get("review") or {},
                {f["id"]: f for f in d.get("frameworks", [])}, tuple(controls), d.get("description", ""),
                d.get("limits", ""), tuple(d.get("hazards", [])), d.get("checks"),
                Path(path).parent if path else None, None, d)


def read(folder):
    """A pack folder -> Pack, with its tree hash."""
    folder = Path(folder)
    pj = folder / "pack.json"
    if not pj.exists():
        raise PackError(f"{folder}: no pack.json")
    try:
        d = json.loads(pj.read_text())
    except json.JSONDecodeError as e:
        raise PackError(f"{pj}: not JSON ({e})") from None
    pack = parse(d, pj)
    pack.sha256 = tree_sha256(folder)
    return pack


def resolve(ref, search=()):
    """A pack reference -> its folder. A path to a folder, or an id (optionally id@version) found in `search` folders
    and then the built-in packs. Built-in packs live in folders named by id."""
    p = Path(ref)
    if (p / "pack.json").exists():
        return p
    pid, _, version = str(ref).partition("@")
    for base in [*map(Path, search), BUILTIN]:
        for cand in (base / pid, base / f"{pid}@{version}" if version else None):
            if cand is not None and (cand / "pack.json").exists():
                if version and json.loads((cand / "pack.json").read_text()).get("version") != version:
                    continue
                return cand
    raise PackError(f"no pack {ref!r}" + (f" in {', '.join(map(str, search))}" if search else "") +
                    " or among the built-in packs")


def builtin():
    """Every built-in pack, by id."""
    return {d.name: d for d in sorted(BUILTIN.iterdir()) if (d / "pack.json").exists()} if BUILTIN.exists() else {}


# ---------------- validating ----------------
def _load_module(pack):
    if not pack.checks_file:
        return None
    f = pack.path / pack.checks_file
    if not f.exists():
        raise PackError(f"{pack.id}: checks file {pack.checks_file} not found")
    name = "shio_pack__" + re.sub(r"\W", "_", f"{pack.id}__{pack.version}__{pack.sha256[:12]}")
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, f)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return mod


def _fixture_cases(pack, check, proof):
    f = pack.path / (proof.param("fixtures") or f"fixtures/{check}.json")
    if not f.exists():
        return None, f
    d = json.loads(f.read_text())
    return d.get("cases", []), f


def validate(folder, run_fixtures=True):
    """-> (ok, problems, pack or None). Structure, identity, licence, review status, proofs, fixtures (run, unless
    run_fixtures=False) and the README's Limits section."""
    problems = []
    try:
        pack = read(folder)
    except PackError as e:
        return False, [str(e)], None
    from .licences import LicenceError, parse_spdx
    if not ID.match(pack.id):
        problems.append(f"id {pack.id!r}: lower-case words separated by dots, e.g. med.phi")
    if not SEMVER.match(pack.version):
        problems.append(f"version {pack.version!r} is not semantic (MAJOR.MINOR.PATCH)")
    try:
        parse_spdx(pack.licence)
    except LicenceError as e:
        problems.append(f"licence: {e}")
    if pack.status not in STATUSES:
        problems.append(f"status {pack.status!r} must be one of {', '.join(STATUSES)}")
    needs = ["counsel"] + (["clinical_lead"] if pack.id.startswith("med.") else [])
    if pack.status == "reviewed":
        for who in needs:
            r = pack.review.get(who)
            if not (isinstance(r, dict) and r.get("name") and r.get("date")):
                problems.append(f"status is reviewed but review.{who} is not recorded (name and date)")
    texts = [pack.name, pack.description, *[c.title for c in pack.controls], *[c.requirement for c in pack.controls]]
    claims = sorted({m.group(0).lower() for t in texts for m in CLAIM.finditer(t or "")})
    if claims and pack.status != "reviewed":
        problems.append(f"the pack's text claims {', '.join(repr(c) for c in claims)}, which only a pack reviewed by "
                        f"{' and '.join(needs)} may say")
    readme = pack.path / "README.md"
    if not readme.exists():
        problems.append("README.md is missing")
    elif not re.search(r"(?mi)^#+\s*limits\b", readme.read_text()):
        problems.append("README.md has no \"Limits\" section saying what the pack does not cover")
    ids = [c.id for c in pack.controls]
    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        problems.append(f"control id {dup} is used twice")
    if not pack.controls and pack.status != "research":
        problems.append("a pack needs at least one control (a pack still being researched has status research)")
    from .assess import PROOFS
    try:
        mod = _load_module(pack)
    except Exception as e:
        problems.append(f"{pack.checks_file}: does not import ({type(e).__name__}: {e})")
        mod = None
    gate_failures = _gate_results(pack, run_fixtures)
    for c in pack.controls:
        if c.stage is not None and c.stage not in STAGES:
            problems.append(f"{c.id}: stage {c.stage!r} must be one of {', '.join(STAGES)}")
        if c.on_fail is not None and c.on_fail not in ON_FAIL:
            problems.append(f"{c.id}: on_fail {c.on_fail!r} must be one of {', '.join(ON_FAIL)}")
        if c.planned and pack.status not in ("draft", "research"):
            problems.append(f"{c.id}: planned (not built) controls may only be in draft or research packs")
        if c.planned and c.proofs:
            problems.append(f"{c.id}: a planned control has no proofs yet; remove \"planned\" once it has one")
        if not c.planned and not c.proofs:
            problems.append(f"{c.id}: no proof; a control without a test does not ship (mark it planned)")
        for p in c.proofs:
            if p.kind is ProofKind.GATE:
                from .preflight.controls import by_control
                gc = by_control(pack.id, p.target)
                if gc is None:
                    problems.append(f"{c.id}: the pre-model gate has no control {pack.id}:{p.target}")
                else:
                    problems += [f"{c.id} (gate): {x}" for x in gate_failures.get(gc.key, [])]
            elif p.kind is ProofKind.ATTESTATION:
                if not p.param("owner") or not isinstance(p.param("valid_days"), int):
                    problems.append(f"{c.id}: an attestation proof needs \"owner\" (a role) and integer \"valid_days\"")
                if not c.on_fail:
                    problems.append(f"{c.id}: an attestation control needs on_fail")
        if not CONTROL_ID.match(c.id):
            problems.append(f"control id {c.id!r}: upper-case words and a number, e.g. PHI-1")
        for r in c.refs:
            if r.framework not in pack.frameworks:
                problems.append(f"{c.id}: refers to framework {r.framework!r}, which the pack does not declare")
        for p in c.proofs:
            if p.kind is ProofKind.LINT and p.target not in PROOFS:
                problems.append(f"{c.id}: lint proof {p.target!r} is not one shio assess knows "
                                f"({', '.join(sorted(PROOFS))})")
            elif p.kind is ProofKind.EVAL:
                if p.param("metric") is None or not isinstance(p.param("threshold"), (int, float)):
                    problems.append(f"{c.id}: an eval proof needs \"metric\" and a numeric \"threshold\"")
            elif p.kind is ProofKind.RUNTIME and p.param("pack"):
                # evidence from another pack's control (a framework pack citing med.phi, say): that pack validates
                # its own fixtures; here the check and control must exist there
                try:
                    other = read(resolve(p.param("pack")))
                    if p.target not in other.runtime_checks():
                        problems.append(f"{c.id}: {other.label()} has no runtime check {p.target!r}")
                    elif p.param("control") not in other.runtime_checks()[p.target]:
                        problems.append(f"{c.id}: {other.label()} check {p.target} does not enforce control "
                                        f"{p.param('control')!r}")
                except PackError as e:
                    problems.append(f"{c.id}: {e}")
            elif p.kind is ProofKind.RUNTIME:
                fn = getattr(mod, p.target, None) if mod else None
                if not callable(fn):
                    problems.append(f"{c.id}: runtime check {p.target!r} is not a function in {pack.checks_file}")
                    continue
                problems += _check_fixtures(pack, c, p, fn, run_fixtures)
    return not problems, problems, pack


def _gate_results(pack, run):
    """{gate control key: [problems]} for the gate controls this pack's controls name: fixtures and mutation tests."""
    targets = {p.target for c in pack.controls for p in c.proofs if p.kind is ProofKind.GATE}
    if not targets or not run:
        return {}
    from .preflight import harness
    from .preflight.controls import by_control
    out = {}
    for t in targets:
        gc = by_control(pack.id, t)
        if gc is not None:
            out[gc.key] = [f"{r.fixture} ({r.kind}): {r.detail}" for r in harness.run(gc) if not r.ok]
    return out


def _check_fixtures(pack, control, proof, fn, run):
    """Every check ships with passing, failing and adversarial fixtures, and (when run) they come out as declared."""
    cases, f = _fixture_cases(pack, proof.target, proof)
    where = f"{control.id} ({proof.target})"
    if cases is None:
        return [f"{where}: no fixtures ({f.relative_to(pack.path)})"]
    out = []
    kinds = {c.get("kind") for c in cases}
    for k in ("pass", "fail", "adversarial"):
        if k not in kinds:
            out.append(f"{where}: fixtures need at least one {k} case")
    if not run:
        return out
    for case in cases:
        try:
            got = Verdict.of(fn(*case.get("args", []), **case.get("kwargs", {}))).passed
        except Exception as e:
            out.append(f"{where}: fixture {case.get('id')} raised {type(e).__name__}: {e}")
            continue
        want = {"pass": True, "fail": False}.get(case.get("kind"), case.get("expect"))
        if want is None:
            out.append(f"{where}: adversarial fixture {case.get('id')} needs \"expect\": true or false")
        elif got != want:
            out.append(f"{where}: fixture {case.get('id')} ({case.get('kind')}) "
                       f"{'passed' if got else 'failed'}, expected to {'pass' if want else 'fail'}")
    return out


# ---------------- runtime ----------------
class PackRuntime:
    """A loaded pack. `runtime.<check>(...)` runs a runtime check and returns a Verdict; inside an agent, the record
    cites the pack's version and hash, and the check record names the controls it enforced. `runtime.lib` is the
    checks module itself, for its helper functions (which cite nothing)."""

    def __init__(self, pack, module):
        self._pack, self._module = pack, module
        self._checks = pack.runtime_checks()

    @property
    def pack(self):
        return self._pack

    @property
    def lib(self):
        return self._module

    def stamp(self):
        return self._pack.stamp()

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self._checks:
            raise AttributeError(f"{self._pack.label()} has no runtime check {name!r} "
                                 f"(checks: {', '.join(sorted(self._checks))}; helpers are under .lib)")
        fn, controls, stamp = getattr(self._module, name), self._checks[name], self._pack.stamp()
        # a check the pack lists in RECORDS_SLICES vets coarse monitoring groups; when it passes, its evidence (pairs
        # of group and value) is recorded in clear on the decision, so monitors can slice by site and subgroup
        records_slices = name in getattr(self._module, "RECORDS_SLICES", ())

        def run_check(*args, **kwargs):
            from ..core import cite
            v = Verdict.of(fn(*args, **kwargs))
            cite(stamp, controls, None if v.passed else f"[{self._pack.id} {'/'.join(controls)}] {v.detail}",
                 dict(v.evidence) if records_slices and v.passed else None)
            return v
        run_check.__name__ = name
        run_check.__doc__ = fn.__doc__
        return run_check

    def check(self, name, *args, **kwargs):
        return getattr(self, name)(*args, **kwargs)

    def __repr__(self):
        return f"<pack {self._pack.label()} sha256 {self._pack.sha256[:12]}>"


_cache, _cache_lock = {}, threading.Lock()


def load_pack(ref, search=(), sha256=None, require_valid=True):
    """Load a pack for use: `load_pack("med.phi")`, `load_pack("med.phi@0.1.0", sha256="...")`, or a folder.

    sha256 pins the exact pack: a different tree (an edited check, a changed fixture) is refused. require_valid runs
    the validator first, fixtures included, so a pack whose own fixtures fail never decides anything."""
    folder = resolve(ref, search)
    pack = read(folder)
    if sha256 and pack.sha256 != sha256:
        raise PackError(f"{pack.label()} at {folder} has sha256 {pack.sha256[:16]}…, not the pinned {sha256[:16]}…")
    key = (str(folder.resolve()), pack.sha256)
    with _cache_lock:
        if key in _cache:
            return _cache[key]
        if require_valid:
            ok, problems, _ = validate(folder)
            if not ok:
                raise PackError(f"{pack.label()} does not validate:\n  " + "\n  ".join(problems))
        rt = PackRuntime(pack, _load_module(pack))
        _cache[key] = rt
        return rt


# ---------------- OSCAL ----------------
OSCAL_VERSION = "1.1.2"
SHIO_NS = "https://github.com/pratikkp24/shio/ns/oscal"


def to_oscal(pack):
    """The pack as an OSCAL catalog (JSON). Export only: OSCAL has no place for how a control is proven, so proofs go
    in props under Shio's namespace and pack.json stays the source of truth (docs/governance/D2-pack-format.md)."""
    import uuid
    base = uuid.uuid5(uuid.NAMESPACE_URL, f"{SHIO_NS}/{pack.id}/{pack.version}")
    groups = {}
    for c in pack.controls:
        fw = c.refs[0].framework if c.refs else "shio"
        groups.setdefault(fw, []).append({
            "id": re.sub(r"[^a-z0-9_.-]", "-", c.id.lower()),
            "title": c.title,
            "props": [{"name": "label", "value": c.id}]
                     + [{"name": "proof", "ns": SHIO_NS, "value": p.label()} for p in c.proofs]
                     + [{"name": "framework-ref", "ns": SHIO_NS, "value": f"{r.framework} {r.ref}"} for r in c.refs],
            "parts": [{"id": re.sub(r"[^a-z0-9_.-]", "-", c.id.lower()) + "_smt", "name": "statement",
                       "prose": c.requirement}],
        })
    return {"catalog": {
        "uuid": str(base),
        "metadata": {"title": pack.name, "last-modified": f"{pack.effective.isoformat()}T00:00:00Z",
                     "version": pack.version, "oscal-version": OSCAL_VERSION,
                     "props": [{"name": "shio-pack-id", "ns": SHIO_NS, "value": pack.id},
                               {"name": "shio-pack-sha256", "ns": SHIO_NS, "value": pack.sha256 or ""},
                               {"name": "status", "ns": SHIO_NS, "value": pack.status}]},
        "groups": [{"id": re.sub(r"[^a-z0-9_.-]", "-", fw.lower()),
                    "title": pack.frameworks.get(fw, {}).get("title", fw), "controls": cs}
                   for fw, cs in groups.items()],
    }}
