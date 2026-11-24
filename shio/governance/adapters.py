"""Adapters: how outside tools enter a Shio agent without weakening its guarantee (D3 spec, D10 framework).

The trust class decides the adapter type, and the type decides where its output may go:

  reader   anything that can be probabilistic (a classifier, an NER model, an LLM-based validator). It is a model as
           far as Shio is concerned: it answers a read, so its output is a Reading, sealed until a check or rule
           looks at it. A PHI detector is a reader; only checks decide what its findings mean.
  check    deterministic code that decides (a lookup in a pinned table, a policy engine). It must be version- and
           hash-pinned and reviewed, return the same Verdict for the same input, and change nothing.
  sink     an exporter (a GRC tool, a SIEM, a dashboard). It receives finished records and returns nothing a
           decision could use: it sits outside the boundary.
  host     an orchestrator that runs a Shio agent (a Temporal activity, a job runner). It never enters a decision:
           the agent inside it keeps its own boundary, records and signatures. Checked for licence and pins only.

Every adapter has a manifest: name, exact version, trust class, licence, and its dependencies with exact versions and
licences. Its implementation is hashed (the source file), and an agent manifest pins that hash. In regulated mode an
adapter that is not pinned (a version range, an unpinned dependency, no hash pin) is refused when the agent card is
built (`shio registry scan`) and again at run time (a reader without a pin can't answer a regulated read).
"""
import abc
import copy
import enum
import hashlib
import importlib
import inspect
import re
from dataclasses import dataclass, field

from .verdict import Verdict

EXACT = re.compile(r"^(==)?\d+(\.\d+)*([a-z]+\d*)?$")


class AdapterError(ValueError):
    pass


class TrustClass(str, enum.Enum):
    READER = "reader"
    CHECK = "check"
    SINK = "sink"
    HOST = "host"


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    licence: str

    @property
    def pinned(self):
        return bool(EXACT.match(self.version.strip()))


@dataclass(frozen=True)
class Manifest:
    name: str
    version: str
    trust: TrustClass
    licence: str
    description: str = ""
    dependencies: tuple = ()
    extra: str = None            # the pip extra that installs its dependencies: shio-lang[extra]
    reviewed_by: str = None      # a check adapter's reviewer (required for regulated use)

    @property
    def pinned(self):
        return bool(EXACT.match(self.version)) and all(d.pinned for d in self.dependencies)

    def unpinned(self):
        out = [] if EXACT.match(self.version) else [f"{self.name} {self.version}"]
        return out + [f"{d.name} {d.version}" for d in self.dependencies if not d.pinned]


class Adapter(abc.ABC):
    manifest: Manifest = None
    trust: TrustClass = None

    @classmethod
    def ref(cls):
        return f"{cls.__module__}:{cls.__qualname__}"

    @classmethod
    def implementation_sha256(cls):
        """sha256 of the source file that defines the adapter: what an agent manifest pins."""
        try:
            return hashlib.sha256(open(inspect.getsourcefile(cls), "rb").read()).hexdigest()
        except (TypeError, OSError):
            return None

    def identity(self):
        m = self.manifest
        ident = {"kind": f"{self.trust.value}-adapter", "name": m.name, "version": m.version,
                 "sha256": self.implementation_sha256()}
        if m.pinned and ident["sha256"]:
            ident["pinned"] = f"{m.name}=={m.version}@{ident['sha256'][:16]}"
        return ident


class ReaderAdapter(Adapter):
    """Answers a read. Subclasses implement read_request(req) -> the raw answer (JSON-ready or a string), which Shio
    parses into the read's type. It never decides anything: what it found is a Reading. `schema` is the type its
    answers fit (a pydantic model), which agents read it as."""
    trust = TrustClass.READER
    schema = None

    @property
    def name(self):
        return self.manifest.name

    @abc.abstractmethod
    def read_request(self, req):
        ...

    def propose(self, req):
        return self.read_request(req)


class CheckAdapter(Adapter):
    """Deterministic code that decides. Subclasses implement decide(*args) -> Verdict | bool | (bool, detail)."""
    trust = TrustClass.CHECK
    fixtures = ()                # ((args, expected passed), ...) for the conformance tests

    @abc.abstractmethod
    def decide(self, *args, **kwargs):
        ...

    def __call__(self, *args, **kwargs):
        return Verdict.of(self.decide(*args, **kwargs))


class SinkAdapter(Adapter):
    """Receives finished records (the trace sink interface: emit(record, name)). Returns nothing."""
    trust = TrustClass.SINK

    @abc.abstractmethod
    def emit(self, record, name):
        ...


class HostAdapter(Adapter):
    """Runs Shio agents (an orchestrator). Subclasses implement run(agent, *args, **kwargs) -> the agent's outcome."""
    trust = TrustClass.HOST

    @abc.abstractmethod
    def run(self, agent, *args, **kwargs):
        ...


def load(ref):
    """'package.module:Class' -> the adapter class."""
    mod, _, qual = ref.partition(":")
    obj = importlib.import_module(mod)
    for part in qual.split("."):
        obj = getattr(obj, part)
    if not (isinstance(obj, type) and issubclass(obj, Adapter)):
        raise AdapterError(f"{ref} is not an Adapter")
    return obj


# ---------------- conformance ----------------
@dataclass
class Result:
    test: str
    ok: bool
    detail: str = ""


@dataclass
class Conformance:
    adapter: str
    results: list = field(default_factory=list)

    @property
    def ok(self):
        return all(r.ok for r in self.results)

    def add(self, test, ok, detail=""):
        self.results.append(Result(test, bool(ok), detail))


def conformance(adapter, regulated=False, pin=None, policy=None, sample=None):
    """Run the conformance tests on an adapter instance. pin: the sha256 the agent manifest pins. sample: for a
    reader, a ReadRequest to answer; for a sink, a record to emit. -> Conformance."""
    from .licences import check_manifest_licence
    cls, m = type(adapter), adapter.manifest
    out = Conformance(cls.ref() if hasattr(cls, "ref") else repr(cls))
    out.add("has a manifest", isinstance(m, Manifest), "" if isinstance(m, Manifest) else "manifest missing")
    if not isinstance(m, Manifest):
        return out
    base = {TrustClass.READER: ReaderAdapter, TrustClass.CHECK: CheckAdapter, TrustClass.SINK: SinkAdapter,
            TrustClass.HOST: HostAdapter}[m.trust]
    out.add("trust class matches its type", isinstance(adapter, base),
            "" if isinstance(adapter, base) else f"manifest says {m.trust.value}, but it is not a {base.__name__}")
    ok, why = check_manifest_licence(m.licence, "extra", m.name, policy)
    out.add("licence allowed", ok, why)
    for d in m.dependencies:
        ok, why = check_manifest_licence(d.licence, "extra", d.name, policy)
        out.add(f"dependency {d.name} licence allowed", ok, why)
    unpinned = m.unpinned()
    actual = cls.implementation_sha256()
    if regulated:
        out.add("pinned (regulated mode refuses unpinned dependencies)", not unpinned,
                "unpinned: " + ", ".join(unpinned) if unpinned else "")
        out.add("implementation hash pinned", pin is not None and pin == actual,
                "no hash pin in the agent manifest" if pin is None else
                ("" if pin == actual else f"pinned {pin[:16]}…, implementation is {str(actual)[:16]}…"))
    elif pin is not None:
        out.add("implementation hash matches its pin", pin == actual, f"pinned {pin[:16]}…, is {str(actual)[:16]}…")
    if m.trust is TrustClass.READER:
        _reader_tests(adapter, out, sample)
    elif m.trust is TrustClass.CHECK:
        _check_tests(adapter, out, regulated)
    elif m.trust is TrustClass.SINK:
        _sink_tests(adapter, out, sample)
    else:
        _host_tests(adapter, out)
    return out


def _reader_tests(adapter, out, sample):
    from .. import core
    from ..core import BoundaryError, Reading, Source
    req_source = sample or Source("conformance", text="Patient seen 2026-01-02 at 12 Main St, phone 555-201-3344.")

    @core.agent(record=False, name="conformance")
    def probe(src):
        r = core.read(adapter.schema or dict, "conformance probe", by=adapter, sources=[src])
        sealed = False
        try:
            r.value      # noqa: B018  (outside a check: must be refused)
        except BoundaryError:
            sealed = True
        got = core.check(lambda v: v is not None, name="answered")(r)
        return {"sealed": sealed, "is_reading": isinstance(r, Reading), "answered": got}

    try:
        res = probe(req_source)
        out.add("output is a Reading", res["is_reading"])
        out.add("output is sealed outside checks and rules", res["sealed"])
        out.add("answers a read", res["answered"], "" if res["answered"] else "the read came back null")
    except Exception as e:
        out.add("answers a read inside an agent", False, f"{type(e).__name__}: {e}")
    ident = adapter.identity()
    out.add("identity names the adapter", ident.get("name") == adapter.manifest.name)


def _check_tests(adapter, out, regulated):
    if regulated:
        out.add("reviewed (a check decides, so a person has reviewed it)", bool(adapter.manifest.reviewed_by))
    if not adapter.fixtures:
        out.add("has fixtures", False, "a check adapter ships (args, expected) fixtures")
        return
    for i, (args, want) in enumerate(adapter.fixtures):
        snapshot = copy.deepcopy(args)
        try:
            a, b = adapter(*args), adapter(*copy.deepcopy(snapshot))
        except Exception as e:
            out.add(f"fixture {i} runs", False, f"{type(e).__name__}: {e}")
            continue
        out.add(f"fixture {i} deterministic", a == b, f"{a!r} then {b!r}")
        out.add(f"fixture {i} changes nothing", args == snapshot, "the check changed its input")
        out.add(f"fixture {i} gives {want}", a.passed == want, str(a))


def _sink_tests(adapter, out, sample):
    record = sample or {"agent": "conformance", "outcome": {"status": "OK"}, "checks": [], "readings": []}
    snapshot = copy.deepcopy(record)
    try:
        ret = adapter.emit(record, "conformance.json")
        out.add("emit returns nothing a decision could use", ret is None, f"returned {type(ret).__name__}")
        out.add("emit changes nothing", record == snapshot, "the sink changed the record")
    except Exception as e:
        out.add("emit runs", False, f"{type(e).__name__}: {e}")


def _host_tests(adapter, out):
    """A host runs an agent and hands back exactly what the agent returned: it can't change a decision."""
    from .. import core

    @core.agent(record=False, name="conformance_host")
    def probe(x):
        return {"status": "OK", "x": x}

    try:
        got = adapter.run(probe, 7)
        out.add("returns the agent's own outcome", got == {"status": "OK", "x": 7}, f"got {got!r}")
    except Exception as e:
        out.add("runs an agent", False, f"{type(e).__name__}: {e}")


# ---------------- the registry, and the SBOM ----------------
class Registry:
    """The adapters an agent uses, each with its pin. check() is what `shio registry scan` and
    `shio adapters check` run: in regulated mode, any failure refuses the build."""

    def __init__(self):
        self.entries = []        # (adapter instance, pinned sha256 or None)

    def add(self, adapter, pin=None):
        if not isinstance(adapter, Adapter):
            raise AdapterError(f"{adapter!r} is not an Adapter")
        self.entries.append((adapter, pin))
        return adapter

    @classmethod
    def from_manifest(cls, items):
        """[{"ref": "module:Class", "sha256": "...", "args": {...}}] -> Registry."""
        reg = cls()
        for it in items or []:
            reg.add(load(it["ref"])(**it.get("args", {})), it.get("sha256"))
        return reg

    def check(self, regulated=False, policy=None):
        """-> (ok, [Conformance])."""
        results = [conformance(a, regulated, pin, policy) for a, pin in self.entries]
        return all(r.ok for r in results), results

    def sbom(self, extra_components=()):
        return sbom([(a, pin) for a, pin in self.entries], extra_components)


def sbom(adapters, extra_components=()):
    """A CycloneDX-style bill of materials for an agent card: every adapter (with its trust class and pin) and its
    declared dependencies, plus any extra components (the program's local modules)."""
    comps = []
    for a, pin in adapters:
        m = a.manifest
        comps.append({"type": "library", "bom-ref": f"adapter:{m.name}@{m.version}", "name": m.name,
                      "version": m.version, "licenses": [{"expression": m.licence}],
                      "hashes": [{"alg": "SHA-256", "content": a.implementation_sha256() or ""}],
                      "properties": [{"name": "shio:trust-class", "value": m.trust.value},
                                     {"name": "shio:pinned", "value": str(bool(m.pinned and pin))},
                                     {"name": "shio:implementation", "value": type(a).ref()}]})
        for d in m.dependencies:
            comps.append({"type": "library", "bom-ref": f"{m.name}:{d.name}@{d.version}", "name": d.name,
                          "version": d.version, "licenses": [{"expression": d.licence}],
                          "properties": [{"name": "shio:required-by", "value": m.name}]})
    comps += list(extra_components)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": comps}
