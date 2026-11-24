"""Further adapters (D32): output validators as readers, eval tools, Temporal and DSPy.

  ValidatorReader    any output validator or classifier (toxicity, PII, a Guardrails validator, an LLM judge) as a
                     reader: its verdict is a Reading that checks judge, never a decision on its own
  DSPyReader         a DSPy module as a reader: its prediction answers a read (shio-lang[dspy])
  TemporalHost       runs a Shio agent as a Temporal activity (shio-lang[temporal]); a host, outside every decision
  JUnitSink          writes eval results as JUnit XML, which CI systems and test dashboards read
  import_eval        an external eval tool's metrics, sealed as a Shio eval result so bundles can cite it

Third-party packages are imported only when an adapter is used, and each installs as an extra.
"""
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from ..adapters import (Dependency, HostAdapter, Manifest, ReaderAdapter, SinkAdapter, TrustClass)
from ..assess import seal


class ValidatorReader(ReaderAdapter):
    """Wrap fn(text) -> JSON-ready dict (or a bool) as a reader. The caller declares what it is (name, version,
    licence), because a validator's verdict is only as good as the validator."""

    def __init__(self, fn, name, version, licence, schema=None, dependencies=()):
        self.fn = fn
        self.manifest = Manifest(name, version, TrustClass.READER, licence, "an output validator as a reader",
                                 tuple(dependencies))
        self.schema = schema

    def read_request(self, req):
        text = "\n".join(s.text or "" for s in req.sources)
        if req.context:
            text += "\n" + json.dumps(req.context, ensure_ascii=False, default=str)
        out = self.fn(text)
        return json.dumps(out if self.schema else {"value": out}, default=str)


class DSPyReader(ReaderAdapter):
    """A DSPy module as a reader: called with the read's sources as `document` (and the ask as `question`), its
    prediction's fields are the answer."""
    manifest = Manifest("dspy-reader", "0.1.0", TrustClass.READER, "MIT OR Apache-2.0", "a DSPy module as a reader",
                        (Dependency("dspy", "==3.4.0", "MIT"),), extra="dspy")

    def __init__(self, module, schema=None):
        self.module, self.schema = module, schema

    def read_request(self, req):
        pred = self.module(document="\n\n".join(s.text or "" for s in req.sources), question=req.ask)
        fields = dict(pred.items()) if hasattr(pred, "items") else vars(pred)
        return json.dumps(fields if self.schema else {"value": fields}, default=str)


class TemporalHost(HostAdapter):
    """Run Shio agents inside Temporal. activity(agent) returns a Temporal activity that calls the agent; run() calls
    it directly (what the activity does), so a host never alters what the agent decided."""
    manifest = Manifest("temporal-host", "0.1.0", TrustClass.HOST, "MIT OR Apache-2.0",
                        "Shio agents as Temporal activities", (Dependency("temporalio", "==1.20.0", "MIT"),),
                        extra="temporal")

    def run(self, agent, *args, **kwargs):
        return agent(*args, **kwargs)

    def activity(self, agent, name=None):
        from temporalio import activity

        @activity.defn(name=name or getattr(agent, "__name__", "shio_agent"))
        def run_agent(*args):
            return self.run(agent, *args)
        return run_agent


class JUnitSink(SinkAdapter):
    """Eval results to JUnit XML. emit(result, path) writes the file; it returns nothing."""
    manifest = Manifest("junit-eval-sink", "0.1.0", TrustClass.SINK, "MIT OR Apache-2.0",
                        "eval results as JUnit XML for CI")

    def __init__(self, folder=None):
        self.folder = Path(folder) if folder else None

    def emit(self, record, name):
        if record.get("format") != "shio-eval/1" or self.folder is None:
            return None
        self.folder.mkdir(parents=True, exist_ok=True)
        (self.folder / f"{Path(name).stem}.xml").write_bytes(to_junit(record))
        return None


def to_junit(result):
    failures = [r for r in result["results"] if not r["passed"]]
    suite = ET.Element("testsuite", name=f"shio-eval-{result['suite']}", tests=str(result["cases"]),
                       failures=str(len(failures)))
    for r in result["results"]:
        case = ET.SubElement(suite, "testcase", classname=result["suite"], name=r["id"])
        if not r["passed"]:
            ET.SubElement(case, "failure", message=r["detail"][:500])
    for g in result.get("gate_failures", []):
        case = ET.SubElement(suite, "testcase", classname=f"{result['suite']}.gates", name=g.split(" ")[0])
        ET.SubElement(case, "failure", message=g)
    return ET.tostring(suite, encoding="utf-8", xml_declaration=True)


def import_eval(tool, suite, metrics, cases=None, signer=None, note=""):
    """An external eval tool's results as a sealed Shio eval result (no per-case detail unless given). The tool's
    name is recorded, so a bundle says where the number came from."""
    import datetime as dt
    return seal({"format": "shio-eval/1", "suite": suite, "origin": tool, "note": note,
                 "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                 "cases": len(cases or []), "passed": sum(1 for c in cases or [] if c.get("passed")),
                 "metrics": dict(metrics), "slices": {}, "gates": {}, "gate_failures": [],
                 "results": list(cases or [])}, signer)
