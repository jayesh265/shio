"""GOV-1 registry as code, GOV-6 dependency graph, GOV-2 discovery hand-off.

registry.json (format shio-registry/1) lists, with an owner for each: systems, agents, models, tools, data sources
and vendors. Every reference must resolve, every agent needs a purpose and an owner, and an agent declares exactly
the tools, models and data it uses.

  validate(reg)               structure, references and owners
  check_code(reg, root)       the registry against the code: for each agent with a Shio manifest, the tools its
                              program really declares (via the agent card scan) must be listed; for Python agents,
                              the tools `shio doctor` finds. CI fails when an agent uses a tool its entry doesn't list.
  graph(reg)                  nodes and edges (system > agent > model > vendor, agent > tool, agent > data source),
                              as JSON, Mermaid and Graphviz DOT
  candidates(reg, found)      discovery results not yet in the registry, for a person to triage (nothing registers
                              itself)
"""
import json
from pathlib import Path

FORMAT = "shio-registry/1"
KINDS = ("owners", "vendors", "models", "tools", "data_sources", "systems", "agents")
REFS = {"vendors": {}, "models": {"vendor": "vendors"}, "tools": {}, "data_sources": {"vendor": "vendors"},
        "systems": {}, "agents": {"system": "systems", "models": "models", "tools": "tools", "data": "data_sources"}}


class RegistryError(ValueError):
    pass


def load(path):
    reg = json.loads(Path(path).read_text())
    reg["_path"] = str(path)
    return reg


def validate(reg):
    """-> [problems]. Empty means the registry is internally consistent."""
    if reg.get("format") != FORMAT:
        return [f"format must be {FORMAT!r}"]
    out = []
    owners = reg.get("owners", {})
    for kind in KINDS[1:]:
        for name, e in reg.get(kind, {}).items():
            where = f"{kind}.{name}"
            if not isinstance(e, dict):
                out.append(f"{where}: must be an object")
                continue
            if e.get("owner") not in owners:
                out.append(f"{where}: owner {e.get('owner')!r} is not in owners")
            for field, target in REFS.get(kind, {}).items():
                vals = e.get(field)
                for v in ([vals] if isinstance(vals, str) else vals or []):
                    if v not in reg.get(target, {}):
                        out.append(f"{where}: {field} {v!r} is not in {target}")
            if kind == "agents":
                for need in ("purpose", "system"):
                    if not e.get(need):
                        out.append(f"{where}: needs a {need}")
            if kind == "models" and not e.get("version"):
                out.append(f"{where}: needs a pinned version")
            if kind == "tools" and "side_effect" not in e:
                out.append(f"{where}: must say whether it has side effects (side_effect: true or false)")
    return out


def check_code(reg, root=None):
    """-> [problems]: tools an agent's code uses that its registry entry doesn't list (and the reverse, as notes)."""
    root = Path(root or Path(reg.get("_path", ".")).parent)
    out = []
    for name, a in reg.get("agents", {}).items():
        declared = set(a.get("tools", []))
        used = set()
        if a.get("manifest"):
            from .card import load_manifest, scan
            c, _ = scan(load_manifest(root / a["manifest"]))
            used |= {t["name"] for t in c.get("tools", [])}
        if a.get("python"):
            from .doctor import scan_python
            used |= {t["name"] for t in scan_python(root / a["python"])["tools"]}
        for t in sorted(used - declared):
            out.append(f"agents.{name}: uses tool {t!r}, which its registry entry does not list")
        unknown = sorted(t for t in used if t not in reg.get("tools", {}))
        out += [f"agents.{name}: tool {t!r} is not in the registry's tools" for t in unknown if t not in declared]
    return out


def graph(reg):
    nodes, edges = {}, set()

    def node(kind, name):
        nodes[f"{kind}:{name}"] = {"id": f"{kind}:{name}", "kind": kind, "name": name,
                                   "owner": reg.get(kind + "s" if kind != "data" else "data_sources", {})
                                   .get(name, {}).get("owner")}
        return f"{kind}:{name}"
    for name, a in reg.get("agents", {}).items():
        ag = node("agent", name)
        if a.get("system"):
            edges.add((node("system", a["system"]), ag, "runs"))
        for m in a.get("models", []):
            edges.add((ag, node("model", m), "calls"))
            v = reg.get("models", {}).get(m, {}).get("vendor")
            if v:
                edges.add((f"model:{m}", node("vendor", v), "provided by"))
        for t in a.get("tools", []):
            edges.add((ag, node("tool", t), "uses"))
        for d in a.get("data", []):
            edges.add((ag, node("data", d), "reads"))
            v = reg.get("data_sources", {}).get(d, {}).get("vendor")
            if v:
                edges.add((f"data:{d}", node("vendor", v), "hosted by"))
    return {"nodes": sorted(nodes.values(), key=lambda n: n["id"]),
            "edges": [{"from": a, "to": b, "label": lab} for a, b, lab in sorted(edges)]}


def _safe(s):
    return "".join(ch if ch.isalnum() else "_" for ch in s)


def mermaid(g):
    lines = ["graph LR"]
    for n in g["nodes"]:
        lines.append(f'  {_safe(n["id"])}["{n["kind"]}: {n["name"]}"]')
    for e in g["edges"]:
        lines.append(f'  {_safe(e["from"])} -->|{e["label"]}| {_safe(e["to"])}')
    return "\n".join(lines) + "\n"


def dot(g):
    lines = ["digraph registry {", "  rankdir=LR;"]
    for n in g["nodes"]:
        lines.append(f'  "{n["id"]}" [label="{n["kind"]}\\n{n["name"]}"];')
    for e in g["edges"]:
        lines.append(f'  "{e["from"]}" -> "{e["to"]}" [label="{e["label"]}"];')
    return "\n".join(lines + ["}"]) + "\n"


def candidates(reg, found):
    """Discovery results (shio doctor) not yet registered: for a person to triage. Never registered automatically."""
    known_tools = set(reg.get("tools", {}))
    out = []
    for f in found.get("tools", []):
        if f["name"] not in known_tools:
            out.append({"kind": "tool", "name": f["name"], "where": f["where"], "side_effect_guess": f["side_effect"],
                        "status": "candidate: needs a person to register or dismiss"})
    for sdk in found.get("model_sdks", []):
        out.append({"kind": "model-sdk", "name": sdk["module"], "where": sdk["where"],
                    "status": "candidate: which registered model does this call?"})
    for m in found.get("mcp_servers", []):
        out.append({"kind": "mcp-server", "name": m["name"], "where": m["where"],
                    "status": "candidate: register its tools, then pin their definitions (CORE-6)"})
    return out
