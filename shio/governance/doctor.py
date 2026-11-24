"""DX-3 `shio doctor` and GOV-2 discovery: scan an agent repository, list its tools, flag unguarded side-effect tools,
find model SDK calls and MCP servers, and propose an argument policy and a threat list to start from.

It reads code; it never runs it. Heuristics, stated plainly:

  a tool        a function passed to something agent-shaped: tools=[...] / tools={...}, Tool(fn) / Tool(func=fn),
                @tool / @function_tool / @mcp.tool decorators, or a function name in a `tools` dict or list
  side effect   the name starts with an action verb (send, pay, refund, delete, write, create, update, transfer,
                post, execute, run, book, cancel, charge, order, publish, email, notify, upload) - a guess to confirm
  guarded       the function is wrapped by a Shio gate somewhere in the repository: ArgGate/AgtGate/CedarGate .wrap,
                guard.Tool / wrap_tools, or a Guard session's call
  MCP servers   mcp.json, .mcp.json, claude_desktop_config.json or any JSON file with "mcpServers"

What it can't see: tools built dynamically, tools in other languages, and guards applied outside the repository.
Nothing it finds is registered automatically (GOV-2: a person triages).
"""
import ast
import json
from pathlib import Path

from .preflight.bypass import MODEL_SDKS, _banned

VERBS = ("send", "pay", "refund", "delete", "remove", "write", "create", "update", "transfer", "post", "execute", "run",
         "book", "cancel", "charge", "order", "publish", "email", "notify", "upload", "drop", "issue", "approve",
         "submit", "deploy", "grant", "revoke", "set", "put", "patch")
TOOL_DECORATORS = ("tool", "function_tool", "mcp.tool", "server.tool", "app.tool")
GUARD_WRAPPERS = ("wrap", "wrap_tools", "gated", "call")
GUARD_CLASSES = ("ArgGate", "AgtGate", "CedarGate", "Guard", "GuardGate", "LangChainToolGate", "OpenAIToolGate",
                 "ClaudeToolGate", "MCPToolGate")


def side_effect(name):
    n = name.lower().lstrip("_")
    return any(n == v or n.startswith(v + "_") or n.startswith(v) and n[len(v):len(v) + 1].isupper() for v in VERBS)


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _names_in(node):
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [e.id for e in node.elts if isinstance(e, ast.Name)]
    if isinstance(node, ast.Dict):
        return [v.id for v in node.values if isinstance(v, ast.Name)]
    return [node.id] if isinstance(node, ast.Name) else []


def scan_python(path):
    files = [Path(path)] if Path(path).is_file() else sorted(Path(path).rglob("*.py"))
    defs, tools, guarded, sdks = {}, {}, set(), []
    for f in files:
        if "site-packages" in f.parts or ".venv" in f.parts:
            continue
        try:
            tree = ast.parse(f.read_text(), str(f))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs.setdefault(node.name, f"{f}:{node.lineno}")
                if any(_dotted(d).endswith(TOOL_DECORATORS) or _dotted(d) in TOOL_DECORATORS
                       for d in node.decorator_list):
                    tools[node.name] = f"{f}:{node.lineno}"
            elif isinstance(node, ast.Call):
                fn = _dotted(node.func)
                last = fn.split(".")[-1]
                for kw in node.keywords:
                    if kw.arg in ("tools", "functions", "func", "fn"):
                        for n in _names_in(kw.value):
                            tools.setdefault(n, f"{f}:{node.lineno}")
                if last == "Tool" or last == "StructuredTool" or last == "from_function":
                    for n in _names_in(node.args[0]) if node.args else []:
                        tools.setdefault(n, f"{f}:{node.lineno}")
                if last in GUARD_WRAPPERS and (any(c in fn for c in GUARD_CLASSES) or "gate" in fn.lower()
                                               or "guard" in fn.lower() or "session" in fn.lower()):
                    for a in node.args:
                        guarded.update(_names_in(a))
                if last in GUARD_CLASSES:
                    for a in node.args:
                        guarded.update(_names_in(a))
            elif isinstance(node, ast.Assign):
                if any(isinstance(t, ast.Name) and "tool" in t.id.lower() for t in node.targets):
                    for n in _names_in(node.value):
                        tools.setdefault(n, f"{f}:{node.lineno}")
                    if isinstance(node.value, ast.DictComp) or isinstance(node.value, ast.Dict):
                        for v in getattr(node.value, "values", []):
                            if isinstance(v, ast.Call) and _dotted(v.func).split(".")[-1] in GUARD_WRAPPERS:
                                wrapped = [n for a in v.args for n in _names_in(a)]
                                guarded.update(wrapped)
                                for n in wrapped:
                                    tools.setdefault(n, f"{f}:{node.lineno}")
            if isinstance(node, ast.Import):
                sdks += [{"module": a.name, "where": f"{f}:{node.lineno}"} for a in node.names
                         if _banned(a.name, MODEL_SDKS)]
            elif isinstance(node, ast.ImportFrom) and node.module and _banned(node.module, MODEL_SDKS):
                sdks.append({"module": node.module, "where": f"{f}:{node.lineno}"})
    # a comprehension that wraps every tool (tools = {n: gate.wrap(f) for n, f in raw.items()}) guards them all
    for f in files:
        try:
            text = f.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        if ".wrap(fn" in text or ".wrap(f," in text or "wrap_tools(" in text:
            guarded.update(t for t in tools if t in text)
    found = [{"name": n, "where": defs.get(n, w), "side_effect": side_effect(n), "guarded": n in guarded}
             for n, w in sorted(tools.items()) if n in defs]
    return {"tools": found, "model_sdks": sdks}


def scan_mcp(path):
    out = []
    root = Path(path)
    for f in ([root] if root.is_file() else list(root.rglob("*.json"))):
        if "node_modules" in f.parts or ".venv" in f.parts:
            continue
        try:
            d = json.loads(f.read_text())
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        servers = d.get("mcpServers") if isinstance(d, dict) else None
        for name, cfg in (servers or {}).items():
            out.append({"name": name, "where": str(f), "command": (cfg or {}).get("command") or (cfg or {}).get("url")})
    return out


def examine(path):
    """-> the doctor's report: tools, unguarded side-effect tools, SDKs, MCP servers, a proposed policy, threats."""
    py = scan_python(path)
    mcp = scan_mcp(path)
    unguarded = [t for t in py["tools"] if t["side_effect"] and not t["guarded"]]
    policy = {"format": "shio-argpolicy/1", "default": "deny",
              "tools": {t["name"]: {"on_fail": "hold" if t["side_effect"] else "deny",
                                    "args": {}, "_todo": "add ranges, allow-lists and relations to trusted facts"}
                        for t in py["tools"]}}
    threats = []
    if unguarded:
        threats.append({"risk": "ASI02 tool misuse", "detail": f"{len(unguarded)} side-effect tool(s) run without a "
                                                               f"gate: {', '.join(t['name'] for t in unguarded)}"})
    if py["model_sdks"]:
        threats.append({"risk": "pre-model gate bypass (CORE-5)", "detail": f"{len(py['model_sdks'])} direct model SDK "
                                                                            f"import(s); route them through the gate"})
    if mcp:
        threats.append({"risk": "ASI04 supply chain / tool poisoning", "detail": f"{len(mcp)} MCP server(s): pin "
                                                                                 f"their tool definitions (CORE-6)"})
    return {"tools": py["tools"], "unguarded": unguarded, "model_sdks": py["model_sdks"], "mcp_servers": mcp,
            "proposed_policy": policy, "threats": threats}


def render(r):
    lines = [f"{len(r['tools'])} tool(s), {len(r['unguarded'])} unguarded side-effect tool(s), "
             f"{len(r['model_sdks'])} direct model SDK import(s), {len(r['mcp_servers'])} MCP server(s)"]
    for t in r["tools"]:
        mark = "UNGUARDED" if t in r["unguarded"] else ("guarded" if t["guarded"] else "read-only?")
        lines.append(f"  {mark:10} {t['name']:24} {t['where']}")
    for s in r["model_sdks"]:
        lines.append(f"  SDK        {s['module']:24} {s['where']}")
    for m in r["mcp_servers"]:
        lines.append(f"  MCP        {m['name']:24} {m['where']}")
    if r["threats"]:
        lines.append("threats:")
        lines += [f"  - {t['risk']}: {t['detail']}" for t in r["threats"]]
    lines.append("to do: write --policy to a file, fill in each tool's argument rules, and wrap the tools with ArgGate")
    return "\n".join(lines)
