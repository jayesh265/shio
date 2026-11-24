"""No bypass: the gate is the only way to a model client (the spec's "for the gate itself" rules).

Two layers, because neither alone is enough:

  lint(paths)          static: fails when any Python file outside the allowed transport modules imports a model SDK
                       (import, from-import, __import__ or importlib.import_module with a literal name). CI runs it.
  ImportSeal(...)      runtime: removes the SDKs from sys.modules, keeps them privately, and installs an import hook
                       that refuses them to everyone; the gate's transport gets them through seal.module(name). Agent
                       code that tries `import anthropic` gets ImportError.

Python can't stop code that is determined to escape (ctypes, reading the private map): imported Python is trusted
code in Shio's model, and this makes "checked before anything is sent" the path of least resistance and a CI failure
to break, not a sandbox.
"""
import ast
import importlib
import importlib.abc
import sys
from pathlib import Path

MODEL_SDKS = frozenset({"anthropic", "openai", "google.generativeai", "google.genai", "mistralai", "cohere", "ollama",
                        "litellm", "boto3.bedrock", "vertexai", "groq", "together"})


def _top(name):
    return name.split(".")[0]


def _banned(name, banned):
    return any(name == b or name.startswith(b + ".") or (_top(b) == b and _top(name) == b) for b in banned)


def lint(paths, allow=(), banned=MODEL_SDKS):
    """-> [(file, line, module)] for every model SDK import outside the allowed files."""
    allowed = {Path(a).resolve() for a in allow}
    found = []
    files = [f for p in paths for f in ([Path(p)] if Path(p).is_file() else Path(p).rglob("*.py"))]
    for f in sorted(set(files)):
        if f.resolve() in allowed or "site-packages" in f.parts:
            continue
        try:
            tree = ast.parse(f.read_text(), str(f))
        except (SyntaxError, UnicodeDecodeError):
            found.append((str(f), 0, "(file does not parse: can't be checked)"))
            continue
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            elif isinstance(node, ast.Call):
                fn = node.func
                target = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                if target in ("__import__", "import_module") and node.args and isinstance(node.args[0], ast.Constant):
                    names = [str(node.args[0].value)]
            for n in names:
                if _banned(n, banned):
                    found.append((str(f), node.lineno, n))
                    break
    return found


class _Refuse(importlib.abc.MetaPathFinder):
    def __init__(self, banned):
        self.banned = banned

    def find_spec(self, name, path=None, target=None):
        if _banned(name, self.banned):
            raise ImportError(f"{name} is sealed: model clients are reached only through the pre-model gate "
                              f"(shio.governance.preflight)")
        return None


class ImportSeal:
    """with ImportSeal({"anthropic"}) as seal: agent code can't import anthropic; the transport uses
    seal.module("anthropic")."""

    def __init__(self, banned=MODEL_SDKS):
        self.banned = frozenset(banned)
        self._private, self._finder = {}, _Refuse(self.banned)

    def __enter__(self):
        for name in list(sys.modules):
            if _banned(name, self.banned):
                self._private[name] = sys.modules.pop(name)
        sys.meta_path.insert(0, self._finder)
        return self

    def module(self, name):
        """For the gate's transport only: the real module, imported once outside the seal if needed."""
        if name not in self._private:
            sys.meta_path.remove(self._finder)
            try:
                self._private[name] = importlib.import_module(name)
                for n in [n for n in sys.modules if _banned(n, self.banned)]:
                    self._private.setdefault(n, sys.modules.pop(n))
            finally:
                sys.meta_path.insert(0, self._finder)
        return self._private[name]

    def __exit__(self, *exc):
        if self._finder in sys.meta_path:
            sys.meta_path.remove(self._finder)
        sys.modules.update(self._private)
        return False
