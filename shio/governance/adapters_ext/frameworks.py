"""Agent-framework adapters (D32): Shio Guard's gate over the tool calls of agents built with LangChain, the OpenAI
SDK, the Claude SDK and MCP, as check adapters with manifests, pins and conformance fixtures.

The gate itself is shio.guard (a blind plan from the user's request, provenance of every control value). These
classes give each framework its adapter identity, so an agent card lists which framework adapter decided its tool
calls, at which version, under which licence:

  OpenAIToolGate.tool_messages(tool_calls, run)     an assistant message's tool calls -> the tool messages
  ClaudeToolGate.tool_results(content, run)         Claude's tool_use blocks -> tool_result blocks
  LangChainToolGate.wrap(tools)                     LangChain-style tools and plain functions, gated
  MCPToolGate.call(client, name, args)              a call to an MCP server, gated (async)

decide(name, args) is the common check: a call the gate would run passes; held or denied fails.
"""
import contextlib
import tempfile

from ..adapters import CheckAdapter, Dependency, Manifest, TrustClass


@contextlib.contextmanager
def _scratch_traces():
    """Fixture sessions record their gate decisions in a throwaway folder, not the caller's traces."""
    from ... import core
    saved = core._config.get("trace_dir")
    core._config["trace_dir"] = tempfile.mkdtemp(prefix="shio-gate-fixture-")
    try:
        yield
    finally:
        core._config["trace_dir"] = saved


def fixture_session():
    """A Guard session for conformance: a replay planner, so it is deterministic and needs no model."""
    from ... import guard
    from ...models import replay
    tools = [guard.Tool("read_notes", output="untrusted"),
             guard.Tool("send_email", side_effect=True, control={"to": "email"}, content=["body"])]
    planner = replay(lambda req: {"actions": "email the summary", "delegated": False, "tools": ["send_email"],
                                  "sources": []}, name="fixture planner")
    with _scratch_traces():
        return guard.Guard(tools, planner).start("Summarise the notes and email them to dana@acme.com",
                                                 requester="fixture")


class GuardGate(CheckAdapter):
    manifest = Manifest("shio-guard-gate", "1.0.0", TrustClass.CHECK, "MIT OR Apache-2.0",
                        "Shio Guard's gate over a proposed tool call", reviewed_by="shio maintainers (core)")
    fixtures = ((("send_email", {"to": "dana@acme.com", "body": "Q3 summary"}), True),
                (("send_email", {"to": "audit@acme-review.co", "body": "Q3 notes"}), False),
                (("delete_repo", {"name": "core"}), False))

    def __init__(self, session=None):
        self.session = session
        self._fixture = session is None

    def _s(self):
        if self.session is None:
            self.session = fixture_session()
        return self.session

    def decide(self, name, args):
        ctx = _scratch_traces() if self._fixture else contextlib.nullcontext()
        with ctx:
            d = self._s().check(name, args)
        return d.outcome == "run", f"{d.outcome}: {d.why}"


class OpenAIToolGate(GuardGate):
    manifest = Manifest("openai-tool-gate", "1.0.0", TrustClass.CHECK, "MIT OR Apache-2.0",
                        "Guard over OpenAI-style tool calls", (Dependency("openai", "==2.8.1", "Apache-2.0"),),
                        extra="openai", reviewed_by="shio maintainers (core)")

    def tool_messages(self, tool_calls, run):
        return self._s().openai_tool_messages(tool_calls, run)


class ClaudeToolGate(GuardGate):
    manifest = Manifest("claude-tool-gate", "1.0.0", TrustClass.CHECK, "MIT OR Apache-2.0",
                        "Guard over Claude tool_use blocks", (Dependency("anthropic", "==1.2.0", "MIT"),),
                        extra="anthropic", reviewed_by="shio maintainers (core)")

    def tool_results(self, content, run):
        return self._s().anthropic_tool_results(content, run)


class LangChainToolGate(GuardGate):
    manifest = Manifest("langchain-tool-gate", "1.0.0", TrustClass.CHECK, "MIT OR Apache-2.0",
                        "Guard over LangChain-style tools", (Dependency("langchain-core", "==1.1.0", "MIT"),),
                        extra="langchain", reviewed_by="shio maintainers (core)")

    def wrap(self, tools):
        from ... import guard
        return guard.wrap_tools(self._s(), tools)


class MCPToolGate(GuardGate):
    manifest = Manifest("mcp-tool-gate", "1.0.0", TrustClass.CHECK, "MIT OR Apache-2.0",
                        "Guard over calls to an MCP server", (Dependency("mcp", "==1.22.0", "MIT"),),
                        extra="mcp", reviewed_by="shio maintainers (core)")

    async def call(self, client, name, args):
        return await self._s().mcp_call(client, name, args)
