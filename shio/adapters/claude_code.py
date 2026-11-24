"""HAR-10 (first host): Shio Guard as a Claude Code PreToolUse hook.

Claude Code runs a hook command before each tool call, passing JSON on stdin (session_id, cwd, hook_event_name,
tool_name, tool_input) and reading a decision from stdout:
    {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow" | "deny" | "ask",
                            "permissionDecisionReason": "..."}}
Configure it in .claude/settings.json:
    {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command",
        "command": "shio hook claude-code --policy .shio/argpolicy.json --rules .shio/session.rules --ledger .shio/ledger"}]}]}}

What it decides, per call, with state kept per Claude Code session in a journal:
  argument policy   (CORE-2) the tool's input against .shio/argpolicy.json; deny -> deny, hold -> ask (the person is
                    asked in Claude Code)
  temporal rules    (CORE-3) e.g. "never Bash after mcp__mail__read_inbox": the session's earlier calls are replayed
                    into the monitor from the journal, so the rule holds across separate hook processes
  default           tools the policy doesn't list are allowed unless the policy's default is deny
Every decision is a signed, hash-chained entry in the ledger folder (SignedChain "claude-code"), with the session, the
tool, a hash of its input (not the input) and why. If anything in the hook fails, it answers "ask", never "allow".

Limits: Claude Code's other permission settings still apply; the hook sees the tool input Claude proposes, not
where its values came from (the in-process Guard sees provenance); hooks run on the user's machine with the user's
rights, so this is a policy check, not a sandbox.
"""
import hashlib
import json
import sys
import time
from pathlib import Path


def decide(event, policy=None, rules=None, ledger=None, state=None):
    tool, args = event.get("tool_name", ""), event.get("tool_input") or {}
    session = event.get("session_id", "unknown")
    reasons, outcome = [], "allow"
    if policy is not None:
        d = policy.check(tool, args) if tool in policy.tools or policy.default == "deny" else None
        if d is not None and not d.allowed:
            outcome = "deny" if d.outcome == "deny" else "ask"
            reasons.append(d.explain())
    if rules:
        from ..governance.enforce.temporal import Monitor
        m = Monitor(rules)
        history = (state or {}).get(session, [])
        for i, h in enumerate(history):
            m.observe(h, float(i))
        v = m.check(tool, float(len(history)))
        if v:
            outcome = "deny"
            reasons += v
    if outcome == "allow" and state is not None:
        state.setdefault(session, []).append(tool)
    entry = {"session": session, "tool": tool, "input_sha256": hashlib.sha256(json.dumps(args, sort_keys=True,
                                                                                         default=str).encode())
             .hexdigest(), "decision": outcome, "why": "; ".join(reasons) or "within policy", "time": time.time()}
    if ledger:
        from ..governance.chain import SignedChain
        SignedChain(ledger, "claude-code").append("hook_decision", entry)
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": outcome,
                                   "permissionDecisionReason": f"Shio: {entry['why']}"}}


def main(argv=None, stdin=None, stdout=None):
    import argparse
    p = argparse.ArgumentParser(prog="shio hook claude-code")
    p.add_argument("--policy")
    p.add_argument("--rules")
    p.add_argument("--ledger", default=".shio/ledger")
    a = p.parse_args(argv)
    out = stdout or sys.stdout
    try:
        event = json.loads((stdin or sys.stdin).read())
        policy = None
        if a.policy:
            from ..governance.enforce.argpolicy import ArgPolicy
            policy = ArgPolicy.load(a.policy)
        rules = Path(a.rules).read_text() if a.rules else None
        state_file = Path(a.ledger) / "claude-code-sessions.json"
        state = json.loads(state_file.read_text()) if state_file.exists() else {}
        res = decide(event, policy, rules, a.ledger, state)
        Path(a.ledger).mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps(state))
    except Exception as e:                       # fail closed: never "allow" on error
        res = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                      "permissionDecisionReason": f"Shio hook error ({type(e).__name__}): asking"}}
    out.write(json.dumps(res))
    return 0
