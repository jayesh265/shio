# Microsoft Agent Governance Toolkit as a policy backend

[Microsoft's Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) (AGT, MIT) is a
deterministic policy engine for agent actions. Shio Guard uses it as one more policy backend, alongside the built-in
Cedar subset and OPA (D31). It also ships as a check adapter (D32). Shio keeps all of its own rules while using it.

```bash
pip install "shio-lang[agt]"         # agent-governance-toolkit-core==5.0.0; needs Python 3.11 or later
```

## What it gives you

| Piece | What it is |
|---|---|
| `AgtBackend(policies)` | AGT's `PolicyEngine` behind Shio's `PolicyBackend` interface. `decide(action, args)` returns a frozen `AgtDecision` (allowed, effect, rule, policy, reason, approvers, layer). |
| `AgtGate(policies, ledger=...)` | AGT's policy enforced on any agent's tool calls, whether written in Shio or not. `gate.wrap(fn)` raises `AgtDenied` before a call the policy doesn't allow. Each decision becomes a signed, hash-chained entry in a Shio ledger. |
| `AgtPolicyCheck` | The same decision as a check adapter: pinned to AGT 5.0.0, reviewed, and shipped with fixtures, so an agent card names the engine and its version. |
| `import_audit(log)` | Reads AGT's own audit log, first verifying its hash chain. |

```python
from shio.governance.adapters_ext.agt import AgtGate

gate = AgtGate("policies/helpdesk.yaml", ledger="workspace/gates", agent="helpdesk", requester="helpdesk-bot",
               approver=lambda req: ask_a_person(req))      # -> (approved, by, note)
issue_refund = gate.wrap(issue_refund)
```

Policies are standard AGT YAML. A policy written for AGT's own `govern()` works here unchanged, because the gate
builds the same evaluation context: `{"action": {"type": <tool>}, <arg>: {"value": v}}`.

## What Shio adds on top

- **Defence in depth.** Give the gate a Shio Guard session (`guard=`) and Guard's provenance check runs first, then
  AGT's policy. Either one can stop a call. Each ledger entry records which layer decided.
- **Approvals bound to the exact call.** AGT's `require_approval` effect goes to Shio's approver along with the
  call's sha256, and the approval record stores that digest. Maker-checker applies: the agent's requester can't approve
  its own call. If the approver fails or returns no name, the call is refused.
- **A ledger, not a log.** Gate decisions go into a `SignedChain` (`agt-gate.jsonl`): sequenced, hash-chained and
  optionally signed. Editing or removing an entry breaks verification. Entries hold argument *names*, never their
  values, so personal data in arguments never reaches the ledger.
- **Fail-safe (strict mode, on by default).** Strict mode can only tighten AGT's decision, never loosen it:
  - *At load:* AGT's evaluator understands `==`, `!=`, `in [...]`, number comparisons and bare field names, joined
    by `and`/`or`. It treats any other condition as never matching, so a deny rule written another way would silently
    never deny. Shio refuses to load such a policy and says which rule is the problem.
  - *At decision time:* AGT reads a missing number as 0 and a non-number as "no match". So under AGT alone,
    `amount.value > 500` lets a refund with no amount (or `amount="lots"`) through. When AGT allows a call, Shio
    re-evaluates each deny and require_approval rule in three-valued logic (true, false, unknown). A rule that can't
    be ruled out applies: a deny rule denies, and an approval rule asks a person. The decision's layer is
    `shio-strict`.
  - An engine error is a denial (`effect: "error"`), never a pass.

## Limits

- AGT runs in the same process as the agent, as AGT's own README also says. The gate stops calls the agent makes
  through it. It does not stop code that calls the tool directly.
- AGT's rate limits, execution rings, trust scoring, SRE features and approval handlers are not used. Approvals go
  through Shio's approver.
- Strict mode mirrors AGT 5.0.0's condition grammar. The pin is exact: a new AGT version means re-checking that
  grammar, the conformance fixtures and the licence check.
- Licence: AGT is MIT. Its dependency `certifi` (via `httpx`) is MPL-2.0, which is allowed only by a policy
  exception that counsel has not yet approved, so a strict licence check fails until counsel decides.

Tests: `tests/test_governance_agt.py` (11 tests, skipped where AGT isn't installed).
