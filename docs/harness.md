# The code-driven harness (experimental)

The model proposes each step as a typed reading. Code decides what runs, and every tool call goes through the Guard
gate. The harness runs on the [durable engine](durable.md), so every step is journaled, resumable and replayable. Its
modules are new and additive (`shio.harness`, `shio.sandbox`, `shio.tools`, `shio.gateways`, `shio.adapters`), and
nothing in the frozen API changed.

```bash
shio init coding my-agent && cd my-agent && python agent.py      # offline, scripted model, a refusal in the record
shio runs show <run id> --db .shio/runs.db
```

| Package | Module | What it guarantees | Test |
|---|---|---|---|
| HAR-1 agent loop | `harness/loop.py` (`AgentLoop`, `ToolSpec`, `Budget`) | Propose, check, run guarded, record, repeat. A malformed proposal is no step; an undeclared tool is refused; reads and acts both go through the Guard; step, cost and time budgets and a stop function apply | `test_a_fake_model_drives_twenty_steps_every_step_recorded_and_replayed`, `test_an_unplanned_or_injected_tool_call_is_denied_and_the_run_stops_at_its_budget` |
| HAR-2 sandbox | `sandbox/` | macOS sandbox-exec, Linux bubblewrap or Docker: writes only inside the scope, network denied (or a host allowlist on macOS), CPU and wall limits, every run recorded. With no backend it refuses rather than running unconfined | `test_sandbox_refuses_writes_outside_scope_and_network_and_kills_runaways` |
| HAR-3 context engine | `harness/context.py` | Segments keep source, trust and hash. `@file` stays inside the root; AGENTS.md and CLAUDE.md load as trusted; compression keeps lineage, and untrusted stays untrusted | `test_compressed_context_keeps_lineage_and_untrusted_stays_untrusted` |
| HAR-4 memory | `harness/memory.py` | A write is an `acts` call through the Guard. Its trust is decided by code from the Guard ledger, so untrusted text can't become trusted memory. Erasure is recorded on the chain | `test_untrusted_text_cant_become_trusted_memory_and_erase_is_recorded` |
| HAR-5 skills | `harness/skills.py` | Hashed and pinned; a changed file fails to load. An `acts` tool needs a review entry, by someone other than the person who pinned it. A skill can't call or widen undeclared tools | `test_skills_are_pinned_reviewed_and_cant_widen_or_call_undeclared_tools` |
| HAR-6 subagents | `harness/delegate.py`, `ctx.child` | A child gets only tools its parent has. Its answer returns as untrusted data, and the parent's journal names the child's record sha256 | `test_a_child_cant_have_more_tools_and_the_parent_names_its_record` |
| HAR-7 scheduler | `harness/schedule.py` | Cron and HMAC-signed webhooks; each slot fires once, even with two schedulers. Unattended runs hold every act unless a rule allows it; webhook payloads are untrusted | `test_cron_and_a_scheduled_run_stops_in_hold_at_its_first_act` |
| HAR-8 gateways | `gateways/` | Slack (signed requests, five-minute window), web and email (HMAC tokens bound to the run, the hold and the identity). The approver comes from the channel, and a requester can't approve their own request | `test_slack_approval_takes_identity_from_the_channel_and_records_the_exact_call`, `test_web_and_email_tokens_are_bound_to_one_call_and_identity` |
| HAR-9 tools | `tools/` | Scoped file read and write (symlink- and `..`-safe), allowlisted HTTPS fetch (untrusted, its URL a Guard control value), shell only through the sandbox, read-only git, SELECT-only SQLite | `test_each_vetted_tool_refuses_its_injection_case`, `test_http_fetch_of_an_injected_address_is_denied_by_the_guard` |
| HAR-10 adapters | `adapters/claude_code.py`, `shio hook claude-code` | Claude Code PreToolUse hook: argument policy plus temporal rules per session, signed ledger entries, and "ask" (never "allow") on any error | `test_claude_code_hook_denies_the_injected_email_scenario_and_records_it` |
| HAR-11 credential handles | `harness/secrets.py` | The agent sees `secret://name`. The tool resolves it for the call only, and results and errors are scrubbed. The test scans every file the run wrote | `test_a_secret_never_reaches_the_prompt_journal_record_or_trace` |
| HAR-12 install and templates | `harness/templates.py`, `shio init` | Coding and clinical-intake agents, offline on a scripted model, giving a recorded, replayable run in seconds | `test_a_new_user_reaches_a_recorded_replayable_run_offline_in_seconds` |

## Limits

- **Hermes and the OpenAI Agents SDK adapters are not built.** The brief says to verify each host's plugin API first,
  and that wasn't possible offline. The Claude Code hook protocol is the documented PreToolUse JSON.
- **The loop has no `.shio` syntax.** SPEC.md has no loop form; adding one goes through SPEC.md first.
- **Memory provenance is matched by text windows** against untrusted outputs this task read, so a paraphrase of
  injected text can pass as trusted. Recalled trusted memory is still checked by the Guard like any trusted record.
- **The sandbox's network allowlist** is macOS-only (bubblewrap and Docker give no network or all of it); see
  `shio/sandbox` for each backend's limits.
- **The Claude Code hook** sees the tool input, not where its values came from; it's a policy check, not provenance.
  Its session state is a JSON file without locking between concurrent hook processes.
- **Gateways** don't cover Teams or Jira, and there's no OIDC identity.
- **All of this is new trusted code.** It's labelled experimental until the outside review covers it.
