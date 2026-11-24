# Durable execution (experimental)

These are runs that survive a crash, a restart or a three-day wait for an approver, with no model call or side effect
repeated. `shio.durable` uses only the standard library (SQLite), so the base install still depends only on pydantic.
It is **experimental** until the outside review covers it (see [Readiness](#readiness)).

```python
from shio.durable import Engine, Journal, Worker

eng = Engine(Journal(".shio/runs.db"), records=".shio/records")

@eng.workflow("refunds")
def refunds(ctx, inp):
    plan = ctx.read("plan", model.propose, inp["request"])      # journaled: replayed, never re-asked
    ctx.wait(seconds=120)                                         # a timer stored in the journal
    return ctx.act("issue_refund", {"order": "A-1"}, issue_refund, gate=gate)   # gated, idempotent

run_id = eng.start("refunds", {"request": "...", "requester": "dana"})
eng.run(run_id)          # completed | waiting | held | failed. Call again from any process to resume
```

```bash
shio runs list --db .shio/runs.db
shio runs show RUN --db .shio/runs.db                      # status, held call, next timer, journal check
shio runs approve RUN HOLD --by "M. Chen" --role finance   # then: shio resume RUN --agent agent.py
shio runs resolve RUN KEY not_done --by "M. Chen"          # a call whose outcome a crash left unknown
shio worker --agent agent.py                               # take runnable runs, one lease at a time
shio runs migrate RUN --agent agent.py --by NAME --reason "move to v2"
```

## How it works

It uses event sourcing. A workflow is deterministic Python, and everything non-deterministic it does goes through the
context, which journals it before and after:
- `ctx.read`: a model call or any read
- `ctx.act`: a tool call through the gate
- `ctx.wait`: a timer
- `ctx.now`: the clock

To resume, the engine re-executes the workflow from the top. Everything already journaled is answered from the
journal, and execution carries on at the first unfinished step.

| Package | What it does | Test |
|---|---|---|
| DUR-1 journal | Append-only events per run in SQLite, hash-chained and signed. When a run ends, a signed ledger record is derived from it, and `derive_record()` reproduces that record exactly | `test_a_finished_runs_journal_reproduces_its_signed_record` |
| DUR-2 resume | Re-execution answered from the journal; continues on any worker | `test_kill_at_every_step_boundary_repeats_no_model_call_or_side_effect` (every boundary of a 6-step run) |
| DUR-3 idempotency | Each act gets a key from run, step and argument hash, passed to the tool as `idempotency_key`. A call started but never completed is held for a person, never retried. A tool that raises `PermissionError` has refused before acting, which is a denial | `test_crash_between_a_payment_and_its_record_never_pays_twice` |
| DUR-4 durable approvals | A held call survives restarts. `approve` and `reject` work from any process, the CLI or a gateway, and need the approver role and four eyes. A deadline denies | `test_a_run_held_overnight_resumes_after_an_approval_in_a_new_process` |
| DUR-5 timers | `ctx.wait` stores its fire time; a worker picks the run up once it is due; it fires once | `test_a_two_minute_wait_survives_a_restart_and_fires_once` |
| DUR-6 retry policy | Reads retry with backoff. Acts follow their `Policy`, defaulting to no retry; a failing act is held with its error | `test_a_flaky_read_recovers_and_a_failing_act_is_held_with_its_error` |
| DUR-7 workers and leases | Atomic lease acquisition. Every append checks the lease in the same transaction, and `(run_id, seq)` is a primary key | `test_two_workers_never_run_the_same_step_and_a_dead_workers_run_is_picked_up` |
| DUR-8 versioning | A run pins its workflow's sha256; a different version refuses to continue; `migrate` is an explicit journal entry | `test_a_run_started_before_a_program_change_finishes_on_the_old_version` |
| DUR-10 inspector | `shio runs list` and `show` | `test_a_stuck_runs_state_held_call_and_next_timer_are_visible_from_the_cli` |
| DUR-9 Temporal backend | **Not built.** Not run; the brief's decision 2 is open | |

The gate is asked again on replay, even for steps already done. That lets a stateful gate such as a Guard session
rebuild its plan and ledger exactly. If a replayed decision differs from the journaled one, the run stops
(`NonDeterminism`); it never continues. `engine.replay(run_id)` re-executes a finished run strictly from its journal
and fails if anything would need a new event.

## Limits

- **Workflows must be deterministic** apart from `ctx` calls. Code that reads the clock, randomness or the network
  directly breaks replay. Replay catches a different sequence of steps, but not a different value computed from a
  hidden source.
- **A read interrupted mid-call is asked again.** The provider may have answered and charged once already. Acts are
  never repeated without a person.
- **"Unknown outcome" needs a person.** Shio can't tell whether an external system acted. The tool's idempotency key
  lets the person, or the provider, check.
- **Postgres is not built.** SQLite in WAL mode serves one host; several workers on different hosts need a shared
  store.
- **Guard traces are written again on each replay.** The journal and the derived record are the source of truth.
- **No OpenTelemetry spans per step yet.** That's part of DUR-10.

## Readiness

These are the brief's eight gates, as they stand after this work:

| Gate | Status |
|---|---|
| Outside review of the boundary, extended to the harness and durable code | Not done (a person's job) |
| Gate tested against attacks that get past the model | Partial: the adaptive attacker covers the deterministic layers (docs/governance/requirements.md); weaker-model runs still to do |
| One production deployment | Not done |
| Crash-resume proof | Done for the local engine: kill at every boundary, no repeated model or tool call |
| Harness comparison on shared tasks (Shio, Hermes, plain Python) | Not started; needs Hermes and models |
| Approver identity | Done for Slack (signed requests), web and email (signed tokens); not OIDC |
| Sandbox before shell tools | Done: HAR-2's tests pass, and the shell tool runs only through it |
| Quickstart and docs | Done: `shio init`, a recorded, replayable run offline in about a second |
