# Changelog

Shio follows [semantic versioning](https://semver.org). Until 1.0, a minor version (0.x) may change the language or the
API; every such change is listed here.

## Unreleased: Shio Guard

Governance over Shio agents, built to the Shio Guard build plan (all five phases; see
[docs/governance/README.md](docs/governance/README.md) for each deliverable, its test, and what still needs a person).
New package `shio.governance` and 13 built-in packs in `shio/packs/`; new commands `shio registry | assess | pack |
adapters | licences | eval | impact | effectiveness | monitors | incident | safety-case | policy-draft | release | cds |
cedar | credo | console`; `shio evidence --framework` builds framework bundles; `shio verify` also verifies cards,
bundles, sealed documents and signed chains. Two reference agents in `examples/medical/` (simulated data and models).

Also in this release:

- **Live monitor.** `shio console` now serves `/monitor`, a read-only dashboard of every checkpoint (ledger
  integrity, checks, sign-offs, cards, packs, evals, drift and incidents, tool-call gates, evidence) over a JSON API
  (`/api/<view>`). `--workspace` serves a whole workspace folder, and `--demo DIR` builds a synthetic one. The page's
  CSP allows scripts from the console only, and the console answers only loopback Host headers when bound to
  loopback. See docs/governance/monitor.md.
- **Microsoft Agent Governance Toolkit.** `shio-lang[agt]` adds AGT 5.0.0 as a policy backend (`AgtBackend`), a tool
  gate with signed ledger entries and call-bound approvals (`AgtGate`), and a check adapter (`AgtPolicyCheck`). Strict
  mode refuses rules AGT could never match and denies when a deny rule's input is missing or unreadable (AGT alone
  reads a missing number as 0). See docs/governance/microsoft-agt.md.

- **Pre-model compliance gate and policy packs** (the policy pack specification). `shio.governance.preflight`: the
  compliance context, model profiles and registries (loaded strictly), a signed attestation ledger, a seven-step gate
  with a strictest-wins outcome lattice, routing, redaction by tokenisation with a second detector pass, holds with
  named-role maker-checker approval, a signed record written before any call (hashes only), a single-use bound
  client, output leak checks, fail-closed everywhere, a no-bypass lint and import seal. 35 enforced controls, each
  with fixtures and a mutation test. 13 new draft packs generated from the spec (`tools/spec_packs.py`); the pack
  format gains `gate` and `attestation` proofs, `stage`, `on_fail` and `planned` controls. `shio preflight
  check | attest | attestations | coverage | lint | fixtures | demo`; a Pre-model gate view in the monitor; the
  coverage matrix in docs/governance/coverage.md. See docs/governance/preflight.md.

- **Product requirements (PRD), first round** (see docs/governance/requirements.md for every requirement's status):
  argument-level policies with plan narrowing and strict value reading (CORE-2, `ArgPolicy`, `ArgGate`); an adaptive
  attacker with pass^k (EVAL-1, `shio attack run`); temporal policies compiled to a monitor (CORE-3, `shio temporal`);
  circuit breakers and a kill switch (CORE-4); MCP definition pinning (CORE-6); detector plug-ins as signals (CORE-7);
  an OpenAI-compatible drop-in proxy (INT-2, `shio proxy`); `shio doctor` and discovery (DX-3, GOV-2); the registry as
  code with a dependency graph (GOV-1, GOV-6, `shio inventory`); risk classification and a risk register (GOV-3,
  `shio risk`); a SOC 2 draft pack (GOV-4); the control evidence report and reviewer metrics (EVID-1, OVR-3,
  `shio report`); a ranked, capped review queue (OVR-1); expiring exceptions and four-eyes policy changes (GOV-5);
  calibrated clinical abstention with an exact error bound and a patient-facing release gate (MED-3, MED-8);
  `shio quickstart` (DX-1), `shio preflight explain` (DX-2), `shio preflight bench` (NFR-4), a GitHub Action with a
  coverage diff (INT-3), and a proposed stability policy (docs/STABILITY.md).
- **Pre-model gate hardening, found by the adaptive attacker.** Disguised identifiers (spacing, spelled-out or
  non-ASCII digits, full-width, zero-width, homoglyphs, " at " / " dot ", base64) went through redaction 100% of the
  time. A de-obfuscation pass now runs in classification and in the second pass after redaction; the same attacker
  found no bypass afterwards (docs/governance/results/adaptive.json).

- **Code-driven harness and durable execution** (experimental; the build brief's HAR and DUR packages). New modules,
  standard library only: `shio.durable` (SQLite run journal, resume by replay, idempotent acts that hold on an unknown
  outcome, durable approvals with deadlines, timers, retry policy, workers and leases, version pinning and `migrate`,
  a signed ledger record derived from the journal), `shio.harness` (the agent loop over the Guard gate, context
  engine with lineage, memory with provenance and erasure, signed and reviewed skills, subagents, credential
  handles, cron and webhook triggers, `shio init` templates), `shio.sandbox` (sandbox-exec, bubblewrap and Docker
  backends, fail closed), `shio.tools` (scoped file, allowlisted fetch, sandboxed shell, read-only git and SQL),
  `shio.gateways` (Slack, web and email approvers with channel identity) and `shio.adapters.claude_code` (a
  PreToolUse hook). Commands: `shio runs | resume | worker | init | hook`. Not built: the Temporal backend (DUR-9),
  Hermes and OpenAI Agents SDK adapters, Postgres. See docs/harness.md and docs/durable.md.

Changes to existing behaviour:

- **Signed chains (performance).** Appends read only the last entry instead of the whole file (they were O(n) each,
  O(n^2) overall).
- **med.phi.** The MRN pattern accepts any single punctuation mark after the keyword ("MRN= 123...").
- **med.phi (fix).** Keyword identifier patterns (MRN, device, account, licence, plan ID) no longer match inside base64
  signatures and hashes ("+mRn...", "udIa..."), which made the PHI-in-records test fail about once in 4,000 runs.
- **CLI.** A command that returns a non-zero status now exits with it (so `shio preflight lint` fails CI).
- **Evidence (fix).** `shio evidence` no longer crashes on records that carry no program path (it tried to read the
  current directory as the program).

- **Ledger (fix).** `split` now moves check arguments that aren't JSON (recorded as `opaque` reprs, such as a `Source`
  passed to a check) to the vault. Before, their repr stayed in the clear record and could carry free text or personal
  data. Found while building the referral agent; regression test `test_check_arguments_that_are_not_json_go_to_the_vault`.
- **Records.** A top-level record may carry `packs` (the pack versions whose checks decided, with their sha256) and
  `slices` (coarse monitoring groups a pack check vetted); a check record may carry `controls` (the pack controls it
  enforced). A failed pack check with no message of its own records the pack's reason. New: `shio.core.cite()`.
- **Replay.** `shio.replay.replay_detail()` returns structured results and can answer reads with a new model (all, or
  swapped by recorded name), which change-impact replay uses. `replay()` is unchanged.
- **Evidence.** Records whose `record_type` is not a decision (incidents, safety events) are counted as events, not
  decisions. `build(..., write_manifest=False)` lets a framework bundle write one manifest over everything.

## 1.0.0rc2 (2026-10-23)

Security fixes for the nine findings in [docs/REVIEW-BRIEF.md](docs/REVIEW-BRIEF.md) §4, found preparing the outside
review. Each has a regression test in `tests/test_review_findings.py`, and its probe in `docs/review/probes/` now
shows it stopped.

- **Ledger (L1, L2).** `verify` with a public key or HMAC secret (and `shio verify --pubkey`, and the evidence manifest
  check) now treats an unsigned or unverifiable entry as a problem, so an appended unsigned sign-off no longer passes.
  Event entries (sign-off, label, erasure, migration) are written as `"v": 2`: their hash and signature cover `seq`
  and `prev`, so a signed event followed only by events can't be deleted and the rest re-linked. Ledgers written
  before 1.0 still verify, with a note; an old-form event after a new one is a problem.
- **Guard (G1-G4).** A control value is grounded only where trusted text holds it as a whole token or address
  (`bob@acme.co` is no longer grounded by `bob@acme.com`). Digits-only values are judged when an IBAN/account is
  wanted. An approval covers one run of exactly that call (the next identical call is held again). The requester
  defaults to the actor, `guard ... approved by` passes it, and four eyes compares names like the ledger's
  maker-checker. Same verdict as before on all 3,058 recorded AgentDojo calls; offline obedient attacker 0 of 249.
- **Compiler (B1-B3).** `.shio` code can't reach the runtime's private names (`_open`, `_run`, `_SEALED`...) as
  attributes or imports, `last_run`, `builtins`, `attrgetter`/`methodcaller`; `getattr` in `.shio` code is
  `shio.core.checked_getattr`, which refuses computed private or dunder names, and mutating methods inside a check.
  A check can't take a mutating method or a dunder at all, and functions, lambdas and method aliases defined in the
  same `.shio` file are checked for purity when a check uses them. Regulated programs can't name `__shio` themselves.
  Possibly breaking: `.shio` code that used these names, or a check that calls a same-file helper which changes
  outside state, no longer compiles.

## 1.0.0rc1 (2026-10-21)

The first release candidate for 1.0. Nothing new: the public API in [docs/API.md](docs/API.md) is frozen as 1.0, and
from here to 1.0.0 only fixes land. Install with `pip install --pre shio-lang`.

1.0.0 is final once these are done: an outside security review of the boundary, at least one production deployment,
and the benchmark results on Haiku 5.5. Classifier: Development Status 4 (Beta).

## 0.9.0 (2026-10-20)

- **Images and PDFs, natively.** `Source.image(path)` (in `.shio`: `image(path)`) for PNG, JPEG, GIF and WebP, and
  `Source.from_pdf(path)` now records that it is a PDF. Claude gets images and PDFs as image and document blocks (a
  PDF sent as a document isn't also sent as text); `openai_compat(..., vision=True)` sends images as data URLs, which
  covers Ollama vision models. A model that can't read a source fails the read, so the reading is null and its checks
  fail. Traces record each source's media type and SHA-256. Files over 20 MB are refused with a clear error.

## 0.8.0 (2026-10-20)

- **Async agents.** `@shio.agent` on an `async def`, and `async agent` in `.shio`: reads become `await aread(...)`, so
  the model call doesn't block the event loop. A model with `async apropose(request)` is awaited; any other runs in a
  worker thread. Concurrent agents keep their own readings and traces (context variables).
- **`shio label`.** A reviewer marks a recorded decision right or wrong (`--right|--wrong --by NAME [--note]`). The
  label is a ledger entry bound to the record's hash, signed when a key is set, and checked by `shio verify`.
  `trace.load` gives each run its labels, and `shio train` leaves decisions labelled wrong out of the fine-tune set.

## 0.7.0 (2026-10-20)

- **Typed tools in the language.** `tool NAME(ARG: KIND, ...) reads [trusted|untrusted|mixed] [opens] = fn` and
  `tool NAME(...) acts = fn` declare an agent's tools (kinds `email`, `url`, `iban`, `name`, `text` or a plain type);
  `guard REQUEST by MODEL [approved by APPROVER]` starts the task (Shio Guard's blind plan); `call NAME(args)` calls a
  tool. An `acts` call compiles only inside a rule, and at run time goes through the gate: it runs, or raises
  `GateHeld` (after asking the approver) or `GateDenied`, which the rule can catch. Calling an `acts` tool from plain
  Python, outside a rule or without `guard`, raises `BoundaryError`. Example: `examples/tools/mail.shio`.
- **README and docs refreshed**: PyPI and CI badges, the language table, and the status section.

## 0.6.0 (2026-10-20)

- **Approvals for held calls** (`shio.guard`). A held call gets an id; `Guard(approver=...)` asks a person
  (`ApprovalRequest -> Approval`; `terminal_approver()` built in), or `Session.approve(id, by=)` / `reject(...)`
  answer it later. Approvals are bound to the exact arguments, only lift a hold (a denied call stays denied, and an
  approved one is re-checked), follow four eyes (`start(requester=)`: the requester can't approve their own task),
  and are recorded as runs in the signed chain. The adapters ask the approver too.
- **SPEC: tools as typed effects.** The design for `tool` declarations and `call` in the language, planned for 0.7.0.

## 0.5.0 (2026-10-20)

- **Shio Guard adapters.** `Session.openai_tool_messages(tool_calls, run)` screens an OpenAI-style assistant
  message's tool calls and returns the tool messages; `Session.anthropic_tool_results(content, run)` does the same
  for Claude's `tool_use` blocks (refusals marked `is_error`); `guard.wrap_tools(session, tools)` wraps LangChain-style
  tools and plain functions; `await Session.mcp_call(client, name, args)` gates calls to an MCP server and records what
  it returned. A held or refused call never runs, and the model is told why.
- **Tool declarations from schemas.** `Tool.infer(name, description, schema)` guesses recipient, URL, IBAN and
  free-text arguments from names and formats; `Tool.from_mcp(tool)` uses MCP's `readOnlyHint` and `openWorldHint`.
- **Docs site** at https://pratikkp24.github.io/shio/ (MkDocs, built in CI with `--strict`, published from main).

## 0.4.0 (2026-10-20)

- **Trace sinks** (`shio.trace`). Copies of every signed record to SQL (`SqlSink`, any DB-API driver), S3
  (`S3Sink`, `pip install 'shio-lang[s3]'`), OpenTelemetry (`OtelSink`: a span per run, child spans per read, check
  and rule; `pip install 'shio-lang[otel]'`) or a JSONL file (`JsonlSink`). The local chain stays the source of truth;
  copies carry no vault data, so erasure still works; a failing sink never fails a run. `Background()` sends off the
  run's thread.
- **A declared public API.** `shio.__all__`, and [docs/API.md](docs/API.md): what is public, what is internal, and
  how each can change. Use `shio.Source` rather than `shio.core.Source`.

## 0.3.0 (2026-10-20)

- **Shio Guard** (`shio.guard`). Put Shio in front of any agent's tools without rewriting the agent: declare the
  tools (`Tool(name, side_effect=, control=, content=, output=)`), start a task from the user's request (a blind plan),
  and check each proposed call: run, hold for a person, or deny, with the reason. Provenance by value: recipients,
  URLs and IBANs must come from trusted text or a place the request pointed at; addresses the agent never read are
  denied; delegated requests hold. `Session.reply()` finds names an injection planted in a final answer. Replayed over
  the 3,058 tool calls of the AgentDojo run, it decides every one as the benchmarked gate did.
- **Anthropic backend.** `models.anthropic("claude-opus-5-5", effort=...)` through the official SDK with structured
  outputs (`pip install 'shio-lang[anthropic]'`). A refusal gives a null reading.
- **Retries and pacing.** Every backend retries timeouts, 429 and 5xx with backoff, honouring `Retry-After`
  (`retries=`); `per_minute=` paces calls across threads.
- **Boundary fuzzing in CI.** Generated programs try to get a reading into plain code (10,000 across five seeds
  refused at compile time), and 1,000+ expressions run against a live reading from Python: none leak.
- **Dual licence.** Shio is now MIT OR Apache-2.0, at your option.
- `AGENTS.md`: how to work in this repository, for coding agents and people.

## 0.2.0 (2026-10-20)

The first release on PyPI. (0.1.0 was never published.)

- **The language.** `read`, `check`, `when`, `rule` and `signoff`. A model's reading can only be looked at in a check,
  a when, a rule or a later read's `seeing` clause. Anywhere else is a compile error, and the runtime enforces it again.
- **The boundary is hardened.** What a model said is sealed in a private registry: `reading._value`, `.raw`,
  `.request`, copying and pickling are refused. Reflection (`locals()`, `vars()`, `eval`, `exec`, frames, and `gc`,
  `inspect` and `ctypes` scans) is a compile error. A `check` or `when` only decides: no `:=` and no mutating calls.
  `tests/test_boundary_escapes.py` lists every escape route known and what stops it.
- **Models.** `ollama()` with weight-digest pinning, `openai_compat()` for any OpenAI-compatible API, and `replay()`
  for tests. A failing, unreachable or unreadable model gives a null reading that fails its checks, never a crash.
- **Traces.** Every run is saved: readings, checks, rules, outcome. `shio replay` re-runs it; `shio train` turns
  traces into SFT and GRPO data with the checks as the reward.
- **Regulated mode** (`pip install 'shio-lang[regulated]'`). Hash-chained, signed records (Ed25519 or HMAC); personal
  data in an AES-256-GCM vault that can be erased without breaking the chain; policy tables in force on a date;
  reason codes; maker-checker sign-off.
- **Benchmark.** AgentDojo v1.2.2 on Opus 5.5: 0/949 attacks succeeded with Shio, against 17/949 with no defence.
  Normal tasks completed: 85.6% with Shio, 92.8% without. See the README for the setup and its limits.
