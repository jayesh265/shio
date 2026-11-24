# Product requirements: traceability

Every requirement in *Shio Guard: product requirements, Credo AI parity, research trends and bets* (24 Nov 2026), with
where it lives, the test that shows it works, and what is missing. **Built** means it exists, with a test that
matches the PRD's "how we know it works". **Partial** means part of it is built and the rest is named. **Not built**
means not started; the reason is given.

Numbers quoted here come from files in `docs/governance/results/`. All of them are on synthetic data.

## Phase 1: Trust

| ID | Status | Where | Test | Missing |
|---|---|---|---|---|
| EVAL-1 adaptive attacker, pass^k | Built | `attack/adaptive.py`, `attack/scenarios.py`, `shio attack run` | `test_prd_trust.py` | Attacks text and values, not an LLM. The identifier detector was hardened against this same library, so other transformations may get through |
| EVAL-2 AgentDojo and ASB on three models | Not built | | | Needs model access and the benchmark harnesses; the earlier benchmark in the README is the only model-level number |
| CORE-2 argument-level policies | Built | `enforce/argpolicy.py` (`ArgPolicy`, `ArgGate`) | `test_a_hijacked_amount_with_a_valid_recipient_is_held` and 30 more | Rules name arguments of one call; cross-call relations are CORE-3 |
| CORE-10 fail closed by default | Built for the gate, argument policies, signals, proxy and breakers | `preflight/gate.py` and the rest | `test_fail_closed_every_way`, `test_detectors_are_signals_and_a_failing_detector_fails_closed` | No single fault-injection matrix yet across the older Guard and runtime components (those have their own tests) |
| EVID-2 offline verification | Built earlier | `shio verify`, `ledger.verify(head=)` | `tests/test_ledger*`, `test_an_outsider_verifies_the_card_and_bundle_offline_with_the_public_key` | Key rotation is documented in SECURITY.md; head anchoring outside the folder is manual |
| DX-1 quickstart under five minutes | Built | `shio quickstart` | `test_quickstart_blocks_an_attack_in_seconds` (about 0.6 s here) | Uses a scripted "model", not a local LLM |
| DX-2 plain-language reasons | Built for gate decisions | `preflight.gate.explain`, `shio preflight explain` | `test_explain_reads_like_a_sentence` | Not yet reviewed by a non-developer, which the PRD's test asks for |
| DX-7 stable API, deprecation window | Proposed policy | [STABILITY.md](../STABILITY.md) | | Maintainers adopt it at 1.0 |
| INT-1 adapters current | Partial | `adapters_ext/frameworks.py`, `agt.py` | `test_each_adapter_passes_conformance_and_the_licence_check` | Pins are chosen versions; CI doesn't yet test against current releases |
| NFR-1 security of Shio | Partial | THREAT-MODEL.md §8 | | The outside review is a person's job |

## Phase 2: Governance in code

| ID | Status | Where | Test | Missing |
|---|---|---|---|---|
| GOV-1 registry as code | Built | `inventory.py`, `shio inventory validate\|check` | `test_ci_fails_when_an_agent_uses_a_tool_its_entry_does_not_list` | Model checks compare names, not provider metadata |
| GOV-3 risk register and classification | Built | `risk.py`, `shio risk` | `test_risk_classification_worked_examples` (7 examples) | The PRD's test is "match a lawyer's reading"; no lawyer has read them yet |
| GOV-4 five v1 packs | Built (draft) | gov.nist-ai-rmf, gov.iso42001, eu.ai-act, soc2, med.hipaa.* | `test_the_five_v1_packs_exist_validate_and_carry_jurisdiction_and_dates` | No review records: no pack is `reviewed` |
| EVID-1 control evidence report | Built | `oversight.control_report`, `shio report controls` | `test_control_report_counts_fires_and_overrides` | "Checked by hand" on a real record set is still to do |
| EVID-6 coverage matrix per pack | Built | `preflight/coverage.py`, [coverage.md](coverage.md) | `test_coverage_matrix_marks_planned_as_not_covered_and_never_claims_compliance` | |
| CORE-5 pre-model gate | Built | `preflight/` ([preflight.md](preflight.md)) | `tests/test_preflight.py` (165) | Recall on a public de-identification set isn't measured yet (see MED-1) |
| OVR-1 rank and cap held calls | Built | `oversight.ReviewQueue` | `test_a_flood_of_benign_holds_does_not_bury_a_risky_one` | Not yet wired into the console's reviewer view |
| INT-2 proxy mode | Built (OpenAI-compatible) | `enforce/proxy.py`, `shio proxy` | `test_an_unmodified_agent_is_protected_by_changing_one_url` | No MCP proxy. Streaming is refused. It sees less than the in-process Guard |
| DX-3 shio doctor | Built | `doctor.py`, `shio doctor` | `test_doctor_finds_the_planted_unguarded_tool_and_discovery_needs_a_person` | Heuristic; Python only |

## Phase 3: Medical and depth

| ID | Status | Where | Test | Missing |
|---|---|---|---|---|
| MED-1 identifier gate | Built | `preflight` (tokenisation, de-obfuscation, second pass) | `test_record_is_written_before_sending_and_holds_no_phi`, adaptive results | Recall on a *public* de-identification corpus. Detectors are patterns; names in free text remain the weak spot |
| MED-2 minimum necessary | Built | PRV-04, RES-03 gate controls | fixtures and mutation tests | |
| MED-3 calibrated abstention | Built | `clinical.calibrate`, `thresholds`, `accept` | `test_calibrated_threshold_holds_its_error_bound_on_fresh_data` | Coverage and rejection rates on a real clinical dataset need reviewer labels from a clinician |
| MED-4 clinician sign-off | Built earlier | `signoff * by role`, gate holds | `test_holds_need_the_named_role_and_maker_checker` | Verified credentials (CORE-8): roles are names today |
| MED-5 FHIR adapter | Not built | | | Needs a FHIR test server and SMART scopes |
| MED-9 clinical test bed | Not built | | | Needs MedAgentBench and GPAgentBench-2K, and models |
| CORE-1 information-flow labels | Partial (earlier) | Guard's provenance ledger, Readings | `tests/test_boundary_escapes.py`, `tests/test_fuzz_boundary.py` | Value-level labels through containers and closures are a language change (SPEC.md first) |
| CORE-3 temporal policies | Built | `enforce/temporal.py`, `shio temporal check` | `test_temporal_rules_compile_to_a_deterministic_monitor`, overhead test | Rules name tools, not argument values |
| CORE-4 circuit breakers and kill switch | Built | `enforce/limits.Breakers` | `test_a_breaker_trips_across_calls_and_needs_a_person_to_resume` | State is in memory per process; trips and resumes are on the chain |
| CORE-6 MCP definition pinning | Built | `enforce/limits.McpPins` | `test_a_changed_mcp_tool_description_is_held` | Not wired into `MCPToolGate` automatically |
| CORE-8 authenticated identity | Not built | | | Needs OIDC or verifiable credentials; today approvers are matched by name and role |

## Phase 4: Ecosystem

| ID | Status | Where | Test | Missing |
|---|---|---|---|---|
| EVAL-3 open leaderboard | Not built | | | The adaptive harness's `defend(payload)` interface is where another guardrail would plug in |
| EVAL-4 policy tests with mutation | Built for gate controls | `preflight/harness.py` | 35 mutation tests | Mutation score per pack for argument and temporal policies |
| EVAL-5 domain red-team generator | Partial | `shio pack redteam` (from pack fixtures) | `test_red_team_cases_are_derived_from_every_packs_adversarial_fixtures` | Not generative |
| EVID-3 change-impact replay | Built earlier | `impact.py` | `tests/test_governance_measurement.py` | |
| EVID-4 OTel and SIEM export | Partial (earlier) | OTel, SQL and S3 sinks | | Versioned SIEM JSON schema |
| EVID-5 attestations | Built | `preflight/attest.py` | `test_expired_attestation_and_corrupt_profile_deny` | |
| EVID-7 evidence bundle | Built earlier | `bundle.py`, `shio verify` | `test_an_outsider_verifies_the_card_and_bundle_offline_with_the_public_key` | The verifier isn't packed inside the archive |
| GOV-2 discovery scanner | Built | `doctor.py`, `inventory.candidates` | the doctor test | Gateway logs aren't scanned |
| GOV-5 workflows | Built | `workflow.py` (exceptions, four-eyes policy changes) | `test_policy_change_without_a_second_approver_is_refused` | |
| GOV-6 dependency graph | Built | `inventory.graph`, `shio inventory graph` | `test_dependency_graph_matches_the_hand_drawn_one` | |
| GOV-7 drift measures | Built earlier | `monitors.py` | `test_an_alert_fires_on_seeded_drift_and_an_incident_becomes_a_signed_record` | |
| GOV-8 assistant | Not built (P2) | | | |
| GOV-9 console | Built (read-only, local) | `console.py`, `/monitor` | `tests/test_governance_monitor.py` | No OIDC login |
| CORE-7 detector plug-ins as signals | Built | `enforce/limits.Signals` | `test_detectors_are_signals_and_a_failing_detector_fails_closed` | Not yet plugged into the preflight classifier |
| CORE-9 pattern library | Not built (P2) | | | |
| INT-3 GitHub Action | Built | `.github/actions/shio-guard/action.yml`, `shio preflight coverage-diff` | `test_coverage_diff_fails_a_change_that_removes_or_weakens_a_control` | The composite action itself is not run in this repo's CI |
| INT-4 Slack, Teams, Jira approvals | Not built | | | Needs those services; `Gate.approve` is the hook |
| INT-5 reference deployment | Not built (P2) | | | |
| INT-6 TypeScript SDK | Not built | | | |
| OVR-2 reviewer context | Partial | `explain`, Guard provenance | | Comparison with a normal call and similar past decisions |
| OVR-3 reviewer metrics | Built | `oversight.reviewer_metrics`, `shio report reviewers` | `test_reviewer_metrics_from_signoffs` | |
| OVR-4 labels feed calibration | Partial | `clinical.thresholds` from labels | | Wiring from `shio label` to recalibration, as a record |
| MED-6 safety case as code | Built earlier | `safety.py` | `test_safety_case_is_rebuilt_from_records_and_needs_the_clinical_lead` | Format not yet confirmed with clinical safety advisers |
| MED-7 research mode | Built | med.research gate controls | fixtures | |
| MED-8 patient-facing release gate | Built | `clinical.release` | `test_patient_facing_release_gate` | The risk scores come from the caller |
| MED-10 medication checks | Partial (earlier) | med.rx with a fixture formulary | | An authoritative, licensed drug database |
| MED-11 classification helper | Partial | `risk.classify` (EU), `cds.py` (FDA posture) | | |
| DX-4 language server | Partial (earlier) | `editors/vscode` | | |
| DX-5 honest-limits pages | Partial | every governance page has a Limits or "Not done" section | `test_every_governance_page_states_its_limits` | Links to tests and last review dates aren't enforced |
| DX-6 browser playground | Not built | | | |

## Non-functional

| ID | Status | Evidence |
|---|---|---|
| NFR-2 honesty | Every feature page states its limits; this page lists what's missing | |
| NFR-3 fail closed | See CORE-10 | |
| NFR-4 latency | Measured: [results/gate-latency.json](results/gate-latency.json). Gate decision about 0.7 ms at p50 and 1.3 ms at p99 on the fixture world, including the record write, on one laptop. Ledger appends are constant-time (`test_chain_appends_are_constant_time`) | |
| NFR-5 determinism and replay | Gate, argument and temporal decisions are pure functions of inputs and history; detectors are signals | |
| NFR-6 privacy | No telemetry; the gate records hashes only; the vault is unchanged | |
| NFR-7 offline | Everything here runs without network | |
| NFR-8 licensing | The core is MIT OR Apache-2.0; the `[agt]` extra's certifi exception is waiting for counsel | |
| NFR-9 compatibility | Python 3.10 to 3.13 (the AGT extra needs 3.11) | |
| NFR-11 accessibility | The monitor uses semantic tables, labelled controls, focus, and both themes | Not audited against WCAG AA |
| NFR-12 jurisdiction and time | Packs carry `effective` dates; reg.india is advisory | |
| NFR-13 supply chain | Licence policy check; pinned extras | |
| NFR-14 project health | Not built: code of conduct, RFC process and pack maintainers are for the maintainers to set up | |

## Adaptive attack result (EVAL-1)

From [results/adaptive.json](results/adaptive.json) (`shio attack run --k 5 --budget 300 --seed 11`):

| Target | Attack success | pass^5 |
|---|---:|---:|
| Phone, email, SSN and MRN through the pre-model gate | 0% | 100% |
| Payment amount above the invoice total (argument policy) | 0% | 100% |
| Payment to an unlisted recipient (argument policy) | 0% | 100% |

Utility pass^5 is 100% on 8 benign sentences and a valid payment.

**Before the de-obfuscation pass existed, the same attacker got all four identifier types through 100% of the time.**
It used spacing, spelled-out digits, full-width characters, zero-width characters and base64. That finding is why
the pass exists. The hardened detector was tuned against this attacker's library, so treat the 0% as "no bypass found
by this library". New transformations will need new folds.
