# Shio Guard: governance over Shio agents

Shio guarantees that a model only reads and code decides. Shio Guard turns that guarantee into the artefacts a
governance programme asks for: agent cards, control proofs, framework evidence bundles, eval results, change-impact
replays, control effectiveness, monitors, incidents and a clinical safety case. Every artefact is hashed and signed
with the ledger's keys, so an auditor verifies it offline with the public key alone.

The work follows the [Shio Guard build plan](#deliverables) (36 deliverables in five gated phases). This page says,
for each deliverable, what was built, where, what proves it is done, and **what still needs a person**: engineers
cannot sign off clinical or legal correctness, and nothing here pretends otherwise.

## Architecture

```
          .shio program ──compile──▶ compiled agent ──run──▶ signed record (ledger) ──┐
               │                         ▲   ▲                    │ cites pack@version│
               │                         │   │                    ▼   and controls    │
  agent.json ──┤                 readers │   │ checks         shio evidence --framework
  (manifest)   │       (models, PHI detector) (pack checks, Cedar)  │                  │
               ▼                                                    ▼                  ▼
     shio registry scan ─▶ signed card ─▶ review log      bundle (signed manifest) ─▶ shio verify (offline)
     shio assess ─▶ signed assessment (control proofs)            ▲
     shio eval ─▶ signed eval results ────────────────────────────┘
     shio impact / effectiveness / monitors / safety-case / release ─▶ reports, incidents, promotions (signed)
```

| Module | What it is |
|---|---|
| `shio/governance/packs.py` | Pack format, validator, loader (hash-pinned), runtime that cites pack versions in records, OSCAL export |
| `shio/governance/adapters.py` | Reader, check, sink and host adapters: trust class, pinned manifest, conformance tests, SBOM |
| `shio/governance/licences.py`, `licence-policy.json` | SPDX parser, the licence policy, the CI check |
| `shio/governance/card.py`, `cds.py` | Agent cards, re-review trigger, decision-support posture |
| `shio/governance/assess.py` | Static control proofs over compiled programs |
| `shio/governance/bundle.py` | Framework evidence bundles and their offline verification |
| `shio/governance/evals.py`, `gtv.py` | Eval harness; generate-then-verify and the three-option ladder |
| `shio/governance/impact.py`, `effectiveness.py` | Change-impact replay; control effectiveness from reviewer labels |
| `shio/governance/monitors.py`, `safety.py`, `promote.py` | Monitors and incidents; safety case; promotion gate |
| `shio/governance/policy_compiler.py`, `cedar.py` | Policy-to-checks compiler; Cedar/OPA interop |
| `shio/governance/console.py`, `registry_index.py` | Read-only web console; open pack registry |
| `shio/governance/chain.py` | Signed hash chains and the approval log (reviews, approvals, promotions) |
| `shio/packs/*` | 13 built-in packs (`shio pack list`) |
| `examples/medical/referral`, `examples/medical/trial` | Reference agents 1 and 2 (simulated data and models) |

Two small changes to the core runtime support this: `shio.core.cite()` lets a pack check record the pack version and
control in the decision record (and vetted monitoring groups, for med.monitor), and `shio.ledger.split` now moves
non-JSON check arguments to the vault (a pre-existing gap: a `Source` passed to a check was recorded as a repr, in
clear). `shio.replay` gained `replay_detail()` (structured results, model swaps) on which change-impact replay is built.

## Engineering rules, and where they are enforced

| Rule | Enforced by |
|---|---|
| Trust class decides the adapter type | `adapters.py`: readers answer reads (output sealed as a Reading); checks are deterministic, pinned, reviewed (conformance runs fixtures twice, checks nothing changed); sinks return nothing; hosts return exactly the agent's outcome |
| MIT and Apache-2.0 only in the core | `shio licences check` in CI; fails on any unidentified licence (fail closed) |
| Integrations ship as extras | `pyproject.toml` extras (`presidio`, `dspy`, `temporal`, `openai`, `langchain`, `mcp`); third-party imports are lazy |
| Every check has pass, fail and adversarial fixtures | the pack validator refuses a runtime check without all three, and runs them |
| Packs are dated and versioned | `effective` and semver required; records cite `id@version` and the tree sha256 |
| No compliance labels without review | the validator refuses "compliant", "certified"... unless the pack is `reviewed` with counsel (and, for `med.*`, the clinical lead) named |
| Negative tests for every guarantee | `tests/test_governance_assess.py`: each proof fails when the code breaks its control |
| Say what is simulated | reference agents, fixtures and eval sets say SIMULATED/SYNTHETIC/FIXTURE; the card records `simulated` model entries; assessments note replay models |

## Deliverables

Status: **built** means the software deliverable exists and its "done when" criterion is tested; **needs people**
names the human sign-off the plan requires and that only the named role can give.

| # | Deliverable | Built | Proof it is done | Needs people |
|---|---|---|---|---|
| D1 | Decision record | [D1-decisions.md](D1-decisions.md) | proposals written for all four decisions | founders' signatures |
| D2 | Pack format spec | [D2-pack-format.md](D2-pack-format.md), `packs.py` | `test_two_sample_controls_pass_the_validator`; OSCAL evaluated, export built | founders confirm the OSCAL decision |
| D3 | Adapter interface spec | [D3-adapter-interface.md](D3-adapter-interface.md), threat model §8 | spec reviewed against the threat model, which is updated | security reviewer |
| D4 | Licence and dependency policy | [D4-licence-policy.md](D4-licence-policy.md), `shio licences check` (CI) | `test_governance_licences.py` | counsel approves the allow-list and the typing-extensions exception |
| D5 | Agent card generator | `shio registry scan` | `test_changing_a_tool_changes_the_card_hash`, `test_verify_rejects_an_edited_card` | |
| D6 | Re-review trigger | `shio registry check` (CI) | `test_ci_fails_until_the_right_roles_sign_off_the_exact_hash` | the review roles themselves |
| D7 | Pack loader and runtime | `load_pack`, `PackRuntime`, `core.cite` | `test_records_cite_the_pack_name_version_and_control` | |
| D8 | `shio assess` and control proofs v1 | `assess.py` (9 proofs) | `test_reference_agents_prove_at_least_three_controls_for_every_path` + a negative test per proof | |
| D9 | `shio evidence --framework` | `bundle.py` | `test_an_outsider_verifies_the_card_and_bundle_offline_with_the_public_key` | |
| D10 | Adapter framework | `adapters.py`, conformance, SBOM in card | `test_a_deliberately_unpinned_adapter_is_refused_at_build_time` | |
| D11 | Governance pack v0 (NIST AI RMF subset) | `shio/packs/gov.nist-ai-rmf` | every control maps to a proof (validator) | founders confirm the framework; counsel reviews wording |
| D12 | med.phi | `shio/packs/med.phi` | `test_safe_harbor_removal_on_a_fixture_letter`, `test_an_unapproved_model_is_refused_before_it_sees_any_phi`, `test_phi_stays_out_of_records_except_the_vault` | privacy officer owns the model and field lists; counsel, clinical lead |
| D13 | PHI detector as a reader | `adapters_ext/phi_detector.py` | `test_detector_recall_is_measured_on_fixtures` (recall 0.88 overall; names 0.63), `test_detector_output_is_a_reading_judged_by_a_check` | |
| D14 | Eval harness | `evals.py`, `shio eval` (CI) | `test_regression_against_a_baseline_fails_ci`, `test_red_team_cases_are_derived_from_every_packs_adversarial_fixtures` | |
| D15 | med.grounding | `shio/packs/med.grounding` | rates measured on a labelled set (`test_grounding_rates_are_measured_on_the_labelled_set`) | clinical safety lead builds and labels the real set: the bundled one is synthetic |
| D16 | Generate-then-verify | `gtv.py`, [D16-free-text-options.md](D16-free-text-options.md) | wrongful-rejection rates reported per option (`results/gtv.json`) | the team picks an option per use |
| D17 | Change-impact replay | `impact.py`, `shio impact` | `test_swapping_a_model_reports_exactly_which_decisions_change` | |
| D18 | Control effectiveness | `effectiveness.py`, `shio effectiveness` | `test_every_check_shows_its_measured_numbers_from_reviewer_labels` | reviewers' labels |
| D19 | Reference agent 1 | `examples/medical/referral` | `test_reference_agent_1_runs_end_to_end_with_clinician_signoff_and_a_signed_record` | clinician sign-off is the human step it demonstrates |
| D20 | med.rx | `shio/packs/med.rx` | fixtures pass; `test_reference_data_without_a_confirmed_licence_is_refused` | licensing of real reference data |
| D21 | med.triage | `shio/packs/med.triage` | `test_the_model_never_answers_first_on_a_red_flag` | clinical lead approves the red-flag list (the gate enforces it) |
| D22 | med.trial | `shio/packs/med.trial` | `test_the_arm_assignment_never_appears_in_a_reads_sources`, `test_eligibility_matches_the_labelled_set_of_charts` | |
| D23 | Policy-to-checks compiler beta | `policy_compiler.py`, `shio policy-draft` | `test_policy_becomes_draft_checks_tests_and_a_traceability_matrix`, `test_every_draft_needs_a_recorded_human_approval` | policy owners approve drafts |
| D24 | Clinical safety case v1 | `safety.py`, `shio safety-case` | `test_safety_case_is_rebuilt_from_records_and_needs_the_clinical_lead` | clinical safety lead reviews and approves |
| D25 | Web console v1, and the live monitor ([monitor.md](monitor.md)) | `console.py`, `monitor.py`, `ui/`, `shio console --workspace / --demo` | `test_a_compliance_user_finds_a_controls_evidence_without_the_command_line`, `tests/test_governance_monitor.py` | local, single-user: no authentication |
| D26 | Reference agent 2 | `examples/medical/trial` | `test_screener_signoff_and_ledger_verify`, eligibility suite 10/10 | design partner review |
| D27 | Monitors and incidents | `monitors.py`, `shio monitors`, `shio incident` | `test_an_alert_fires_on_seeded_drift_and_an_incident_becomes_a_signed_record` | |
| D28 | med.monitor | `shio/packs/med.monitor` | `test_metrics_are_sliced_by_group_and_site_and_safety_events_are_records` | clinical lead chooses the groups |
| D29 | med.change | `promote.py`, `shio release`, `shio/packs/med.change` | `test_a_change_without_signoff_cannot_be_promoted` | release manager |
| D30 | med.cds | `cds.py`, proof `cds-posture`, `shio cds` | `test_cds_posture_fails_when_the_card_contradicts_it` | counsel reviews the constraints |
| D31 | Policy-engine interop: Cedar, OPA, Microsoft AGT ([microsoft-agt.md](microsoft-agt.md)) | `cedar.py`, `adapters_ext/agt.py`, `shio cedar` | `test_a_cedar_policy_is_enforced_on_a_non_shio_agent`, `tests/test_governance_agt.py` | counsel: the `certifi` (MPL-2.0) exception for the `[agt]` extra; Rego import not built |
| D32 | Further adapters | `adapters_ext/frameworks.py`, `integrations.py` | `test_each_adapter_passes_conformance_and_the_licence_check` | pin framework dependency versions to the ones CI installs |
| D33 | Credo AI export sink | `adapters_ext/credo.py`, `shio credo export` | dry-run mapping tested | **a Credo tenant**: endpoints and payload fields are unverified placeholders |
| D34 | EU and India packs | `eu.ai-act`, `in.icmr` (draft); `in.dpdp`, `in.cdsco` (research) | packs validate; research notes in [research/](research/) | counsel reviews each pack; DPDP and CDSCO research |
| D35 | Open pack registry | `registry_index.py`, `shio pack publish|install`, [CONTRIBUTING-packs.md](CONTRIBUTING-packs.md) | `test_a_third_party_publishes_a_pack_that_passes_the_validator` | |
| D36 | Security review, production, 1.0 | [RELEASE-1.0-CHECKLIST.md](RELEASE-1.0-CHECKLIST.md) | | outside security reviewer, a production deployment |

## Quick start

```bash
pip install -e ".[regulated]"
shio pack list                                    # the built-in packs
shio pack validate                                # every pack, fixtures run
shio licences check --extra regulated             # the licence policy (CI runs this)
cd examples/medical/referral
shio keygen keys && export SHIO_SIGNING_KEY=keys/shio-signing.key
shio registry scan agent.json -o card.json        # the signed agent card (fails the build on any problem)
shio assess --manifest agent.json -o assessment.json
shio run referral.shio L001 --traces records --as intake-bot
shio eval evals/regression.json --card card.json -o regression.json
shio evidence records --from 2026-11-01 --to 2026-11-30 -o bundle --framework gov.nist-ai-rmf \
    --card card.json --assessment assessment.json --eval regression.json --approvals reviews
shio verify bundle --pubkey keys/shio-signing.pub
shio console --records records --cards . --bundles .
```

## The policy pack specification

| Part | Where | Test | Needs a person |
|---|---|---|---|
| Pre-model gate (step 1): context, profiles, attestations, record, fail-closed | `preflight/` ([preflight.md](preflight.md)) | `tests/test_preflight.py` | the design partner's shadow-mode month |
| 35 enforced gate controls, fixtures and mutation tests | `preflight/controls.py` | `shio preflight fixtures` | counsel reviews each control's reading of the rule |
| 13 spec packs (draft) and the coverage matrix | `tools/spec_packs.py`, [coverage.md](coverage.md) | `test_spec_packs_validate_and_their_gate_proofs_run` | counsel and the clinical safety lead, before any pack is `reviewed` |
| No bypass | `preflight/bypass.py`, `shio preflight lint` | `test_shio_itself_has_no_bypass` | |

The product requirements document's requirements are traced one by one in [requirements.md](requirements.md).
