# med.trial

Eligibility, deviations, adverse-event reporting clocks, blinding and consent, in code.

**Status: draft.** Not reviewed by the clinical safety lead or counsel. The bundled protocol is a fixture.

| Control | What it enforces | Proof |
|---|---|---|
| TRL-1 | Eligibility evaluated in code over model-read facts; unknown facts go to a person | runtime `eligible`, eval `eligibility.pass_rate >= 0.95` |
| TRL-2 | No allocation label or code in anything a model reads | runtime `blinded` |
| TRL-3 | Visits outside their windows, or missed, are flagged | runtime `no_deviations` |
| TRL-4 | Serious adverse events reported inside their expedited clocks (24 h; 7 or 15 days for SUSARs) | runtime `ae_reported_in_time` |
| TRL-5 | Consent version matches the protocol's | runtime `consent_current` |

Criteria are a composite tree (`All`, `Any`, `Not`, `Criterion`) with three-valued logic: a fact the model couldn't
read is unknown, and unknown is never eligible.

## Limits

- Criteria are comparisons over facts. Anything that needs clinical judgement must be entered by a person as a fact.
- Clocks follow ICH E2A from the time of awareness; national rules may be stricter and must be added per study.
- `blinded` finds labels and codes as written (spacing and case ignored); it can't find allocation implied indirectly.
