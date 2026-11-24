# med.monitor

Subgroup and per-site metrics, and safety events as signed records.

**Status: draft.** Not reviewed by the clinical safety lead or counsel. `slices.json` is an example.

| Control | What it enforces | Proof |
|---|---|---|
| MON-1 | Each decision names its site and subgroups, from the allowed list, in clear | runtime `slices_recorded`, sign-off `clinical_safety_lead` of a monitoring report |
| MON-2 | Each safety event is a complete, signed record in the ledger | runtime `safety_event_complete` |

`checks.lib.subgroup_metrics(records)` gives decisions, check-failure, override and outcome rates per group value and
flags disparities; `checks.lib.record_safety_event(records, event)` writes an event to the ledger.

## Limits

- Groups must be coarse and listed. A value not on the list is refused, so identifiers can't reach the clear record.
- Rates for groups smaller than `min_n` are reported but not compared.
- A safety event record does not replace national incident reporting.
