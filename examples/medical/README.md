# Medical reference agents (Shio Guard)

> **SIMULATED.** Every letter, chart, protocol, drug and formulary here is made up, and every model is a mock that reads
> by headings. Nothing here is clinical data, clinical guidance or a clinical tool. The packs they use are drafts that
> no clinical safety lead or counsel has reviewed.

| Agent | Folder | Packs | Signs off |
|---|---|---|---|
| Referral summariser (reference agent 1, D19) | [referral/](referral/) | med.phi, med.grounding | clinician |
| Trial eligibility screener (reference agent 2, D26) | [trial/](trial/) | med.trial, med.rx, med.phi | investigator |

Each folder has the program (`.shio`), its trusted support module, an agent manifest (`agent.json`) for
`shio registry scan` and `shio assess`, eval suites (`evals/`, written by `make_evals.py`) and eval targets.
See [docs/governance](../../docs/governance/README.md).
