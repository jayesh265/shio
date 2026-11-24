# eu.ai-act (draft)

The obligations for high-risk AI systems in the EU AI Act (Regulation (EU) 2024/1689) that Shio's artefacts can
evidence, each mapped to a proof.

**Status: draft.** Counsel has not reviewed it. It does not say a system meets the Act.

| Control | Article | Proof |
|---|---|---|
| EU-1 risk management | 9 | sign-off of the safety case |
| EU-2 data governance, bias | 10 | eval `regression.max_slice_gap <= 0.10` |
| EU-3 technical documentation | 11, Annex IV | sign-off of the agent card |
| EU-4 record-keeping | 12 | lint `regulated-mode` |
| EU-5 human oversight | 14 | lint `signoff-required`, `readings-through-rules` |
| EU-6 accuracy, robustness | 15 | evals `regression`, `redteam` |
| EU-7 post-market monitoring | 72 | sign-off of a monitoring report |
| EU-8 serious incidents | 73 | runtime `med.monitor` MON-2 |

## Limits

- Classification (is it high-risk? provider or deployer?) is for counsel.
- Not covered: conformity assessment, the quality management system, registration, CE marking, the deployer's own
  obligations beyond what records show, and general-purpose AI model obligations.
- The Act's obligations apply from dates it sets; this pack's `effective` date is when this version took effect in
  Shio, not a legal date.
