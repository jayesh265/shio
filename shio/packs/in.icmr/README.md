# in.icmr (draft)

The principles of ICMR's 2023 ethical guidelines for AI in biomedical research and healthcare that Shio can evidence.

**Status: draft.** Counsel and the clinical safety lead have not reviewed the mapping.

| Control | Principle | Proof |
|---|---|---|
| ICMR-1 | Autonomy | lint `signoff-required`, `readings-through-rules` |
| ICMR-2 | Safety and risk minimisation | sign-off of the safety case |
| ICMR-3 | Trustworthiness | runtime `med.grounding` GRD-1 |
| ICMR-4 | Data privacy | runtime `med.phi` PHI-1, lint `regulated-mode` |
| ICMR-5 | Accountability | lint `regulated-mode` |
| ICMR-6 | Validity | eval `regression.pass_rate` |
| ICMR-7 | Non-discrimination and fairness | eval `regression.max_slice_gap` |

## Limits

- Ethical principles are not met by code. Ethics committee review, collaboration and accessibility need people.
- India's data protection law (DPDP Act) and medical device rules (CDSCO) are separate packs, still being researched
  (`in.dpdp`, `in.cdsco`).
