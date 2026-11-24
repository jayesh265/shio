# med.rx

Drug resolution, dose recomputation, interactions and allergies, in code.

**Status: draft.** Not reviewed by the clinical safety lead or counsel.

| Control | What it enforces | Proof |
|---|---|---|
| RX-1 | The drug resolves to one code (exact name or synonym, no fuzzy matching) | runtime `drug_resolved` |
| RX-2 | The dose equals the one recomputed from weight, age and kidney function; contraindications caught | runtime `dose_matches` |
| RX-3 | No major or contraindicated interaction; unknown medications fail safe | runtime `no_interactions` |
| RX-4 | No allergy conflict by drug or class; unknown allergies fail safe | runtime `no_allergy_conflict` |
| RX-5 | Reference data loaded only with its licence confirmed | sign-off `regulatory_counsel` of the reference data |

## Reference data and licensing

`fixture-formulary.json` is a **fixture**: made-up codes (`FX-...`), simplified dosing rules and a handful of
interactions, so the checks and tests run. It is not clinical guidance. `ReferenceData.load(path)` refuses any dataset
whose `meta` is not marked `"fixture": true` unless `meta.licence` records `confirmed: true`, `confirmed_by` and
`date`. Drug terminologies, dosing references and interaction databases are licensed differently (some free, some
not): confirm each before building on it, and never bundle one without it.

## Limits

- Kidney function is estimated with Cockcroft-Gault from serum creatinine (umol/L). Other estimates exist and some
  drugs are dosed on eGFR; the reference data must say which.
- Dosing rules are a single dose and frequency per drug with renal bands. Real dosing varies by indication, route,
  formulation and more.
- Interactions are pairs; three-way and dose-dependent interactions are not modelled.
