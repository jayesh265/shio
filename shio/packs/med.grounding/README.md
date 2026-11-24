# med.grounding

Ties every claim and figure in a model's clinical output to the source it read, and catches required items left out.

**Status: draft.** Not reviewed by the clinical safety lead or counsel.

| Control | What it enforces | Proof |
|---|---|---|
| GRD-1 | Every claim carries a word-for-word quote from the source, not from instruction-like text in it | runtime `claims_quoted`, eval `grounding.hallucination_caught >= 0.95` |
| GRD-2 | Every figure (value and unit) appears in the source | runtime `figures_in_source` |
| GRD-3 | Required items present, or "none" only where the source says none | runtime `required_items`, eval `grounding.omission_caught >= 0.95` |
| GRD-4 | Wrongful rejection of good text measured and bounded | eval `grounding.wrongful_rejection <= 0.10`, sign-off `clinical_safety_lead` |

`checks.lib.SourceIndex(source)` indexes a source once for many claims.

## Limits

- A quote shows where a claim came from, not that the claim follows from it. A clinician still reads the output, and
  anything patient-facing needs clinician sign-off until the generate-then-verify rates (D16) are measured.
- Figures are matched by value and unit, not by what they measure: "eGFR 52" is grounded by any 52 in the source.
- Quotes inside instruction-like text ("ignore previous instructions...") don't count; the patterns for such text are
  heuristics and will not catch every injection.
- The rates in the reference agent are measured on a **synthetic** labelled set written by engineers. They are not
  clinical evidence until the clinical safety lead builds and labels the set.
