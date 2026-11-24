# Research notes: India's Digital Personal Data Protection Act, 2023

**Status: research.** No controls are drafted until counsel answers the questions below. The `in.dpdp` pack has no
controls and proves nothing.

## What Shio already has that may be relevant

- Purpose-bound processing: an agent card states its purpose; med.phi's minimum-necessary check limits fields per
  purpose.
- Erasure: `shio erase` deletes a record's vault and enters the erasure in the signed chain; the decision's reasons
  survive in clear.
- Retention: data-handling policies (`shio retention`) erase vaults when their retention ends.
- Records of processing: every decision is a signed record.

## Questions for counsel

1. Which obligations apply to Shio's users as data fiduciaries, and which to Shio as software they run?
2. What consent and notice evidence must a decision record carry, and must consent withdrawal trigger erasure?
3. How do the rules made under the Act (and their commencement) affect retention and breach notification timelines?
4. Are there obligations for "significant data fiduciaries" (audits, impact assessments) that Shio's evidence bundles
   should map to?
5. What applies to transfers of personal data outside India, for hosted models?
6. How does health data interact with sector rules (ICMR guidelines, any digital health regulations)?
