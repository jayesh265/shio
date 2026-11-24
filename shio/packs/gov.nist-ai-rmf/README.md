# gov.nist-ai-rmf (governance pack v0)

A subset of the NIST AI Risk Management Framework 1.0: the subcategories Shio can evidence from its own artefacts.

**Status: draft.** Counsel has not reviewed the wording. The founders still need to confirm this framework as the
first governance pack (D1); Credo AI ships it, which makes interoperability easier.

Every control maps to a proof: a static proof over the program (`shio assess`), a runtime check cited in records, an
eval metric (`shio eval`), or a sign-off by a role. `shio evidence RECORDS --framework gov.nist-ai-rmf ...` builds the
bundle that maps each control to its evidence.

## Limits

- 11 subcategories, not the framework. The organisational ones (policies, culture, workforce, contracts) need people
  and documents, not code.
- Requirement texts are Shio's paraphrases. Check the subcategory references against NIST AI 100-1 before relying on
  them.
- A bundle shows evidence per control. It does not say an organisation conforms to the AI RMF.
