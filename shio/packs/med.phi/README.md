# med.phi

Keeps protected health information (PHI) away from models not approved for it, out of agent outputs, and out of
decision records except the erasable vault.

**Status: draft.** Not reviewed by regulatory counsel or the clinical safety lead. It does not claim that an agent using
it meets the HIPAA Privacy Rule; it gives the checks and evidence a privacy review starts from.

| Control | What it enforces | Proof |
|---|---|---|
| PHI-1 | No Safe Harbor identifier this pack detects in outputs | runtime `no_identifiers` |
| PHI-2 | Only approved, pinned models receive PHI | runtime `approved_model`, lint `models-pinned` |
| PHI-3 | Only the fields a purpose needs | runtime `minimum_necessary` |
| PHI-4 | Expert determination on file when used | runtime `expert_determination`, sign-off `privacy_officer` |
| PHI-5 | PHI kept in the vault, not the record | lint `regulated-mode` |

`checks.lib.deidentify(text, known=[...])` replaces identifiers with tags; `checks.lib.PhiGate(model)` refuses an
unapproved model before it is sent anything (its read comes back null, and its checks fail).

`approved-models.json` and `minimum-necessary.json` are **examples**: your privacy officer owns the real lists.

## Limits

- Pattern detection finds identifiers with a textual shape (phone, email, dates finer than a year, MRN and other
  labelled numbers, street addresses, ZIP codes, ages over 89, IPs, URLs, VINs) and names passed in from structured
  data. It does **not** reliably find names, relatives or employers in free text: use the PHI reader adapter (D13),
  whose findings checks then judge, and measure its recall on your own data.
- Photographs, biometrics and identifiers in images are out of scope.
- The ZIP-prefix list follows the Safe Harbor guidance as published; confirm it against current census data.
- Verdicts name the kinds of identifier found, never their values.
