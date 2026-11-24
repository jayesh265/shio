# med.triage

Red flags run in code before any model replies; a red flag gets fixed emergency wording, and an out-of-scope request
gets a fixed refusal.

**Status: draft.** The red-flag list (`red-flags.json`) is an engineer's draft. It needs the clinical safety lead's
approval, recorded in an approval log against the file's sha256; `TriageGate(..., require_approval=True)` will not
start without it.

| Control | What it enforces | Proof |
|---|---|---|
| TRI-1 | Red flags screened before the model; fixed emergency wording | runtime `no_red_flag`, sign-off `clinical_safety_lead` of the list |
| TRI-2 | Diagnosis, prescribing, dosing and off-topic requests refused | runtime `in_scope` |

Matching uses an Aho-Corasick automaton over every phrase (one pass over the message), on whole words, skipping
mentions negated in the same clause ("no chest pain", "denies...").

## Limits

- Phrases miss red flags described in other words, misspelt, or in other languages. This is a floor under triage,
  not triage.
- Negation looks back four words within a clause; "not sure if it's chest pain" counts as a red flag (on purpose).
- Fixed wording must be localised and approved per deployment (emergency numbers differ by country).
