# D2: Pack format, `shio-pack/1`

A pack is a folder. Its identity is `id@version` plus the sha256 of its file tree.

```
med.phi/
  pack.json        identity, dates, licence, status, review, frameworks, hazards, controls
  checks.py        deterministic checks (only if the pack has runtime proofs)
  fixtures/        <check>.json: pass, fail and adversarial cases for every runtime check
  README.md        what it covers and, under a "Limits" heading, what it does not
  *.json           data the checks read (lists, tables), part of the tree hash
```

## pack.json

| Field | Required | Meaning |
|---|---|---|
| `format` | yes | `"shio-pack/1"` |
| `id` | yes | lower-case words separated by dots: `med.phi`, `gov.nist-ai-rmf` |
| `name`, `description` | name | what the pack is |
| `version` | yes | semantic version; a published version never changes (D35) |
| `effective` | yes | the date this version takes effect; records cite the version in force |
| `licence` | yes | an SPDX expression |
| `status` | yes | `draft`, `research` (no controls yet), `reviewed`, `retired` |
| `review` | for `reviewed` | `{"counsel": {"name", "date"}, "clinical_lead": {...}}` (clinical lead for `med.*`) |
| `limits` | | one paragraph; the README's Limits section says more |
| `checks` | if runtime proofs | the checks module, usually `checks.py` |
| `frameworks` | | `[{"id", "title", "source"}]` the controls refer to |
| `hazards` | medical packs | `[{"id", "title", "severity" 1-5, "likelihood" 1-5}]` for the safety case |
| `controls` | yes (except `research`) | see below |

A control: `{"id": "PHI-1", "title", "requirement", "refs": [{"framework", "ref"}], "hazards": [...], "proof": [...]}`.
The requirement is the pack's own words, not a copy of the framework's text.

## Proofs

| Kind | Fields | Proven by |
|---|---|---|
| `lint` | `proof`: a static proof id | `shio assess` over the program (readings-through-rules, tools-gated, models-pinned, regulated-mode, signoff-required, no-reflection, pack-wired, dependencies-pinned, cds-posture) |
| `runtime` | `check`: a function in `checks.py` (or `pack` + `control`, to cite another pack's control) | the check runs in the agent; the record cites `id@version:control` |
| `eval` | `suite`, `metric`, `op`, `threshold` | `shio eval`: the suite's metric meets the threshold |
| `signoff` | `role`, optional `subject` (decision, card, monitoring, safety-case, promotion...) | a sign-off by that role, in the ledger or an approval log |

A runtime check returns a `Verdict` (truthy when it passed, with a reason, and evidence that never repeats sensitive
values), a bool, or `(bool, reason)`.

## Fixtures

`fixtures/<check>.json`: `{"check", "cases": [{"id", "kind": "pass"|"fail"|"adversarial", "args", "kwargs",
"expect" (adversarial only), "note"}]}`. The validator requires all three kinds for every runtime check and runs them:
a pack whose own fixtures fail is never loaded. Adversarial fixtures also become red-team eval cases
(`shio pack redteam`).

## Validation (`shio pack validate`)

Structure; id, semantic version, SPDX licence; status and review; **no compliance claims** ("compliant", "certified",
"conforms to"...) unless `reviewed` by counsel (and the clinical lead for `med.*`); README with Limits; unique control
ids; framework references declared; lint proofs known to `shio assess`; eval proofs with metric and threshold; runtime
checks present, with their three kinds of fixtures, all coming out as declared. "Two sample controls pass the
validator" (the D2 gate) is `test_two_sample_controls_pass_the_validator`; in fact every built-in pack passes.

## OSCAL compatibility: evaluated, and decided (proposal)

NIST's OSCAL (v1.1.2) catalog model fits a pack's *what*: groups, controls with ids and titles, statement parts, props
and links. It has no standard place for a pack's *how*: the proof kinds, executable checks, fixtures, a tree hash, or
the dates and review a record must cite. Profiles and component definitions don't add executable proofs either.

**Proposal (for the founders to confirm in D1):** `pack.json` is the source of truth; `shio pack oscal ID` exports a
valid OSCAL catalog (controls, statements, framework references as props, proofs as props in Shio's namespace, the
pack's sha256 and status in metadata) so OSCAL tooling and GRC platforms can import packs. Importing OSCAL catalogs
into draft packs (controls without proofs, status `draft`) is a natural next step and not built.

## Runtime (D7)

```python
from shio.governance.packs import load_pack
phi = load_pack("med.phi")                         # or "med.phi@0.1.0", or a folder; sha256="..." pins the tree
phi.no_identifiers(text)                           # a Verdict; inside an agent the record cites the pack and PHI-1
phi.lib.deidentify(text)                           # helpers, which cite nothing
```

Regulated `.shio` programs can't import `shio`, so they import packs through a local support module (whose sha256 is
in every record), as both reference agents do.
