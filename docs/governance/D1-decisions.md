# D1: Decision record

**Status: PROPOSED. Not signed.** The build plan's Phase 0 gate is that the founders sign all four decisions. This
record sets out each decision, the option the engineering work assumed, and why, so the founders can sign it, change
it, or reject it. Where the code depends on a choice, that is said, with what changing it would cost.

| # | Decision | Proposed | Code built on it | Cost to change |
|---|---|---|---|---|
| 1 | Scope | Governance of agents built on Shio (and, through Shio Guard's gate and Cedar, tool calls of other agents), medical first | packs, cards, proofs assume a Shio program | high for scope beyond Shio programs |
| 2 | Relationship with Credo AI | Complement and export, not replace | Credo export sink (D33); NIST AI RMF chosen as the first framework pack because Credo ships it | low |
| 3 | Clinical authority | The clinical safety lead approves every medical pack, the red-flag list and the safety case; their approval is a signed entry bound to the artefact's hash | approval log; `TriageGate(require_approval=True)`; safety case is DRAFT until approved | low |
| 4 | Pack format | JSON manifest plus deterministic Python checks and JSON fixtures, hash-pinned; OSCAL as an export | `packs.py`, the validator, every built-in pack | medium |

## 1. Scope

**Proposed:** Shio Guard governs agents whose decisions are made in Shio (the read/decide boundary is what makes
control proofs possible). It also governs tool calls of agents written elsewhere, through Shio Guard's gate (LangChain,
OpenAI, Claude, MCP adapters) and Cedar policies (`CedarGate`). Medical first: the reference agents and most packs are
clinical.

**Not in scope, for now** (from the build plan): shadow-AI discovery and vendor inventory; executive dashboards and
vendor questionnaires; a Credo-style governance assistant (revisit after Phase 3); anything that claims to diagnose or
to decide a device classification. `med.cds` enforces a declared posture and says so; it never rules on device status.

## 2. Relationship with Credo AI

**Proposed:** complement. Credo AI is a governance platform (inventory, policy, reporting); Shio Guard produces
evidence it can't: control proofs over a program hash, signed decision records, change-impact replay, control
effectiveness from reviewer labels. The integration is an export sink (cards and evidence into a Credo tenant). The
first governance pack follows a framework Credo ships (NIST AI RMF) so evidence lines up.

**Open:** the sink's endpoints and payload fields are placeholders until a Credo tenant is available (build plan open
question 6).

## 3. Clinical authority

**Proposed:** the clinical safety lead has the final word on clinical content: medical packs (status `reviewed` needs
their name and date), the red-flag list, the labelled sets behind published rates, and the safety case. Their approval
is an entry in a signed approval log, bound to the sha256 of exactly what they approved: change the artefact and the
approval no longer applies. Regulatory counsel has the same role for compliance wording, licences and the decision-
support posture. Engineers can't mark either kind of correctness as done; the validator and gates enforce that.

## 4. Pack format

**Proposed:** a folder with `pack.json` (identity, dates, licence, status, review, frameworks, controls and their
proofs), `checks.py` (deterministic checks), `fixtures/` (pass, fail and adversarial cases per check) and `README.md`
(with a Limits section). Identified by id, semantic version and a tree sha256 over every file. OSCAL compatibility was
evaluated (D2): OSCAL catalogs carry controls and statements but have no place for how a control is *proven* or for
executable checks and fixtures, so OSCAL is an export (`shio pack oscal`), and `pack.json` stays the source of truth.

**Open (build plan open question 3):** one repository or separate packages. The format works either way: packs are
folders identified by hash, and the open registry (D35) publishes and installs them individually.

## Signatures

| Founder | Decision 1 | Decision 2 | Decision 3 | Decision 4 | Date |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
