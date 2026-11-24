# The pre-model compliance gate and the policy packs

This implements the *Shio policy pack specification* (24 Nov 2026), starting from its build order step 1. Every
model call that touches health data passes one gate. The gate runs the technical controls itself and requires a
current signed attestation for each organisational control. If any control fails, nothing leaves for the model: the
call is denied, held for a person, redacted, or routed to an approved model.

Three limits from the spec hold here too:
- Code can't make an organisation compliant.
- "All guidelines" means only the ones listed in the coverage matrix.
- Rules move, so every pack is dated and versioned, and every record cites the version in force.

## Using it

```python
from shio.governance.preflight import Gate, Request

gate = Gate.from_folder("compliance/", records="records/gates", attestations="records/attestations")
d = gate.decide(Request(caller="dr.mensah", role="clinician", purpose="treatment", destination="clinical-llm",
                        fields={"reason": "...", "results": "..."}, subject="P-100"))
if d.sendable:
    text = gate.client(d, transport).send()          # transport(profile, payload) -> text; sends once
    problem = gate.check_output(d, text)              # PHI-11: leaked identifiers or unknown tokens
elif d.hold_id:
    gate.approve(d.hold_id, "P. Okafor", "privacy_officer"); d = gate.release(d.hold_id)
```

```bash
shio preflight check request.json --config compliance/        # one decision, as JSON (exit 3 unless sendable)
shio preflight attest security-risk-analysis --owner security_officer --by "L. Brandt" \
     --issued 2026-02-01 --expires 2027-02-01 --document sra.pdf --attestations records/attestations
shio preflight attestations --attestations records/attestations      # missing and expired fail (exit 1)
shio preflight coverage -o docs/governance/coverage.md                # the coverage matrix
shio preflight lint src/ --allow src/transport.py                     # no model SDK outside the gate (exit 1)
shio preflight fixtures                                               # every control's fixtures and mutation tests
shio preflight demo                                                   # decisions over the SYNTHETIC fixture world
```

The live monitor (`shio console --demo DIR`) has a **Pre-model gate** view: decisions per day, the controls that
stopped or changed calls, attestation status and coverage.

## The declared inputs

Three files sit in a folder versioned with the agent. The spec names them `compliance.shio` and `models.shio`; until
that syntax is written into SPEC.md they are JSON files with the same fields, loaded strictly. A missing or unknown
value is a load error that names the file and field. Nothing is guessed.

| File | What it says |
|---|---|
| `compliance.json` | `hipaa_role`, `purposes`, `jurisdictions` (US, US-XX, EU, UK, IN), `data_classes`, `device_status`, `risk_tier`, `retention`, `responsible_roles` (role → named person), `enforce_advisory` |
| `models.json` | For each destination: `endpoint`, `version` (pinned), `service`, `region`, `retention_days`, `logging`, `training_on_inputs` (must be stated), `allowed_classes`, `agreements` (kind, reference, signatory, scope, start, expiry), `subprocessors`, `preference` |
| `registries.json` | Purpose field allow-lists and `needs_phi`, authorizations, role access, restrictions, opt-outs, field classes, public fields, Part 2 consents, minors, the state table, studies (IRB expiry, protocol fields, consents, withdrawals), research pathways and waivers, data use agreements, EU transfer mechanisms, India consents and restricted regions |

`shio/governance/preflight/world.py` is a complete synthetic example: a fictional clinic, three fictional vendors.

## The gate

`Outcome` is a total order, ALLOW < REDACT < ROUTE < HOLD < DENY. Results are combined by its join: the strictest
outcome, plus the union of what each control asked for (fields to drop, tokenisation, approvers, warnings). The join
is commutative, associative and idempotent, so **the strictest result wins** and **order doesn't matter**. The tests
check both properties, over random combinations and over shuffled control orders.

The seven steps:
1. **Classify.** Declared labels, registry field classes, and detectors: the med.phi identifier patterns plus
   sensitive-class terms. Anything unlabelled counts as PHI.
2. **Context.** Who the organisation is and the declared purpose.
3. **Destination.** The requested model profile.
4. **Attestations.** Each `attestation` proof in a loaded pack becomes a gate control that looks the attestation up in
   a signed, hash-chained ledger. Revocation is another entry, never an edit.
5. **Data controls.**
6. **Decide.** A ROUTE re-runs every control against each approved alternative profile, in preference order, and
   denies if none passes. A REDACT drops fields and tokenises identifiers, keeping the token map in a `TokenVault` in
   memory (never in the prompt or the record). It then runs the detectors again on the outgoing payload, and any
   identifier left holds the call.
7. **Record, send, check the output.** The signed record is written before anything is sent. It holds hashes of the
   request, payload, context, profiles, registries and packs, plus every control result and the attestations used.
   It never holds the payload. `gate.client()` returns a client bound to that exact payload, which sends it once.
   `check_output` denies a reading that carries an identifier that wasn't sent, or a token the model shouldn't know.

**Fails closed.** Each of these denies: a crashing detector, a missing profile, an unreadable clock, a control that
raises, or a record that can't be written. **Holds** need a person in one of the hold's approver roles. Where the
compliance context names that person, it has to be them, and maker-checker applies (the caller can't approve). An
approved hold never clears a denial. **Tool results, documents, retrieved context and fed-back output** go through the
same gate (`source=`). **No bypass:** `shio preflight lint` fails the build if code imports a model SDK outside the
transport, and `ImportSeal` refuses such an import at run time. Python can't stop determined code; the lint is what
makes bypassing a CI failure.

## Enforced controls

There are 35 gate controls. Each has pass, fail and adversarial fixtures, and a mutation test: the fail fixture is
re-run with the control switched off and must come out weaker. All 143 checks pass, and `shio pack validate` runs
them for every pack that names a `gate` proof.

| Pack | Enforced at the gate |
|---|---|
| med.hipaa.privacy | PRV-01 purpose, PRV-02 authorization needed, PRV-03 authorization valid, PRV-04 minimum necessary, PRV-06 whole-record justification, PRV-07 role access, PRV-08 agreement and allowed classes and no training on inputs, PRV-09 de-identification by tokenisation, PRV-11 limited data set agreement, PRV-12 research pathway, PRV-14 restrictions, PRV-15 opt-outs |
| med.hipaa.security | SEC-08 unique identity, SEC-14 pinned version, SEC-15 TLS only |
| med.hipaa.baa | BAA-02 scope names the service, BAA-04 subprocessor flow-down, BAA-05 term (warns 60 days out) |
| med.sensitive | SEN-02 Part 2 consent, SEN-04 no legal-proceedings use, SEN-05 QSO or Part 2 flow-down, SEN-07 psychotherapy notes blocked, SEN-10 no genetic underwriting or employment use, SEN-11 minors, SEN-12 reviewed, current state-table rows |
| med.research | RES-01 registered study, RES-02 current IRB approval, RES-03 protocol fields, RES-04 current consent, RES-07 withdrawn participants |
| reg.eu | EU-01 Article 6 and 9, EU-03 processor agreement, EU-04 transfer mechanism |
| reg.india | IN-01 consent, IN-08 restricted transfers (advisory unless `enforce_advisory` lists reg.india) |

Organisational duties (stage X) are `attestation` controls: 32 of them across the 13 new packs.

## Packs and coverage

The spec's packs are generated as data by `tools/spec_packs.py`: med.hipaa.privacy, .security, .baa, .breach and
.records, med.sensitive, med.research, reg.eu, reg.india, sec.agent (its SEC-A01 to SEC-A10 are ASI-01 to ASI-10 here),
gov.iso42001, med.transparency and med.fairness. Every control carries its stage, on-fail and source. Its proof is
decided by what exists, never claimed: `gate`, `lint`, `attestation`, `signoff`, or `planned`.

[coverage.md](coverage.md) is the generated matrix. Across all 26 packs it lists 211 controls: 79 enforced, 8
measured, 41 attested and 83 planned. **Planned means not covered.** The matrix also lists the sources the spec leaves
out (FTC Health Breach Notification Rule, TEFCA, CCPA, UK GDPR, SOC 2 and HITRUST).

## Not done yet

- **Planned controls (83).** These include the breach and records packs, which are clocks and retention rather than
  request-time checks, plus most of med.research's stage R and A controls and most of sec.agent.
- **The 8 packs from the earlier build plan** (med.phi, med.grounding, med.rx, med.triage, med.cds, med.change,
  med.monitor, gov.nist-ai-rmf) are still at that plan's scope. The spec's larger control lists for them (PHI-01 to
  PHI-14, GRD-01 to GRD-08, RX-01 to RX-09, TRI-01 to TRI-08, CDS-01 to CDS-09, CHG-01 to CHG-07, MON-01 to MON-08,
  NST-01 to NST-08) are not yet catalogued. Their current controls appear in the matrix under their existing ids.
- **Detectors** are patterns and keyword lists. The spec's per-class recall corpus, a second detector pass with a
  different model family (PHI-07), and image, audio and quasi-identifier checks (PHI-08 to PHI-10) are not built. The
  gate's second pass reuses the same patterns.
- **The state table** ships with its schema and one fixture row. Counsel populates the real rows, and unreviewed
  states hold.
- **Holds are kept in memory** by the gate that made them, because payloads are never stored. A restarted process
  loses its open holds, and the caller re-asks.
- **People still decide.** Everything in the spec's "Open legal questions" and "Decisions needed" (the named clinical
  safety lead and counsel, US-first or India-first, shadow mode with a design partner) is still open. No pack is
  `reviewed`.
