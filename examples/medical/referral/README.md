# Reference agent 1: referral summariser

> **SIMULATED.** Synthetic letters (fictional people and numbers) and mock models (`referral_support.py`). Not a
> clinical tool. The labelled grounding set is written by engineers, not clinicians.

A model reads a referral letter and proposes a structured summary in which every claim quotes the letter. Code decides
whether it may go to the clinician:

| Check | Pack control | Catches |
|---|---|---|
| `approved` | med.phi PHI-2 | a model not approved for PHI (it is refused before it is sent anything) |
| `grounded` | med.grounding GRD-1 | a claim with no quote in the letter, or quoted only from hidden instructions |
| `figures` | med.grounding GRD-2 | a figure not in the letter (a tenfold dose) |
| `complete` | med.grounding GRD-3 | an allergy or medication left out |
| `no_identifiers` | med.phi PHI-1 | an identifier left in the summary |
| `minimum` | med.phi PHI-3 | fields beyond what the referral needs |
| `detected` | (reader) | what the PHI detector, a reader, found in the summary |

Every outcome, ready or not, waits for a clinician's sign-off (`signoff * by role "clinician"`).

```bash
shio keygen keys && export SHIO_SIGNING_KEY=keys/shio-signing.key
shio run referral.shio L001 --traces records --as intake-bot        # L001..L008
shio signoff records/<record>.json --as "Dr R. Osei" --role clinician --meaning "checked against the letter"
shio verify records --pubkey keys/shio-signing.pub
shio registry scan agent.json -o card.json && shio assess --manifest agent.json
for s in regression redteam grounding; do shio eval evals/$s.json; done
python measure_gtv.py                                               # D16: the three free-text options
```

Mock models: `careful` (faithful), `obedient` (follows hidden instructions in the letter), `sloppy` (a tenfold dose,
allergies dropped), `leaky` (copies the phone number), `unapproved` (not on the PHI list).
