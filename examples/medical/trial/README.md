# Reference agent 2: trial eligibility screener

> **SIMULATED.** A fixture protocol (FX-TRIAL-007), a fixture study drug (Zelvaprant, FX-INV-101), a fixture
> formulary, synthetic charts and a mock model (`screener_support.py`). Not a real study, drug or patient.

Blinding is checked before anything reaches the model: chart C10 names the participant's arm, so it is never read.
A model reads the chart's facts; code decides eligibility (med.trial TRL-1), the consent version (TRL-5) and, for an
eligible participant, the study drug's dose recomputed from weight, age and kidney function (med.rx RX-2),
interactions (RX-3) and allergies (RX-4). Every outcome waits for an investigator.

| Chart | Expected | Why |
|---|---|---|
| C01, C02 | ELIGIBLE | C02's dose is halved for kidney function |
| C03, C04, C05 | NOT_ELIGIBLE | over 80; pregnant; HbA1c above 10.5 |
| C06 | REVIEW | pregnancy status not recorded (unknown is never eligible) |
| C07 | REVIEW | interacts with clarithromycin |
| C08 | REVIEW | consent version out of date |
| C09 | REVIEW | planned dose double the recomputed dose |
| C10 | REVIEW | the chart names the allocation: never sent to the model |

```bash
export SHIO_SIGNING_KEY=hmac:demo
shio run screener.shio C02 --traces records
shio eval evals/eligibility.json
```
