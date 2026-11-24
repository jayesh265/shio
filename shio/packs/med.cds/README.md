# med.cds

The build fails if an agent card contradicts its declared decision-support posture.

**Status: draft.** Counsel must review the constraints. They are worded as enforcement of a declared posture, never
as a determination of device status.

Declare a posture in the agent manifest:

```json
"decision_support": {"posture": "hcp-decision-support", "shows_basis": true, "time_critical": false,
                     "inputs": ["text"], "clinical_roles": ["clinician"]}
```

`shio registry scan` and `shio assess` (proof `cds-posture`) then fail on any contradiction:

| Constraint | The card must show |
|---|---|
| CDS-1 audience | `audience: clinician` |
| CDS-2 inputs | no `image(...)` source; no image, signal or waveform inputs declared |
| CDS-3 oversight | `requires_signoff: "*"` and a signoff by a clinical role |
| CDS-4 basis | `shows_basis: true` and `med.grounding` in force |
| CDS-5 not urgent | `time_critical: false` |
| CDS-6 no actions | no acting tool other than `allowed_actions` |

## Limits

- Passing says the agent as built matches what was declared. It says nothing about whether it is a medical device.
- The constraints are checked on the card and program, not on use in practice: deployment monitoring (med.monitor)
  still applies.
