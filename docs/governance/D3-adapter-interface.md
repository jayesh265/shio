# D3: Adapter interface

Outside tools enter a Shio agent only through adapters, and the trust class decides the adapter type.

| Trust class | Base class | What it may do | Where its output goes |
|---|---|---|---|
| reader | `ReaderAdapter` | anything probabilistic: an LLM, a classifier, an NER model, an LLM-based validator | it answers a read, so its output is a **Reading**: sealed until a check or rule looks at it |
| check | `CheckAdapter` | deterministic code that decides: a lookup in a pinned table, a policy engine (Cedar, OPA) | a `Verdict` a check or rule uses |
| sink | `SinkAdapter` | export finished records: a GRC tool, a SIEM, a dashboard (Credo AI, JUnit) | nowhere: `emit()` returns nothing |
| host | `HostAdapter` | run a Shio agent: an orchestrator (Temporal) | the agent's own outcome, unchanged |

## Manifest

Every adapter class carries a `Manifest`: name, **exact version**, trust class, SPDX licence, description, its
dependencies (each with an exact version and a licence), the pip extra that installs them, and, for checks, who
reviewed it. Its implementation is hashed (the sha256 of the source file); an agent manifest pins that hash:

```json
"adapters": [{"ref": "shio.governance.adapters_ext.phi_detector:PatternPhiDetector", "sha256": "…"}]
```

## Conformance (`shio adapters check`, and every `shio registry scan`)

- All: has a manifest; the trust class matches the base class; its licence and its dependencies' licences are
  allowed by the licence policy (D4).
- Regulated mode: the version and every dependency are pinned exactly, and the agent manifest pins the implementation
  hash, which matches the code. **An unpinned adapter refuses the build** (D10's gate). At run time a reader without
  a pin has no `pinned` identity, so a regulated read refuses it too.
- Reader: inside an agent its answer is a Reading, sealed outside checks and rules, and answers a read.
- Check: reviewed (regulated mode); ships fixtures; each fixture gives the same Verdict twice and leaves its input
  unchanged.
- Sink: `emit()` returns nothing and leaves the record unchanged.
- Host: hands back exactly what the agent returned.

The card carries a CycloneDX-style SBOM: each adapter with its trust class, pin and licence, its dependencies, and the
program's local modules with their hashes.

## Reviewed against the threat model

The review of this spec against [THREAT-MODEL.md](../THREAT-MODEL.md) found five risks; each has a mitigation in the
code, and the threat model now has a section on adapters (§8):

| Risk | Mitigation |
|---|---|
| A probabilistic tool registered as a check decides on its own | the trust class is declared in the manifest and checked against the base class; readers can only answer reads, so their output is sealed; checks must be reviewed and deterministic (fixtures run twice) |
| An adapter's code changes after review | the implementation hash is pinned per agent; a different hash fails conformance and the card build |
| A dependency floats to a compromised release | exact pins required in regulated mode; dependencies install only as extras |
| A sink feeds data back into a decision | `emit()` must return nothing; sinks are never passed to agents |
| An adapter's licence contaminates the core | each manifest's licence and dependency licences are judged by the licence policy at conformance |
