"""Shio Guard: governance over Shio agents.

The language guarantees that a model only reads and code decides. This package turns that guarantee into the artefacts
a governance programme asks for, without weakening it:

  packs          dated, versioned, hash-pinned control packs (pack.json + deterministic checks + fixtures)
  adapters       reader, check and sink adapters, each with a trust class, a pinned version and a licence
  licences       the licence and dependency policy, and the check CI runs
  card           agent cards (`shio registry scan`): what an agent is, signed, with a re-review trigger
  assess         control proofs over a program hash (`shio assess`): static, for every code path
  bundle         framework evidence bundles an auditor verifies offline (`shio evidence --framework`)
  evals          eval harness: slices, regression and red-team suites, CI gates
  impact         change-impact replay: which recorded decisions a new model or policy would flip
  effectiveness  per-check blocked / overturned / precision from reviewer labels
  monitors       failure, override and drift monitors, incident and safety-event records
  safety         clinical safety case: hazard log, controls and evidence rebuilt from records
  policy_compiler plain-language policy -> draft checks and tests, with a trace and a human approval
  cedar          Cedar policies parsed and enforced (on Shio or any agent), Rego export, OPA backend
  promote        promotion gate: pinned model and program, regression run and role sign-off
  console        a read-only web console over records, cards, controls and evidence
  registry_index an open pack registry: publish, resolve and install packs by hash

Engineering rules (docs/governance/README.md): probabilistic tools enter as readers; only deterministic, pinned,
reviewed code becomes a check; exporters are sinks outside the boundary; MIT and Apache-2.0 only in the core.
"""
from .verdict import Verdict  # noqa: F401

__all__ = ["Verdict"]
