# AGENTS.md

Guidance for AI coding agents (and people) working in this repository. Shio is a language for agents in which the
model reads, code decides and people approve; it compiles `.shio` files to Python.

## Setup and checks

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[regulated,pdf]" pytest
pytest -q                                            # language, runtime, guard, boundary fuzzing (about a minute)
SHIO_FUZZ_N=5000 pytest -q tests/test_fuzz_boundary.py   # a longer fuzz run before touching the boundary
for f in examples/*.shio examples/*/*.shio; do case "$f" in *_unsafe.shio) ;; *) shio check "$f";; esac; done
shio pack validate && shio licences check --extra regulated --extra pdf   # Shio Guard: packs and licence policy
cd editors/vscode && npm install && npm test         # the VS Code extension
```

CI runs all of this on Python 3.10, 3.12 and 3.13, plus a plain `pip install shio-lang` (the extra-only tests skip).

## Where things are

| Path | What it is |
|---|---|
| `shio/compiler.py` | `.shio` -> Python. The boundary's compile-time half: reading names, reflection, pure checks |
| `shio/core.py` | The runtime: readings (sealed), checks, rules, agents, traces, sign-off |
| `shio/guard.py`, `shio/guard.shio` | Shio Guard: plan, provenance ledger and gate for any agent's tool calls |
| `shio/models.py` | Model backends (Ollama, OpenAI-compatible, Anthropic, replay), retries and pacing |
| `shio/ledger.py`, `shio/policy.py` | Regulated mode: signed hash-chained records, the vault, policy tables |
| `shio/governance/` | Shio Guard: packs, adapters, cards, control proofs, bundles, evals, replay, monitors, console (docs/governance) |
| `shio/governance/monitor.py`, `shio/governance/ui/` | The live monitor: JSON views of every checkpoint, and the dashboard at `/monitor` |
| `shio/governance/adapters_ext/agt.py` | Microsoft Agent Governance Toolkit as a policy backend, tool gate and check adapter (`[agt]` extra) |
| `shio/governance/preflight/` | The pre-model compliance gate: context, profiles, attestations, controls (with fixtures), record, no-bypass lint |
| `shio/governance/enforce/`, `attack/` | Argument and temporal policies, breakers, MCP pins, signals, the proxy; the adaptive attacker |
| `shio/governance/{inventory,risk,oversight,workflow,clinical,doctor}.py` | Registry, risk, evidence report and review queue, exceptions and policy changes, clinical calibration and release, doctor |
| `shio/durable/`, `shio/harness/`, `shio/sandbox/`, `shio/tools/`, `shio/gateways/`, `shio/adapters/` | Durable execution and the code-driven harness (experimental): every act goes through the Guard gate, every step through the journal |
| `tools/spec_packs.py` | Generates the policy pack specification's packs; edit the catalogue there, not the generated pack.json |
| `shio/packs/` | Built-in control packs: `pack.json`, deterministic `checks.py`, pass/fail/adversarial `fixtures/` |
| `examples/medical/` | The two reference agents (simulated data and models) |
| `tests/test_boundary_escapes.py`, `tests/test_fuzz_boundary.py` | Every known escape route, and generated ones |
| `SPEC.md`, `SECURITY.md` | The design, and what Shio does and does not guarantee |

## Rules

- **Keep the boundary sound.** A model's reading may be looked at only in a `check`, a `when`, a `rule` or a later
  read's `seeing` clause. Any change that lets a reading's value reach plain code without one of those is a bug.
  Add a test to `tests/test_boundary_escapes.py` for every route you close, and never weaken an existing one.
- **Checks only decide.** A `check` or `when` must not assign or mutate. Actions belong in rules.
- **Fail safe.** A model that fails, times out or answers badly gives a null reading, which fails its checks. Never
  turn a model failure into a crash or into a pass.
- **Errors point at the `.shio` line** and say what to write instead.
- **No secrets in traces.** API keys come from the environment and never appear in a trace (there is a test).
- **No client names or data** in examples, tests or docs. Use fictional companies.
- **Numbers in docs come from runs.** Benchmark figures in the README must match a results file; state the setup and
  the limits next to them.
- **Packs only claim what was reviewed.** A pack may say "compliant" only when counsel (and, for `med.*`, the clinical
  lead) are named in its review; every runtime check ships pass, fail and adversarial fixtures; `shio pack validate`
  enforces both. Probabilistic tools enter as readers, never as checks (docs/governance/D3-adapter-interface.md).
- **New syntax goes in SPEC.md first**, with the problem it solves. Record user-visible changes in CHANGELOG.md.
- Commit messages say what changed and why. Don't push or release without the maintainer's go-ahead.
