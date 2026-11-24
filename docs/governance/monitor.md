# The Shio Guard monitor

A live, read-only dashboard over every checkpoint Shio Guard keeps. It runs at `/monitor` inside `shio console`.

```bash
shio console --workspace ws/                 # ws/records, cards, reviews, bundles, evals, gates, policies
shio console --demo /tmp/shio-demo           # build a SYNTHETIC demo workspace there, then serve it
# then open http://127.0.0.1:8765/monitor
```

Every part of a workspace is optional, and each one can also be given separately (`--records`, `--cards`,
`--reviews`, `--bundles`, `--evals`, `--gates`, `--policies`). Pass `--pubkey` to verify signatures. A workspace
built by `--demo` uses its own key automatically.

## What it shows

| View | Checkpoints |
|---|---|
| Overview | Headline numbers, every checkpoint as OK / Attention / Failing / No data with the line that explains it, check runs per day, and the sign-off queue |
| Checks | Every check across every decision: runs, pass rate, failures per day, top reason codes, the controls it cites, and its last failure |
| Decisions | The ledger: filter by agent, sign-off state, failed checks or text; page through outcomes, sign-offs, labels and signatures |
| Tool-call gates | Microsoft AGT (and other) gate ledgers: allowed, approved, held and denied calls per day; which rules decided; which layer decided (AGT, Shio Guard, fail-safe); chain verification; AGT policy files and their rules |
| Monitoring | The window against its baseline: model failure rate, check failure rate, override rate, outcome drift (PSI), drift for each check, alerts, and incidents |
| Evals | Each sealed eval result: cases, metrics, gates, failed cases, results by subgroup, seal and signature |
| Packs and controls | Every pack's version, status, licence and validator result (fixtures run); search any control by id, title, framework reference or proof |
| Agents | Agent cards: intact, reviewed, risk tiers, pinned models, tools, packs, and who signs off |
| Evidence | Framework evidence bundles (counts and gaps), assessments and other sealed documents |

The page refreshes every 10 seconds while it is visible, unless you switch auto-refresh off. It works in light and
dark themes and at phone width.

## How it is built

- **`shio/governance/monitor.py`** holds the data. `Workspace` resolves the folders, and `MonitorService` turns them
  into JSON views (`summary`, `checks`, `decisions`, `gates`, `monitoring`, `evals`, `packs`, `cards`, `bundles`,
  `policies`). Each view is cached against a fingerprint of the files it reads (path, size, modification time), so
  a dashboard polling every few seconds re-reads only what changed. The ledger is read once per change and shared by
  every view.
- **`shio/governance/console.py`** serves the API at `GET /api/<view>` (decisions take `limit`, `offset`, `agent`,
  `status`, `failed`, `q`), the page at `/monitor` and its three static files. The classic server-rendered pages are
  unchanged.
- **`shio/governance/ui/`** is plain HTML, CSS and JavaScript, with no build step and no outside libraries. Charts are
  SVG drawn in the page.

## Security and privacy

- **Read-only.** Only GET and HEAD are answered; anything else gets 405. Files are served only by name from a fixed
  list. The console binds to 127.0.0.1 by default, and on loopback it answers only loopback `Host` headers, so a web
  page elsewhere can't read it through DNS rebinding.
- **No script injection.** The monitor's content security policy allows scripts and styles from the console itself
  only: no inline script, no `eval`, no other origins, no framing. The page builds every element with `textContent`,
  never `innerHTML`. The classic pages still allow no scripts at all.
- **No personal data.** Views carry check names, reason codes, outcome labels and counts. They never include a
  model's reading, a record's inputs, or anything in the vault. Gate entries carry argument names, not values. A test
  asserts that no patient name or argument value appears in any view.

## Limits

- It is a local, single-user console with no authentication, so don't expose it beyond loopback without putting
  your own authentication in front of it.
- It reads files. It does not stream: a new record appears at the next refresh.
- Monitoring uses `shio.governance.monitors` with its default 14-day window and 56-day baseline.
- The demo workspace is synthetic, and none of its numbers are evidence about anything.

Tests: `tests/test_governance_monitor.py`.
