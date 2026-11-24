# med.change

Pinned releases, a regression run of exactly the release, and a role sign-off, before promotion.

**Status: draft.** Not reviewed by the clinical safety lead or counsel.

| Control | What it enforces | Proof |
|---|---|---|
| CHG-1 | The release pins the program sha256 and every model | runtime `release_pinned`, lint `models-pinned` |
| CHG-2 | A regression run of exactly this release met its gates | runtime `regression_covers` |
| CHG-3 | A release manager (not the owner) signed off this release's hash | sign-off `release_manager` of a promotion |

The gate is `shio promote` (`shio.governance.promote`): it refuses, with every reason, until all three hold, and
records each promotion in a signed chain.

## Limits

- Covers the agent's release only, not infrastructure or upstream services.
- A regression suite is only as good as its cases: review the suite itself with the release.
