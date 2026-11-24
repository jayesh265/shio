# API stability and deprecation (DX-7, NFR-10)

**Status: proposed.** The maintainers adopt this policy when 1.0.0 is released. Until then the policy applies to
release candidates as a promise of intent.

## What is stable

From 1.0.0, these are the public API. Breaking changes to them happen only in a major release.

| Surface | Stable parts |
|---|---|
| The language | `.shio` syntax and meaning as written in SPEC.md |
| Runtime | `shio.load`, `shio.configure`, `shio.core.Source`, `Reading`, `Verdict`, sign-off |
| Records | Record formats named in their `format` field (`shio-pack/1`, `shio-card/1`, `shio-preflight/1`, `shio-argpolicy/1`, `shio-eval/1`, ...), and `shio verify` |
| Shio Guard | `shio.guard.Guard`, `shio.governance.preflight` (`Gate`, `Request`, `Decision`, `Outcome`), `shio.governance.enforce.argpolicy` (`ArgPolicy`, `ArgGate`), and the adapter base classes in `shio.governance.adapters` |
| Command line | Command names, flags and exit codes documented in `shio --help` |
| Packs | The pack format; a pack's controls keep their ids within a major version of the pack |

Everything else is internal and may change in a minor release. That includes any module or name starting with `_`,
`harness`, the fixture worlds, and `tools/`.

## Versioning and deprecation

- Shio follows [semantic versioning](https://semver.org). Packs version independently, each with its own semver.
- **Deprecation window.** A stable name or flag is deprecated before it is removed. It warns (a `DeprecationWarning`,
  or a message on stderr) for at least **two minor releases and six months**, whichever is longer, and is removed
  only in the next major release.
- **Record formats are never broken in place.** A new format gets a new version (`/2`), and `shio verify` keeps
  verifying older records for the life of the major version.
- **Long-term support.** For regulated users, one minor line per major version is designated LTS and gets security
  fixes for 18 months.

## Limits

This policy doesn't promise behavioural stability for detectors (`med.phi` patterns, the de-obfuscation pass).
Making them catch more is not a breaking change, even if it holds requests that used to pass. Every such change is
recorded in CHANGELOG.md.
