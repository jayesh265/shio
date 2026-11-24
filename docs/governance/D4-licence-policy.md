# D4: Licence and dependency policy

**Status: PROPOSED. Awaiting regulatory counsel's approval.** The policy is `shio/governance/licence-policy.json`;
counsel approves it by recording their name and date in `approved_by`. Until then every `shio licences check` prints
that it is unapproved.

| Scope | Allowed |
|---|---|
| Core (`pip install shio-lang`, no extras) | MIT, Apache-2.0 |
| Extras (`shio-lang[...]`) | the core list, plus BSD-2-Clause, BSD-3-Clause, ISC, MIT-0, 0BSD, PSF-2.0 |
| Never | AGPL (any), SSPL, BUSL, Elastic-2.0, Commons Clause, source-available licences, GPL, non-commercial licences |

## How it is checked

`shio licences check [--extra NAME]... [--strict]` reads every installed dependency of `shio-lang` (breadth first, so
each is reported with the shortest chain that pulls it in), takes its licence from PEP 639 `License-Expression`, else
its trove classifiers, else the free-text `License` field, parses it as an SPDX expression, and judges it: `A OR B`
needs one allowed, `A AND B` needs both. An unidentifiable licence is a violation (it fails closed). CI runs it on
every push, with the `regulated` and `pdf` extras.

## Exceptions

| Package | Licence | Scope | Why | Status |
|---|---|---|---|---|
| typing-extensions | PSF-2.0 | core | required by pydantic, the core's only direct dependency; PSF-2.0 is permissive | **pending counsel** |

An exception that counsel hasn't approved passes the default check with a note, and fails `--strict`.

## Each new dependency

Counsel confirms each new dependency (the plan's rule). Adapters declare their dependencies and licences in their
manifests, and conformance judges them against this policy, so an adapter can't bring in a licence the policy doesn't
allow.
