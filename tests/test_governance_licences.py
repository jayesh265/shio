"""The licence and dependency policy (D4): SPDX expressions, the policy's judgement, and the check CI runs."""
import pytest

from shio.governance.licences import All_, Any_, Lic, LicenceError, Policy, check, parse_spdx


def test_spdx_precedence_and_parentheses():
    assert parse_spdx("MIT") == Lic("MIT")
    e = parse_spdx("MIT OR Apache-2.0 AND BSD-3-Clause")            # AND binds tighter than OR
    assert e == Any_((Lic("MIT"), All_((Lic("Apache-2.0"), Lic("BSD-3-Clause")))))
    assert parse_spdx("(MIT OR Apache-2.0) AND BSD-3-Clause") == All_((Any_((Lic("MIT"), Lic("Apache-2.0"))),
                                                                       Lic("BSD-3-Clause")))
    assert parse_spdx("GPL-2.0-only WITH Classpath-exception-2.0").exception == "Classpath-exception-2.0"


@pytest.mark.parametrize("bad", ["", "MIT OR", "(MIT", "MIT)", "AND MIT", "MIT OR OR Apache-2.0", "MIT $ BSD"])
def test_malformed_expressions_are_errors_not_crashes(bad):
    with pytest.raises(LicenceError):
        parse_spdx(bad)


@pytest.fixture
def policy():
    return Policy.load()


def test_core_allows_only_mit_and_apache(policy):
    assert policy.judge("x", "MIT")[0] and policy.judge("x", "Apache-2.0")[0]
    assert policy.judge("x", "Apache-2.0 OR BSD-3-Clause")[0]          # one allowed choice is enough
    assert not policy.judge("x", "BSD-3-Clause")[0]
    assert policy.judge("x", "BSD-3-Clause", "extra")[0]               # extras may use the wider list
    assert not policy.judge("x", "MIT AND BSD-3-Clause")[0]            # AND needs both


@pytest.mark.parametrize("lic", ["AGPL-3.0-only", "SSPL-1.0", "BUSL-1.1", "MIT AND AGPL-3.0-or-later"])
def test_agpl_sspl_and_source_available_are_denied_everywhere(policy, lic):
    assert not policy.judge("x", lic, "core")[0]
    assert not policy.judge("x", lic, "extra")[0]


def test_unknown_licence_fails_closed(policy):
    ok, why, _ = policy.judge("mystery", None)
    assert not ok and "fails closed" in why


def test_exceptions_are_named_and_flagged_until_counsel_approves(policy):
    ok, why, exc = policy.judge("typing-extensions", "PSF-2.0")
    assert ok and exc and "pending counsel" in why
    assert not policy.judge("other-package", "PSF-2.0")[0]


def test_the_installed_dependencies_pass_and_the_policy_says_it_is_unapproved():
    ok, findings, notes = check(extras=("regulated",))
    assert ok, [f for f in findings if not f.ok]
    assert any("counsel has not approved" in n for n in notes)
    assert {f.package for f in findings} >= {"shio-lang", "pydantic", "cryptography"}
    strict_ok, _, _ = check(strict=True)
    assert not strict_ok                       # strict CI fails while an exception awaits counsel
