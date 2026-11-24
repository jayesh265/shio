"""med.change: a model digest and program hash pinned, and promotion blocked without a regression run of exactly
that release and a role sign-off. The gate itself is shio.governance.promote; the checks here are the deterministic
parts a pipeline (or an agent) runs on a candidate release."""
from shio.governance.verdict import Verdict


def release_pinned(release):
    """CHG-1: the release pins its program by sha256 and every model by a digest or exact version (a mock replay
    counts as pinned and says so)."""
    if not isinstance(release, dict) or len(str(release.get("program_sha256", ""))) != 64:
        return Verdict.fail("the release does not pin the program's sha256")
    loose = [n for n, m in (release.get("models") or {}).items()
             if not (m.get("digest") or m.get("pinned") or m.get("kind") == "replay"
                     or str(m.get("declared", "")).startswith("replay("))]
    if loose:
        return Verdict.fail(f"models not pinned: {', '.join(sorted(loose))}")
    if not release.get("models"):
        return Verdict.fail("the release names no models")
    return Verdict.ok("program and models pinned")


def regression_covers(release, result):
    """CHG-2: the regression result evaluated exactly this release (its sha256), and met its gates."""
    if not isinstance(result, dict) or result.get("suite") != "regression":
        return Verdict.fail("not a regression result")
    if (result.get("subject") or {}).get("release_sha256") != release.get("sha256"):
        return Verdict.fail("the regression run evaluated a different release")
    if result.get("gate_failures"):
        return Verdict.fail("the regression run missed its gates: " + "; ".join(result["gate_failures"]))
    if not result.get("gates"):
        return Verdict.fail("the regression run declares no gates, so it can't block a bad release")
    return Verdict.ok(f"regression run of this release met its gates ({result.get('passed')}/{result.get('cases')})")
