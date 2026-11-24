"""Fixture runner and mutation tests for gate controls (the spec's "for each control" rules).

For every control: each fixture runs through the whole gate over the fixture world and must reach its expected
outcome. Then each failing fixture runs again with that one control switched off, and must come out weaker. If it
is still stopped, the control was never the thing stopping it, and the test says so.
"""
import contextlib
import dataclasses
import tempfile
from pathlib import Path

from . import world as W
from .attest import AttestationLedger
from .context import ComplianceContext, Profiles, Registries
from .controls import BASE_REQUEST, CONTROLS
from .gate import Gate
from .model import Request


@dataclasses.dataclass(frozen=True)
class Outcome_:
    control: str
    fixture: str
    kind: str
    ok: bool
    detail: str


@contextlib.contextmanager
def fixture_gate(fx=None, disabled=frozenset(), attestation_controls=(), packs=()):
    """A gate over the fixture world (with a fixture's edits), in a throwaway folder."""
    c, m, r = W.world(*((fx.context, fx.models, fx.registries) if fx else (None, None, None)))
    with tempfile.TemporaryDirectory(prefix="shio-preflight-") as tmp:
        ledger = AttestationLedger(Path(tmp) / "attestations")
        for kind, owner, by, issued, expires in W.ATTESTATIONS:
            ledger.attest(kind, owner, by, issued, expires, "0" * 64)
        yield Gate(ComplianceContext.from_dict(c), Profiles.from_dict(m), Registries.from_dict(r), ledger,
                   Path(tmp) / "records", CONTROLS, attestation_controls, packs, clock=lambda: W.TODAY,
                   disabled=disabled)


def request(overrides):
    return Request(**{**BASE_REQUEST, **overrides})


def run(control, attestation_controls=(), packs=()):
    """-> [Outcome_] for one control's fixtures and mutation tests."""
    out = []
    kinds = {f.kind for f in control.fixtures}
    for k in ("pass", "fail", "adversarial"):
        if k not in kinds:
            out.append(Outcome_(control.key, "-", k, False, f"needs at least one {k} fixture"))
    for fx in control.fixtures:
        with fixture_gate(fx, attestation_controls=attestation_controls, packs=packs) as gate:
            d = gate.decide(request(fx.request))
        ok = d.outcome is fx.expect
        out.append(Outcome_(control.key, fx.id, fx.kind, ok, f"got {d.outcome.label}, expected {fx.expect.label}"
                            + ("" if ok else f": {d.explain()}")))
        if fx.kind == "fail":
            with fixture_gate(fx, disabled={control.key}, attestation_controls=attestation_controls,
                              packs=packs) as gate:
                m = gate.decide(request(fx.request))
            weaker = m.outcome < fx.expect
            out.append(Outcome_(control.key, fx.id, "mutation", weaker,
                                f"with {control.key} off: {m.outcome.label}" + ("" if weaker else
                                                                                f" (still stopped: {m.explain()})")))
    return out


def run_all(controls=CONTROLS, attestation_controls=(), packs=()):
    return [r for c in controls for r in run(c, attestation_controls, packs)]
