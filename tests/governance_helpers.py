"""Shared helpers for the Shio Guard tests: keys, a clean runtime config, and runs of the reference agents."""
import contextlib
import json
import sys
from pathlib import Path

import shio
from shio import core
from shio.core import Source
from shio.ledger import keygen, load_public_key, load_signer

ROOT = Path(__file__).resolve().parent.parent
REFERRAL = ROOT / "examples" / "medical" / "referral"
TRIAL = ROOT / "examples" / "medical" / "trial"
for p in (REFERRAL, TRIAL):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


@contextlib.contextmanager
def runtime(trace_dir=None, signer=None, actor="test-runner"):
    """Run with these settings, and put every setting back afterwards."""
    saved = dict(core._config)
    core._config.update(trace_dir=str(trace_dir) if trace_dir else None, signer=signer or False, actor=actor,
                        policies=False, jurisdiction=None, as_of=None, table_override=None)
    try:
        yield
    finally:
        core._config.clear()
        core._config.update(saved)


def keys(folder):
    priv, pub, _ = keygen(folder)
    return load_signer(str(priv)), load_public_key(pub)


def referral_program():
    return shio.load(REFERRAL / "referral.shio")


def run_referral(records, signer, letters=("L001",), model="careful", injected=False):
    """Run the referral summariser on synthetic letters; -> [(outcome, record path)]."""
    import referral_support as s
    prog = referral_program()
    out = []
    with runtime(records, signer, actor="intake-bot"):
        for pid in letters:
            text = s.injected_letter(pid) if injected else s.letter(pid)
            result = prog.summarise(Source(pid, text=text), s.patient(pid)["name"], getattr(s, model), s.detector)
            out.append((result, Path(prog.summarise.last_trace)))
    return out


def run_screener(records, signer, charts=("C01",)):
    import screener_support as s
    prog = shio.load(TRIAL / "screener.shio")
    out = []
    with runtime(records, signer, actor="screening-bot"):
        for cid in charts:
            result = prog.screen(Source(cid, text=s.chart(cid)), s.allocation(cid), s.careful)
            out.append((result, Path(prog.screen.last_trace)))
    return out


def load(path):
    return json.loads(Path(path).read_text())
