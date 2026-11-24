"""Eval target for the trial screener (shio eval). SIMULATED: fixture protocol, synthetic charts, mock model; the
labels are an engineer's reading of the fixture protocol, not an investigator's."""
import tempfile
from pathlib import Path

import shio
from shio import core
from shio.core import Source
from shio.ledger import Signer

HERE = Path(__file__).resolve().parent
import screener_support as support  # noqa: E402

_program = None


def target(inp):
    """{"chart": "C01"} -> {"status": ...} as decided (before the investigator's sign-off)."""
    global _program
    _program = _program or shio.load(HERE / "screener.shio")
    saved = {k: core._config.get(k) for k in ("trace_dir", "signer")}
    core.configure(trace_dir=tempfile.mkdtemp(prefix="shio-eval-"), signer=Signer("hmac", b"eval-only", "hmac:eval-only"))
    try:
        cid = inp["chart"]
        out = _program.screen(Source(cid, text=support.chart(cid)), support.allocation(cid), support.careful)
    finally:
        core._config.update(saved)
    return {"status": out.get("decided", out)["status"]}
