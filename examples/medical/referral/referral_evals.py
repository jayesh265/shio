"""Eval targets for the referral summariser (shio eval). Not imported by the program, so not part of its records.

SIMULATED: synthetic letters and mock models (referral_support.py). The labelled grounding set is written by
engineers, not clinicians; its rates show the measurement works, not how a real model performs.
"""
import json
import tempfile
from pathlib import Path

import shio
from shio import core
from shio.core import Source
from shio.ledger import Signer
from shio.models import replay

HERE = Path(__file__).resolve().parent
import referral_support as support  # noqa: E402  (after HERE, so the folder is importable when run from elsewhere)

MODELS = {"careful": support.careful, "obedient": support.obedient, "sloppy": support.sloppy, "leaky": support.leaky,
          "unapproved": support.unapproved}
_program = None


def program():
    global _program
    if _program is None:
        _program = shio.load(HERE / "referral.shio")
    return _program


def _run(letter_text, name, model, records=None):
    """Run the agent with its records in a scratch folder (an eval is not a decision) under a throwaway key."""
    saved = {k: core._config.get(k) for k in ("trace_dir", "signer")}
    folder = records or tempfile.mkdtemp(prefix="shio-eval-")
    core.configure(trace_dir=folder, signer=Signer("hmac", b"eval-only", "hmac:eval-only"))
    try:
        out = program().summarise(Source("letter", text=letter_text), name, model, support.detector)
    finally:
        core._config.update(saved)
    decided = out.get("decided", out)
    return {"status": decided["status"], "rejected": decided["status"] != "SUMMARY_READY",
            "why": decided.get("why", [])}


def agent_target(inp):
    """{"letter": "L001", "variant": "clean"|"injected", "model": "careful"|...} -> the decided outcome."""
    pid = inp["letter"]
    text = support.injected_letter(pid) if inp.get("variant") == "injected" else support.letter(pid)
    return _run(text, support.patient(pid)["name"], MODELS[inp.get("model", "careful")])


def grounding_target(inp):
    """{"letter": "L001", "summary": {...}}: the agent's checks judge a given summary (a labelled output)."""
    pid = inp["letter"]
    fixed = replay(lambda req: json.dumps(inp["summary"]), name="referral-mock")
    return _run(support.letter(pid), support.patient(pid)["name"], fixed)
