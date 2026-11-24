"""HAR-6: subagents. delegate() starts a child run with a narrower tool set; the child's answer comes back to the parent
as data (a reading the parent's code still has to check), and the parent's journal names the child's run and the
sha256 of its signed record.

    @engine.workflow("triage")
    def triage(ctx, inp):
        summary = delegate(ctx, parent_tools, "summarise", child_loop, inp["letter"], tools=["read_letter"])

A child may use only tools its parent has; asking for more is refused before the child starts. The child runs on the
same durable engine (its own journal, gate and budget), so it resumes, holds and replays like any run.
"""
import hashlib
from pathlib import Path


class DelegationError(PermissionError):
    pass


def delegate(ctx, parent_tools, name, child_workflow, request, tools, requester=None):
    have = {t.name if hasattr(t, "name") else t for t in parent_tools}
    extra = sorted(set(tools) - have)
    if extra:
        raise DelegationError(f"a child can't have tools its parent lacks: {', '.join(extra)}")
    out = ctx.child(name, child_workflow, {"request": request, "tools": sorted(tools), "requester": requester})
    return {"reading": out, "trust": "untrusted", "from_child": name}


def record_sha(engine, run_id):
    f = engine.records_for(run_id)
    if not f or not engine.records:
        return None
    return hashlib.sha256((Path(engine.records) / f).read_bytes()).hexdigest()
