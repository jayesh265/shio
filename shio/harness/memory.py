"""HAR-4: memory with provenance. A write is an acts call through the Guard; a read comes back as data with its trust.

  memory_tools(store)  -> ToolSpecs for the agent loop: memory_write (acts, through the Guard), memory_recall (trusted
                         entries only, output "trusted") and memory_recall_untrusted (the rest, output "untrusted")
  provenance           a write's trust is decided by code, not by the model: text that appears in any untrusted tool
                       output this task saw (the Guard ledger) is saved as untrusted, whatever the model claims. Only
                       text grounded in the request or trusted records can become trusted memory
  storage              entries in a signed chain (id, trust, source, sha256 of the text); the text itself in a vault
                       file per entry
  erase                deletes the vault file and appends an erasure to the chain: the entry is gone, the chain still
                       verifies, and the erasure is on record
"""
import hashlib
import json
import uuid
from pathlib import Path

from ..governance.chain import ChainError, SignedChain


class MemoryStore:
    def __init__(self, folder, signer=None):
        self.folder, self.signer = Path(folder), signer
        self.chain = SignedChain(self.folder, "memory")
        (self.folder / "vault").mkdir(parents=True, exist_ok=True)

    def write(self, text, trusted, source, by):
        if not str(text).strip():
            raise ChainError("empty memory")
        mid = f"MEM-{uuid.uuid4().hex[:10]}"
        sha = hashlib.sha256(text.encode()).hexdigest()
        (self.folder / "vault" / f"{mid}.txt").write_text(text)
        self.chain.append("memory_write", {"id": mid, "trusted": bool(trusted), "source": source, "by": by,
                                           "text_sha256": sha}, self.signer)
        return mid

    def entries(self):
        erased = {e["id"] for e in self.chain.entries() if e["kind"] == "memory_erase"}
        out = []
        for e in self.chain.entries():
            if e["kind"] == "memory_write" and e["id"] not in erased:
                p = self.folder / "vault" / f"{e['id']}.txt"
                text = p.read_text() if p.exists() else None
                if text is not None and hashlib.sha256(text.encode()).hexdigest() != e["text_sha256"]:
                    text = None                      # an edited vault file is not memory
                out.append({"id": e["id"], "trusted": e["trusted"], "source": e["source"], "text": text})
        return out

    def recall(self, trusted, query=""):
        q = (query or "").lower()
        return [{"id": e["id"], "text": e["text"], "source": e["source"]} for e in self.entries()
                if e["trusted"] == trusted and e["text"] and q in e["text"].lower()]

    def erase(self, mid, by, reason):
        if mid not in {e["id"] for e in self.entries()}:
            raise ChainError(f"no memory {mid}")
        p = self.folder / "vault" / f"{mid}.txt"
        if p.exists():
            p.unlink()
        self.chain.append("memory_erase", {"id": mid, "by": by, "reason": reason}, self.signer)


def _seen_untrusted(session, text):
    """True when any 30-character window of the text appears in untrusted text this task read (the Guard ledger's
    untrusted outputs), or when there is no ledger to ask: provenance unknown is untrusted."""
    led = getattr(session, "ledger", None)
    if led is None:
        return True
    from ..guard import norm
    t = norm(text)
    pool = list(getattr(led, "untrusted", [])) + list(getattr(led, "open_text", []))
    if not pool:
        return False
    windows = [t] if len(t) <= 30 else [t[i:i + 30] for i in range(0, len(t) - 29, 10)]
    return any(w and w in u for u in pool for w in windows)


def memory_tools(store, by="agent"):
    from .loop import ToolSpec
    state = {"session": None}

    def memory_write(text, source="agent", _session=None):
        session = _session or state["session"]
        trusted = session is not None and not _seen_untrusted(session, text)
        mid = store.write(text, trusted, source, by)
        return {"id": mid, "saved_as": "trusted" if trusted else "untrusted"}

    def memory_recall(query=""):
        return store.recall(True, query)

    def memory_recall_untrusted(query=""):
        return store.recall(False, query)

    specs = [ToolSpec("memory_write", memory_write, "acts", "save a fact for later runs", content=("text",)),
             ToolSpec("memory_recall", memory_recall, "reads", "trusted memories", output="trusted"),
             ToolSpec("memory_recall_untrusted", memory_recall_untrusted, "reads", "memories from untrusted sources")]
    for s in specs:
        s.needs_session = s.name == "memory_write"
    return specs
