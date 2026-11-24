"""Append-only, hash-chained, signed logs for governance events, and the approval log built on one.

The decision ledger (shio.ledger) holds decision records. Governance has events of its own that are not decisions:
a reviewer signing off a new agent card, a person approving a drafted check, a release manager promoting a model. Each
needs the same properties as the ledger: nothing can be edited, removed, inserted or reordered without the chain
showing it, and each entry is signed with the same keys (`shio keygen`, or hmac:).

A SignedChain is one JSONL file. Every entry carries its position (seq), the previous entry's hash (prev), its own
hash over everything else, and a signature over that hash.
"""
import json
import time
from pathlib import Path

from ..ledger import GENESIS, _check_signature, _locked, _same_person, sha256

_UNHASHED = ("sha256", "key_id", "signature")


class ChainError(ValueError):
    pass


def _hash(entry):
    return sha256({k: v for k, v in entry.items() if k not in _UNHASHED})


class SignedChain:
    def __init__(self, folder, name):
        self.folder = Path(folder)
        self.path = self.folder / f"{name}.jsonl"

    def entries(self):
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def _last(self):
        """The last entry, read from the end of the file (appends stay O(1) however long the chain grows)."""
        if not self.path.exists():
            return None
        with open(self.path, "rb") as f:
            f.seek(0, 2)
            end = f.tell()
            pos, buf = end, b""
            while pos > 0:
                step = min(4096, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
                lines = [x for x in buf.split(b"\n") if x.strip()]
                if len(lines) >= 2 or (pos == 0 and lines):
                    return json.loads(lines[-1])
        return None

    def append(self, kind, body, signer=None):
        """Chain, hash, sign and append one entry. -> the entry as written."""
        self.folder.mkdir(parents=True, exist_ok=True)
        with _locked(self.folder):
            last = self._last()
            entry = {**body, "kind": kind, "seq": last["seq"] + 1 if last else 0,
                     "prev": last["sha256"] if last else GENESIS, "time": body.get("time", time.time())}
            entry["sha256"] = _hash(entry)
            if signer is not None:
                entry["key_id"] = signer.key_id
                entry["signature"] = signer.sign(entry["sha256"])
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def verify(self, public_key=None, secret=None):
        """-> (ok, problems). With a key, every entry must carry a good signature."""
        problems, prev = [], GENESIS
        keyed = public_key is not None or secret is not None
        for i, e in enumerate(self.entries()):
            if e.get("seq") != i:
                problems.append(f"entry {i}: sequence number {e.get('seq')} out of order")
            if e.get("prev") != prev:
                problems.append(f"entry {i}: chain broken (an entry before it was changed, removed or reordered)")
            if _hash(e) != e.get("sha256"):
                problems.append(f"entry {i}: edited (its content no longer matches its hash)")
            state = _check_signature(e, public_key, secret)
            if state.startswith("BAD") or (keyed and state != "ok"):
                problems.append(f"entry {i}: {state}")
            prev = e.get("sha256")
        return not problems, problems


APPROVED, REJECTED, PENDING = "APPROVED", "REJECTED", "PENDING"


class ApprovalLog:
    """People's approvals of governance subjects, each bound to the subject's exact sha256.

    A subject is anything with a hash: an agent card, a drafted check, a promotion, a red-flag list, a safety case.
    An approval of one version says nothing about the next: change the subject and its hash changes, so it needs
    approving again. Maker-checker holds: whoever made the subject can't approve it, and nobody approves twice.
    """

    def __init__(self, folder, name="approvals"):
        self.chain = SignedChain(folder, name)

    def record(self, subject_kind, subject_sha256, by, role, meaning, decision="approved", makers=(), signer=None,
               title=""):
        if decision not in ("approved", "rejected"):
            raise ChainError(f"decision must be approved or rejected, not {decision!r}")
        if not str(by).strip() or not str(role).strip() or not str(meaning).strip():
            raise ChainError("an approval needs the person's name, their role and what it means")
        if any(_same_person(by, m) for m in makers):
            raise ChainError(f"maker-checker: {by} made this {subject_kind}, so can't approve it")
        prior = self.for_subject(subject_sha256)
        if any(_same_person(by, e["by"]) for e in prior):
            raise ChainError(f"maker-checker: {by} has already signed this {subject_kind}")
        return self.chain.append("approval", {"subject": {"kind": subject_kind, "sha256": subject_sha256,
                                                          "title": title},
                                              "by": str(by), "role": str(role), "meaning": str(meaning),
                                              "decision": decision, "makers": list(makers)}, signer)

    def for_subject(self, subject_sha256):
        return [e for e in self.chain.entries() if e.get("subject", {}).get("sha256") == subject_sha256]

    def status(self, subject_sha256, roles):
        """-> (APPROVED | REJECTED | PENDING, the roles still missing). Any rejection rejects."""
        entries = self.for_subject(subject_sha256)
        if any(e["decision"] == "rejected" for e in entries):
            return REJECTED, []
        given = {e["role"] for e in entries if e["decision"] == "approved"}
        missing = [r for r in roles if r not in given]
        return (PENDING if missing else APPROVED), missing

    def verify(self, public_key=None, secret=None):
        return self.chain.verify(public_key, secret)
