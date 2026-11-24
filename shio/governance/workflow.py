"""GOV-5: exceptions that expire, and four-eyes approval of policy changes, each a signed record.

Exceptions. A control can be waived for a named scope (an agent, a tool) by an owner, for a reason, until a date.
It takes effect only after a second person approves it, and lapses on its expiry with no action needed. A gate asks
`exceptions.active(control, scope, today)`; an expired or unapproved waiver is not active.

Policy changes. `propose(path, new_text, by)` records the change (the file's sha256 before and after, and a unified
diff); `approve(change, by, role)` records a second person's approval bound to the new content's hash; `apply(change)`
writes the file only when an approval by someone other than the proposer exists for exactly that content, and only
if the file has not changed since the proposal. Anything else is refused.
"""
import datetime as dt
import difflib
import hashlib
import uuid
from pathlib import Path

from .chain import APPROVED, ApprovalLog, ChainError, SignedChain


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


class Exceptions:
    def __init__(self, folder, signer=None):
        self.chain, self.approvals, self.signer = SignedChain(folder, "exceptions"), ApprovalLog(folder, "exception-"
                                                                                                         "approvals"), signer

    def request(self, control, scope, owner, reason, expires, requested_by):
        if not all(str(x).strip() for x in (control, scope, owner, reason, requested_by)):
            raise ChainError("an exception needs the control, its scope, an owner, a reason and who asked")
        if dt.date.fromisoformat(str(expires)) > dt.date.today() + dt.timedelta(days=366):
            raise ChainError("an exception may last at most a year; renew it instead")
        eid = f"EXC-{uuid.uuid4().hex[:8].upper()}"
        e = self.chain.append("exception", {"id": eid, "control": control, "scope": scope, "owner": owner,
                                            "reason": reason, "expires": str(expires), "requested_by": requested_by},
                              self.signer)
        return eid, e["sha256"]

    def _get(self, eid):
        for e in self.chain.entries():
            if e.get("kind") == "exception" and e["id"] == eid:
                return e
        raise ChainError(f"no exception {eid}")

    def approve(self, eid, by, role):
        e = self._get(eid)
        self.approvals.record("exception", e["sha256"], by, role, f"waive {e['control']} for {e['scope']}",
                              makers=[e["requested_by"], e["owner"]], signer=self.signer, title=eid)

    def active(self, control, scope, today=None):
        today = today or dt.date.today()
        for e in self.chain.entries():
            if e.get("kind") != "exception" or e["control"] != control or e["scope"] not in (scope, "*"):
                continue
            if dt.date.fromisoformat(e["expires"]) < today:
                continue
            decisions = [a["decision"] for a in self.approvals.for_subject(e["sha256"])]
            if "approved" in decisions and "rejected" not in decisions:
                return e
        return None

    def listing(self, today=None):
        today = today or dt.date.today()
        out = []
        for e in self.chain.entries():
            if e.get("kind") == "exception":
                ds = [a["decision"] for a in self.approvals.for_subject(e["sha256"])]
                approved = "approved" in ds and "rejected" not in ds
                state = "expired" if dt.date.fromisoformat(e["expires"]) < today else \
                    "active" if approved else "waiting for a second approver"
                out.append({**{k: e[k] for k in ("id", "control", "scope", "owner", "reason", "expires")},
                            "state": state})
        return out


class PolicyChanges:
    def __init__(self, folder, signer=None):
        self.chain, self.approvals, self.signer = SignedChain(folder, "policy-changes"), \
            ApprovalLog(folder, "policy-change-approvals"), signer

    def propose(self, path, new_text, by, why):
        path = Path(path)
        old = path.read_text() if path.exists() else ""
        diff = "".join(difflib.unified_diff(old.splitlines(True), new_text.splitlines(True), str(path), str(path)))
        cid = f"PCH-{uuid.uuid4().hex[:8].upper()}"
        self.chain.append("policy_change", {"id": cid, "path": str(path), "before_sha256": _sha(old),
                                            "after_sha256": _sha(new_text), "proposed_by": by, "why": why,
                                            "diff": diff[:20000]}, self.signer)
        self._pending = getattr(self, "_pending", {})
        self._pending[cid] = new_text
        return cid

    def _get(self, cid):
        for e in self.chain.entries():
            if e.get("kind") == "policy_change" and e["id"] == cid:
                return e
        raise ChainError(f"no policy change {cid}")

    def approve(self, cid, by, role, meaning="reviewed the diff"):
        e = self._get(cid)
        self.approvals.record("policy-change", e["after_sha256"], by, role, meaning, makers=[e["proposed_by"]],
                              signer=self.signer, title=cid)

    def apply(self, cid, new_text=None):
        e = self._get(cid)
        text = new_text if new_text is not None else getattr(self, "_pending", {}).get(cid)
        if text is None or _sha(text) != e["after_sha256"]:
            raise ChainError(f"{cid}: the text to apply is not the text that was proposed")
        ok = [a for a in self.approvals.for_subject(e["after_sha256"]) if a["decision"] == "approved"
              and a["by"] != e["proposed_by"]]
        if not ok:
            raise ChainError(f"{cid}: a policy change needs approval by a second person before it applies")
        path = Path(e["path"])
        cur = path.read_text() if path.exists() else ""
        if _sha(cur) != e["before_sha256"]:
            raise ChainError(f"{cid}: {path} changed since the proposal; propose again from the current version")
        path.write_text(text)
        self.chain.append("policy_applied", {"id": cid, "path": str(path), "after_sha256": e["after_sha256"],
                                             "approved_by": [a["by"] for a in ok]}, self.signer)
        return APPROVED
