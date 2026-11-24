"""The attestation ledger: organisational duties code cannot perform, as signed, expiring records.

A security risk analysis, a signed business associate agreement review, workforce training this period: Shio can't
do these, but it can refuse to send health data while one is missing or has lapsed. Each attestation is an entry in a
signed hash-chained ledger: what (kind), for what scope, who owns the duty, who signed, when it was issued, when it
expires, and the sha256 of the document it points to. Revocation is another entry, so history is never rewritten.
The current attestation of a kind is the latest unrevoked one whose window contains today.
"""
import dataclasses
import datetime as dt
import uuid

from ..chain import ChainError, SignedChain


@dataclasses.dataclass(frozen=True)
class Attestation:
    id: str
    kind: str
    scope: str
    owner_role: str
    signed_by: str
    issued: dt.date
    expires: dt.date
    document_sha256: str

    def current(self, today):
        return self.issued <= today <= self.expires


class AttestationLedger:
    def __init__(self, folder):
        self.chain = SignedChain(folder, "attestations")

    def attest(self, kind, owner_role, signed_by, issued, expires, document_sha256, scope="*", signer=None):
        issued, expires = dt.date.fromisoformat(str(issued)), dt.date.fromisoformat(str(expires))
        if expires < issued:
            raise ChainError("an attestation can't expire before it is issued")
        if not all(str(x).strip() for x in (kind, owner_role, signed_by, document_sha256)):
            raise ChainError("an attestation needs a kind, the owning role, who signed and the document's sha256")
        aid = f"ATT-{uuid.uuid4().hex[:10].upper()}"
        self.chain.append("attestation", {"id": aid, "attestation": kind, "scope": scope, "owner_role": owner_role,
                                          "signed_by": signed_by, "issued": issued.isoformat(),
                                          "expires": expires.isoformat(), "document_sha256": document_sha256}, signer)
        return aid

    def revoke(self, aid, by, reason, signer=None):
        if aid not in {a.id for a in self.all()}:
            raise ChainError(f"no attestation {aid}")
        self.chain.append("revocation", {"id": aid, "by": by, "reason": reason}, signer)

    def all(self):
        out = []
        for e in self.chain.entries():
            if e.get("kind") == "attestation":
                out.append(Attestation(e["id"], e["attestation"], e.get("scope", "*"), e["owner_role"], e["signed_by"],
                                       dt.date.fromisoformat(e["issued"]), dt.date.fromisoformat(e["expires"]),
                                       e["document_sha256"]))
        return out

    def revoked(self):
        return {e["id"] for e in self.chain.entries() if e.get("kind") == "revocation"}

    def current(self, kind, today, scope="*"):
        """The latest current, unrevoked attestation of this kind for the scope (or for every scope), else None."""
        gone = self.revoked()
        found = [a for a in self.all() if a.kind == kind and a.id not in gone and a.current(today)
                 and a.scope in (scope, "*")]
        return max(found, key=lambda a: (a.issued, a.id)) if found else None

    def verify(self, public_key=None):
        return self.chain.verify(public_key)

    def status(self, kinds, today):
        """{kind: (state, attestation)}: current, expiring (within 30 days), expired, or missing."""
        out = {}
        for k in kinds:
            cur = self.current(k, today)
            if cur:
                out[k] = ("expiring" if (cur.expires - today).days <= 30 else "current", cur)
            else:
                past = [a for a in self.all() if a.kind == k]
                out[k] = ("expired" if past else "missing", max(past, key=lambda a: a.expires) if past else None)
        return out
