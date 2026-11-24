"""Credo AI export sink (D33): agent cards and evidence bundles sent to a Credo AI tenant.

A sink: it receives finished, signed artefacts and returns nothing, so it sits outside every decision. It maps a card
to an AI system registration and a bundle to evidence per control, and POSTs them as JSON.

NOT VERIFIED AGAINST A TENANT. Credo AI's API is not public documentation this code could be checked against, and
the build plan notes that tenant access is needed to test it. The endpoint paths and payload field names below are
configuration with placeholder defaults, to be confirmed against a real tenant before use. Until then, dry_run=True
(the default) writes each payload to a folder instead of sending it, so the mapping can be reviewed.
"""
import json
import urllib.request
from pathlib import Path

from ..adapters import Manifest, SinkAdapter, TrustClass

DEFAULT_PATHS = {"card": "/api/v2/{tenant}/use_cases", "bundle": "/api/v2/{tenant}/evidences"}


class CredoSink(SinkAdapter):
    manifest = Manifest("credo-ai-sink", "0.1.0", TrustClass.SINK, "MIT OR Apache-2.0",
                        "agent cards and evidence bundles to a Credo AI tenant (unverified: needs tenant access)")

    def __init__(self, base_url=None, tenant=None, token_env="CREDO_API_TOKEN", paths=None, dry_run=True,
                 out=None, timeout=15, opener=None):
        if base_url and not base_url.startswith("https://"):
            raise ValueError("the Credo AI base URL must be https://")
        self.base_url, self.tenant, self.token_env = (base_url or "").rstrip("/"), tenant, token_env
        self.paths = {**DEFAULT_PATHS, **(paths or {})}
        self.dry_run, self.out, self.timeout, self.opener = dry_run, Path(out) if out else None, timeout, opener
        self.sent = []

    # ---------------- mapping ----------------
    @staticmethod
    def card_payload(card):
        return {"name": card["name"], "description": card["purpose"], "owner": card["owner"],
                "external_id": f"shio:{card['name']}", "metadata": {
                    "shio_card_sha256": card["sha256"], "signature": card.get("signature"),
                    "key_id": card.get("key_id"), "program_sha256": card["program"]["sha256"],
                    "regulated": card["program"]["regulated"],
                    "risk_tiers": {d.get("name", "?"): d["risk_tier"] for d in card["deployments"]},
                    "models": [{k: m.get(k) for k in ("name", "kind", "model", "pinned", "digest", "simulated")}
                               for m in card["models"]],
                    "tools": [t["name"] + (" (acts)" if t["mode"] == "acts" else "") for t in card["tools"]],
                    "packs": [f"{p['id']}@{p['version']}" for p in card["packs"]],
                    "signoff_roles": card["signoff_roles"]}}

    @staticmethod
    def bundle_payload(bundle, manifest=None):
        return {"framework": bundle["framework"]["id"], "framework_version": bundle["framework"]["version"],
                "period": {"from": bundle["period"][0], "to": bundle["period"][1]},
                "ledger_head": bundle["ledger"]["head"], "manifest_sha256": (manifest or {}).get("sha256"),
                "controls": [{"control_id": c["id"], "title": c["title"], "status": c["status"],
                              "references": [f"{r['framework']} {r['ref']}" for r in c["refs"]],
                              "evidence": [e["proof"] for e in c["evidence"]]} for c in bundle["controls"]]}

    # ---------------- sending ----------------
    def emit(self, record, name):
        """The sink interface: an agent card or a bundle.json (with its manifest). Returns nothing."""
        kind = "card" if record.get("format") == "shio-card/1" else \
            "bundle" if record.get("format") == "shio-bundle/1" else None
        if kind is None:
            return None
        payload = self.card_payload(record) if kind == "card" else self.bundle_payload(record)
        self._send(kind, payload, name)
        return None

    def export_bundle(self, folder):
        folder = Path(folder)
        b = json.loads((folder / "bundle.json").read_text())
        m = json.loads((folder / "manifest.json").read_text())
        self._send("bundle", self.bundle_payload(b, m), folder.name)

    def _send(self, kind, payload, name):
        path = self.paths[kind].format(tenant=self.tenant or "TENANT")
        if self.dry_run:
            if self.out:
                self.out.mkdir(parents=True, exist_ok=True)
                (self.out / f"{kind}-{Path(name).stem}.json").write_text(
                    json.dumps({"POST": path, "body": payload}, indent=1))
            self.sent.append({"dry_run": True, "path": path, "kind": kind})
            return
        import os
        token = os.getenv(self.token_env)
        if not (self.base_url and self.tenant and token):
            raise RuntimeError(f"sending to Credo AI needs base_url, tenant and {self.token_env}")
        req = urllib.request.Request(self.base_url + path, data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}",
                                              "User-Agent": "shio-guard-sink"})
        with (self.opener or urllib.request.urlopen)(req, timeout=self.timeout) as resp:
            self.sent.append({"dry_run": False, "path": path, "kind": kind, "status": resp.status})
