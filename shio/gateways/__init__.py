"""HAR-8: gateways and approvers. The approver's identity comes from the channel, never from what a message says.

  SlackGateway   verifies Slack's request signature (v0: HMAC-SHA256 over "v0:{timestamp}:{body}" with the signing
                 secret, timestamp within five minutes) and takes the approver from the payload's user id, mapped to a
                 person and role in the gateway's directory
  WebGateway     approval links carry an HMAC token over (run, hold, identity, expiry): the identity is whoever the
                 link was issued to, and a token for one held call can't approve another
  EmailGateway   email has no verifiable sender here, so a reply must carry a WebGateway token; the From header is
                 never trusted

Every approval records who approved, through which channel, and the exact call (the run's hold and its call key).
A message can't approve its own request: the engine refuses when the approver is the run's requester, and gateways
refuse a token issued to the requester. Inbound messages (a Slack post, an email body) are untrusted input: use
inbound() to wrap them as such before they reach an agent.
"""
import hashlib
import hmac
import json
import time
import urllib.parse


class GatewayError(PermissionError):
    pass


class Directory:
    """channel identity -> (person, role). Only people listed here can approve through a gateway."""

    def __init__(self, entries):
        self.entries = {k: tuple(v) for k, v in entries.items()}

    def who(self, ident):
        if ident not in self.entries:
            raise GatewayError(f"{ident} is not in the approver directory")
        return self.entries[ident]


def inbound(channel, text, sender=None):
    return {"trust": "untrusted", "channel": channel, "sender_claimed": sender, "text": text}


class _Base:
    channel = "base"

    def __init__(self, engine, directory):
        self.engine, self.directory = engine, directory

    def _apply(self, run_id, hold, ident, decision, note=""):
        person, role = self.directory.who(ident)
        run = self.engine.journal.run(run_id)
        req = run["input"].get("requester") if isinstance(run["input"], dict) else None
        if req and person.strip().lower() == str(req).strip().lower():
            raise GatewayError(f"{person} requested this run, so can't approve it")
        f = self.engine.approve if decision == "approve" else self.engine.reject
        f(run_id, hold, person, role, channel=f"{self.channel}:{ident}", note=note)
        return {"run_id": run_id, "hold": hold, "by": person, "role": role, "channel": self.channel,
                "identity": ident, "decision": decision}


class SlackGateway(_Base):
    channel = "slack"

    def __init__(self, engine, directory, signing_secret, clock=time.time):
        super().__init__(engine, directory)
        self.secret, self.clock = signing_secret.encode(), clock

    def verify(self, body, timestamp, signature):
        if abs(self.clock() - int(timestamp)) > 300:
            raise GatewayError("stale Slack request (replay protection)")
        base = f"v0:{timestamp}:".encode() + body
        expect = "v0=" + hmac.new(self.secret, base, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, signature or ""):
            raise GatewayError("Slack signature does not match")

    def handle(self, body, timestamp, signature):
        """An interactive action: payload={"user": {"id": ...}, "actions": [{"value": "approve|reject:RUN:HOLD"}]}."""
        self.verify(body, timestamp, signature)
        form = urllib.parse.parse_qs(body.decode())
        payload = json.loads(form.get("payload", ["{}"])[0])
        ident = payload["user"]["id"]
        decision, run_id, hold = payload["actions"][0]["value"].split(":", 2)
        if decision not in ("approve", "reject"):
            raise GatewayError("unknown action")
        return self._apply(run_id, hold, ident, decision)


class WebGateway(_Base):
    channel = "web"

    def __init__(self, engine, directory, secret, clock=time.time):
        super().__init__(engine, directory)
        self.secret, self.clock = secret.encode(), clock

    def token(self, run_id, hold, ident, ttl=86400):
        exp = int(self.clock() + ttl)
        msg = f"{run_id}|{hold}|{ident}|{exp}"
        return f"{msg}|{hmac.new(self.secret, msg.encode(), hashlib.sha256).hexdigest()}"

    def redeem(self, token, decision="approve", note=""):
        try:
            run_id, hold, ident, exp, mac = token.split("|")
        except ValueError:
            raise GatewayError("malformed approval token") from None
        msg = f"{run_id}|{hold}|{ident}|{exp}"
        if not hmac.compare_digest(hmac.new(self.secret, msg.encode(), hashlib.sha256).hexdigest(), mac):
            raise GatewayError("approval token does not verify")
        if self.clock() > int(exp):
            raise GatewayError("approval token expired")
        return self._apply(run_id, hold, ident, decision, note)


class EmailGateway(WebGateway):
    channel = "email"

    def handle_reply(self, raw_email):
        """Finds a WebGateway token in the reply; the From header is ignored."""
        import re
        m = re.search(r"run-[\w.-]+\|[\w]+\|[\w@.+-]+\|\d+\|[0-9a-f]{64}", raw_email)
        if not m:
            raise GatewayError("no approval token in the reply (the sender address is not proof of identity)")
        decision = "reject" if re.search(r"(?im)^\s*reject", raw_email) else "approve"
        return self.redeem(m.group(0), decision)
