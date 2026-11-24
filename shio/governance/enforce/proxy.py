"""INT-2: a drop-in, OpenAI-compatible proxy that applies Shio's gates with no change to the agent but one URL.

    shio proxy --upstream https://api.vendor.example --policy argpolicy.json [--compliance compliance/] --port 8787
    # the agent: OPENAI_BASE_URL=http://127.0.0.1:8787/v1

POST /v1/chat/completions is checked twice:
  on the way in   every message goes through the pre-model gate (when a compliance folder is given): tool and
                  function messages as source "tool", the rest as "user". Deny or hold answers 403 with a typed
                  error and nothing is sent upstream; redact replaces that message's text with the redacted text.
  on the way out  every tool call the model proposes is checked against the argument policy; a refused call is
                  removed from the response and replaced by a note the agent can read (and a header says so).
                  The assistant's text is checked for identifiers that weren't sent (PHI-11).
Each response carries X-Shio-Gate-Ms, the time Shio added, so the cost is visible (NFR-4).

Limits: the proxy sees messages and tool calls, not the agent's internal provenance, so the in-process Guard (which
knows where each value came from) protects more. Streaming responses are refused rather than passed unchecked. Only
the chat completions route is proxied; anything else is 404. It binds to 127.0.0.1 by default.
"""
import json
import time
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class GuardProxy:
    def __init__(self, upstream, policy=None, gate=None, caller="proxy-agent", role="clinician", purpose="treatment",
                 destination=None, opener=None, timeout=60, log=None):
        if not upstream.startswith(("http://", "https://")):
            raise ValueError("upstream must be an http(s) URL")
        self.upstream, self.policy, self.gate = upstream.rstrip("/"), policy, gate
        self.caller, self.role, self.purpose, self.destination = caller, role, purpose, destination
        self.opener, self.timeout = opener or urllib.request.urlopen, timeout
        self.log = log if log is not None else []

    # ---------------- in ----------------
    def _inbound(self, body, headers):
        if not self.gate:
            return body, None
        from ..preflight.model import Outcome, Request
        decisions = []
        msgs = []
        for m in body.get("messages", []):
            content = m.get("content")
            if not isinstance(content, str) or not content.strip():
                msgs.append(m)
                continue
            req = Request(caller=headers.get("X-Shio-Caller") or self.caller, role=headers.get("X-Shio-Role") or self.role,
                          purpose=headers.get("X-Shio-Purpose") or self.purpose,
                          destination=self.destination or body.get("model", ""), text=content,
                          source="tool" if m.get("role") in ("tool", "function") else "user")
            d = self.gate.decide(req)
            decisions.append(d)
            if not d.sendable:
                return None, d
            msgs.append({**m, "content": d.payload["text"]} if d.outcome is Outcome.REDACT else m)
        return {**body, "messages": msgs}, decisions[-1] if decisions else None

    # ---------------- out ----------------
    def _outbound(self, resp, decision):
        blocked = []
        for ch in resp.get("choices", []):
            msg = ch.get("message") or {}
            kept = []
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function") or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    args = None
                d = self.policy.check(fn.get("name", ""), args if isinstance(args, dict) else "unparseable") \
                    if self.policy else None
                if d is None or d.allowed:
                    kept.append(tc)
                else:
                    blocked.append(d.explain())
            if msg.get("tool_calls") is not None:
                msg["tool_calls"] = kept or None
                if not kept:
                    msg.pop("tool_calls")
                    ch["finish_reason"] = "stop"
            if blocked:
                msg["content"] = ((msg.get("content") or "") + "\n[shio: tool call refused: " + "; ".join(blocked)
                                  + "]").strip()
            if self.gate and decision is not None and isinstance(msg.get("content"), str):
                r = self.gate.check_output(decision, msg["content"])
                if r is not None:
                    msg["content"] = "[shio: the reply was withheld: it carried identifiers that were not sent]"
                    blocked.append(r.reason)
        return resp, blocked

    def handle(self, path, body_bytes, headers):
        """-> (status, response dict, extra headers). Pure enough to test without sockets for the decision parts."""
        t0 = time.perf_counter()
        if path.rstrip("/") not in ("/v1/chat/completions", "/chat/completions"):
            return HTTPStatus.NOT_FOUND, {"error": {"type": "not_found", "message": "only chat completions"}}, {}
        try:
            body = json.loads(body_bytes or b"{}")
        except ValueError:
            return HTTPStatus.BAD_REQUEST, {"error": {"type": "invalid_json", "message": "body is not JSON"}}, {}
        if body.get("stream"):
            return HTTPStatus.BAD_REQUEST, {"error": {"type": "shio_unsupported",
                                                      "message": "streaming is refused: it can't be checked"}}, {}
        try:
            out, decision = self._inbound(body, headers)
        except Exception as e:                       # fail closed
            return HTTPStatus.FORBIDDEN, {"error": {"type": "shio_gate", "message": f"fail-closed: {type(e).__name__}"}}, {}
        if out is None:
            self.log.append({"stage": "in", "outcome": decision.outcome.label})
            return HTTPStatus.FORBIDDEN, {"error": {"type": "shio_gate", "code": decision.outcome.label,
                                                    "message": decision.explain(), "hold": decision.hold_id}}, \
                {"X-Shio-Gate-Ms": f"{(time.perf_counter() - t0) * 1000:.2f}"}
        gate_ms = (time.perf_counter() - t0) * 1000
        fwd = urllib.request.Request(f"{self.upstream}/v1/chat/completions", data=json.dumps(out).encode(),
                                     method="POST", headers={"Content-Type": "application/json",
                                                             **({"Authorization": headers["Authorization"]}
                                                                if headers.get("Authorization") else {})})
        try:
            with self.opener(fwd, timeout=self.timeout) as r:
                resp = json.loads(r.read())
        except Exception as e:
            return HTTPStatus.BAD_GATEWAY, {"error": {"type": "upstream", "message": type(e).__name__}}, {}
        t1 = time.perf_counter()
        resp, blocked = self._outbound(resp, decision)
        gate_ms += (time.perf_counter() - t1) * 1000
        self.log.append({"stage": "out", "blocked": blocked})
        hdrs = {"X-Shio-Gate-Ms": f"{gate_ms:.2f}"}
        if blocked:
            hdrs["X-Shio-Blocked"] = str(len(blocked))
        return HTTPStatus.OK, resp, hdrs


def serve(proxy, host="127.0.0.1", port=8787):
    class H(BaseHTTPRequestHandler):
        server_version = "ShioProxy/1"

        def _send(self, status, obj, extra):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for k, v in extra.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            self._send(*proxy.handle(self.path, self.rfile.read(n), dict(self.headers)))

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(HTTPStatus.OK, {"ok": True}, {})
            self._send(HTTPStatus.NOT_FOUND, {"error": {"type": "not_found"}}, {})

        def log_message(self, *a):
            pass
    return ThreadingHTTPServer((host, port), H)
