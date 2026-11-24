"""The Shio Guard web console, v1 (D25): read-only, over records, agent cards, controls, evidence and the reviewer
queue, so a compliance user can find a control's evidence without the command line.

    shio console --records records/ --cards cards/ --bundles bundles/ --reviews reviews/ [--port 8765]
    shio console --workspace ws/          ws/records, ws/cards, ws/reviews, ws/bundles, ws/evals, ws/gates, ws/policies
    shio console --demo /tmp/shio-demo    build a SYNTHETIC demo workspace there and serve it

Two faces over the same folders: the pages below (server-rendered, no scripts at all), and the live monitor at
/monitor, a dashboard of every checkpoint that polls a JSON API (/api/<view>, shio.governance.monitor). The monitor's
script is served by the console itself: its pages allow scripts from 'self' only, never inline or from elsewhere, and
it builds the page with textContent, never innerHTML, so nothing from a record can run.

Read-only by construction: it answers GET and HEAD only (anything else is 405), opens files only from the folders it
was given and only by names it listed itself, never reads a vault (so personal data and free text stay where the
record put them), escapes everything it shows, and sends a content security policy that allows no scripts. It binds
to 127.0.0.1 unless told otherwise. Standard library only.
"""
import html
import json
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from ..evidence import _outcome_label, pending_signoffs
from ..ledger import _entries, labels
from .packs import builtin, read, resolve

CSS = """body{font:15px/1.5 system-ui,sans-serif;margin:0;color:#1d1d1f;background:#fafaf8}
header{background:#1d2b3a;color:#fff;padding:12px 24px}header a{color:#cfe3ff;margin-right:18px;text-decoration:none}
main{padding:20px 24px;max-width:1200px}table{border-collapse:collapse;width:100%;margin:12px 0;background:#fff}
td,th{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f0f0ec}
.ok{color:#16672f;font-weight:600}.bad{color:#a4161a;font-weight:600}.warn{color:#8a5a00;font-weight:600}
code{background:#f0f0ec;padding:1px 4px;border-radius:3px}form{margin:12px 0}input{padding:6px;width:320px}
@media (prefers-color-scheme:dark){body{background:#151515;color:#eee}table{background:#1e1e1e}th{background:#2a2a2a}
td,th{border-color:#333}code{background:#2a2a2a}}"""
SAFE_NAME = re.compile(r"^[\w.@-]+$")
UI = Path(__file__).resolve().parent / "ui"
STATIC = {"monitor.js": "text/javascript; charset=utf-8", "monitor.css": "text/css; charset=utf-8",
          "monitor.svg": "image/svg+xml"}
HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
MONITOR_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
               "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
JSON_CSP = "default-src 'none'; frame-ancestors 'none'"


def e(x):
    return html.escape("" if x is None else str(x))


def _status_class(s):
    s = str(s).upper()
    return "ok" if s in ("APPROVED", "EVIDENCED", "PROVEN", "VERIFIED", "DECIDED") else \
        "bad" if s in ("REJECTED", "GAP", "FAILED", "MISSING") else "warn"


class Console:
    def __init__(self, records=None, cards=None, bundles=None, reviews=None, packs=(), evals=None, gates=None,
                 policies=None, workspace=None, public_key=None):
        from .monitor import MonitorService, Workspace
        self.workspace = Workspace(workspace, records=records, cards=cards, bundles=bundles, reviews=reviews,
                                   evals=evals, gates=gates, policies=policies)
        ws = self.workspace
        self.records, self.cards, self.bundles, self.reviews = ws.records, ws.cards, ws.bundles, ws.reviews
        self.extra_packs = list(packs)
        self.monitor = MonitorService(ws, packs, public_key=public_key)
        self.routes = [(re.compile(p), fn) for p, fn in [
            (r"^/$", self.home), (r"^/records$", self.record_list), (r"^/record/(?P<name>[\w.@-]+)$", self.record),
            (r"^/cards$", self.card_list), (r"^/card/(?P<name>[\w.@-]+)$", self.card),
            (r"^/controls$", self.control_list), (r"^/control/(?P<pack>[\w.@-]+)/(?P<cid>[\w-]+)$", self.control),
            (r"^/queue$", self.queue), (r"^/bundles$", self.bundle_list),
            (r"^/bundle/(?P<name>[\w.@-]+)$", self.bundle)]]

    # ---------------- data ----------------
    def _record_files(self):
        if not self.records:
            return []
        return [x["file"] for x in _entries(self.records) if x.get("kind") == "record"
                and (self.records / x["file"]).exists()]

    def _load(self, folder, name, allowed):
        if not folder or not SAFE_NAME.match(name) or name not in allowed:
            return None
        return json.loads((folder / name).read_text())

    def _card_files(self):
        return sorted(p.name for p in self.cards.glob("*.json")) if self.cards else []

    def _bundle_names(self):
        return sorted(p.name for p in self.bundles.iterdir() if (p / "bundle.json").exists()) if self.bundles else []

    def _packs(self):
        out = {pid: read(p) for pid, p in builtin().items()}
        for ref in self.extra_packs:
            pk = read(resolve(ref))
            out[pk.id] = pk
        return out

    # ---------------- pages ----------------
    def page(self, title, body):
        nav = "".join(f'<a href="{h}">{t}</a>' for h, t in [("/monitor", "Live monitor"), ("/", "Overview"),
                                                              ("/records", "Records"),
                                                              ("/cards", "Agent cards"), ("/controls", "Controls"),
                                                              ("/bundles", "Evidence bundles"),
                                                              ("/queue", "Reviewer queue")])
        return (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport "
                f"content='width=device-width,initial-scale=1'><title>{e(title)} · Shio Guard</title><style>{CSS}"
                f"</style></head><body><header><strong>Shio Guard</strong> &nbsp; {nav}</header><main><h1>{e(title)}"
                f"</h1>{body}<p style='color:#888'>Read-only. Vaults are never opened here.</p></main></body></html>")

    @staticmethod
    def table(headers, rows):
        return ("<table><tr>" + "".join(f"<th>{e(h)}</th>" for h in headers) + "</tr>"
                + "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows) + "</table>")

    def home(self, q):
        recs, cards, bundles = self._record_files(), self._card_files(), self._bundle_names()
        pending = pending_signoffs(self.records) if self.records else []
        body = self.table(["What", "Count"], [[f'<a href="/records">Decision records</a>', len(recs)],
                                              [f'<a href="/queue">Waiting for sign-off</a>', len(pending)],
                                              [f'<a href="/cards">Agent cards</a>', len(cards)],
                                              [f'<a href="/bundles">Evidence bundles</a>', len(bundles)],
                                              [f'<a href="/controls">Controls (packs)</a>',
                                               sum(len(p.controls) for p in self._packs().values())]])
        body += ("<form action=/controls method=get><label>Find a control's evidence: <input name=q "
                 "placeholder='e.g. PHI-1, grounding, MEASURE 2.5'></label></form>")
        return self.page("Overview", body)

    def record_list(self, q):
        rows = []
        verdicts = {f: ls[-1]["verdict"] for f, ls in labels(self.records).items()} if self.records else {}
        for name in reversed(self._record_files()):
            rec = json.loads((self.records / name).read_text())
            out = rec.get("outcome")
            decided = out.get("decided") if isinstance(out, dict) and out.get("status") == "PENDING" else out
            rows.append([f'<a href="/record/{e(name)}">{e(name)}</a>', e(rec.get("agent")),
                         e(_outcome_label(out)), e(_outcome_label(decided)), e(rec.get("record_type", "decision")),
                         e(verdicts.get(name, "-"))])
        return self.page("Decision records", self.table(["Record", "Agent", "Outcome", "Decided", "Type", "Label"],
                                                        rows))

    def record(self, q, name):
        rec = self._load(self.records, name, set(self._record_files()))
        if rec is None:
            return None
        checks = [[e(c["name"]), f"<span class={'ok' if c['passed'] else 'bad'}>"
                   f"{'skipped' if c.get('skipped') else 'passed' if c['passed'] else 'failed'}</span>",
                   e(c.get("code")), "<br>".join(f'<a href="/control/{e(x.split(":")[0])}/{e(x.split(":")[1])}">{e(x)}'
                                                 f'</a>' for x in c.get("controls", []))] for c in rec.get("checks", [])]
        so = [x for x in _entries(self.records) if x.get("kind") == "signoff" and x.get("file") == name]
        body = (f"<p>Agent <code>{e(rec.get('agent'))}</code>; program <code>"
                f"{e((rec.get('program') or {}).get('sha256', '')[:16])}</code>; packs: "
                + ", ".join(f"<code>{e(p['id'])}@{e(p['version'])}</code>" for p in rec.get("packs", [])) + "</p>")
        body += "<h2>Checks</h2>" + self.table(["Check", "Result", "Reason code", "Controls"], checks)
        body += "<h2>Outcome</h2><pre>" + e(json.dumps(rec.get("outcome"), indent=1)[:4000]) + "</pre>"
        body += "<h2>Sign-offs</h2>" + (self.table(["By", "Role", "Decision", "Meaning"],
                                                   [[e(s["signer"]), e(s["role"]), e(s.get("decision")),
                                                     e(s["meaning"])] for s in so]) if so else "<p>None.</p>")
        return self.page(name, body)

    def card_list(self, q):
        rows = []
        for name in self._card_files():
            c = json.loads((self.cards / name).read_text())
            if c.get("format") != "shio-card/1":
                continue
            state = "-"
            if self.reviews:
                from .card import review_status
                state = "APPROVED" if review_status(c, self.reviews)[0] else "NEEDS REVIEW"
            rows.append([f'<a href="/card/{e(name)}">{e(c["name"])}</a>', e(c["purpose"][:120]),
                         e(", ".join(d["risk_tier"] for d in c["deployments"])), f"<code>{e(c['sha256'][:12])}</code>",
                         f"<span class={_status_class(state)}>{e(state)}</span>"])
        return self.page("Agent cards", self.table(["Agent", "Purpose", "Risk tiers", "Card hash", "Review"], rows))

    def card(self, q, name):
        c = self._load(self.cards, name, set(self._card_files()))
        if c is None:
            return None
        body = f"<p>{e(c['purpose'])}</p><p>Owner {e(c['owner'])}; audience {e(c.get('audience'))}.</p>"
        body += "<h2>Models</h2>" + self.table(["Name", "Pinned", "Simulated", "Detail"],
                                               [[e(m["name"]), e(m["pinned"]), e(m.get("simulated")),
                                                 e(m.get("declared") or m.get("pinned") or m.get("kind"))]
                                                for m in c["models"]])
        body += "<h2>Checks</h2>" + self.table(["Agent", "Check", "Code", "Line"],
                                               [[e(x["agent"]), e(x["name"]), e(x["code"]), e(x["line"])]
                                                for x in c["checks"]])
        body += "<h2>Packs</h2>" + self.table(["Pack", "Version", "Status", "sha256"],
                                              [[e(p["id"]), e(p["version"]), e(p["status"]),
                                                f"<code>{e(p['sha256'][:16])}</code>"] for p in c["packs"]])
        body += "<h2>Deployments</h2>" + self.table(["Name", "Environment", "Risk tier", "Regulated"],
                                                    [[e(d.get("name")), e(d.get("environment")), e(d.get("risk_tier")),
                                                      e(d.get("regulated"))] for d in c["deployments"]])
        return self.page(f"Agent card: {c['name']}", body)

    def control_list(self, q):
        term = (q.get("q", [""])[0] or "").strip().lower()
        rows = []
        for pid, pack in sorted(self._packs().items()):
            for c in pack.controls:
                text = " ".join([pid, c.id, c.title, c.requirement, *[f"{r.framework} {r.ref}" for r in c.refs]]).lower()
                if term and term not in text:
                    continue
                rows.append([f'<a href="/control/{e(pack.id)}/{e(c.id)}">{e(c.id)}</a>', e(pack.label()), e(c.title),
                             e(", ".join(f"{r.framework} {r.ref}" for r in c.refs)),
                             e(", ".join(p.label() for p in c.proofs))])
        form = (f"<form method=get><input name=q value='{e(term)}' placeholder='search controls'></form>")
        return self.page("Controls", form + self.table(["Control", "Pack", "Title", "Framework refs", "Proofs"], rows))

    def control(self, q, pack, cid):
        packs = self._packs()
        pk = packs.get(pack.split("@")[0])
        if pk is None or cid not in {c.id for c in pk.controls}:
            return None
        c = pk.control(cid)
        body = (f"<p><strong>{e(c.title)}</strong>: {e(c.requirement)}</p><p>Proofs: "
                + ", ".join(f"<code>{e(p.label())}</code>" for p in c.proofs) + "</p>")
        hits = []
        for name in self._record_files():
            rec = json.loads((self.records / name).read_text())
            for ch in rec.get("checks", []):
                for x in ch.get("controls", []):
                    if x.split("@")[0] == pk.id and x.endswith(f":{cid}"):
                        hits.append([f'<a href="/record/{e(name)}">{e(name)}</a>', e(ch["name"]), e(x),
                                     f"<span class={'ok' if ch['passed'] else 'bad'}>"
                                     f"{'passed' if ch['passed'] else 'failed'}</span>"])
        body += "<h2>Checks in decision records</h2>" + (self.table(["Record", "Check", "Cited as", "Result"], hits)
                                                         if hits else "<p>No record cites this control.</p>")
        rows = []
        for b in self._bundle_names():
            bj = json.loads((self.bundles / b / "bundle.json").read_text())
            for ctl in bj.get("controls", []):
                if ctl["id"] == cid and bj["framework"]["id"] == pk.id:
                    rows.append([f'<a href="/bundle/{e(b)}">{e(b)}</a>', f"<span class={_status_class(ctl['status'])}>"
                                 f"{e(ctl['status'])}</span>", e("; ".join(x["proof"] for x in ctl["evidence"]))])
        body += "<h2>In evidence bundles</h2>" + (self.table(["Bundle", "Status", "Evidence"], rows) if rows else
                                                  "<p>No bundle maps this control.</p>")
        return self.page(f"{pk.label()} {cid}", body)

    def queue(self, q):
        rows = [[f'<a href="/record/{e(p["file"])}">{e(p["file"])}</a>', e(p["agent"]), e(", ".join(p["roles"])),
                 e(p["requested"]), e(p["age_days"])] for p in (pending_signoffs(self.records) if self.records else [])]
        body = "<h2>Decisions waiting for sign-off</h2>" + (self.table(["Record", "Agent", "Roles", "Requested",
                                                                       "Days waiting"], rows) if rows else "<p>None.</p>")
        if self.reviews and self.cards:
            from .card import review_status
            cards = []
            for name in self._card_files():
                c = json.loads((self.cards / name).read_text())
                ok, lines = review_status(c, self.reviews) if c.get("format") == "shio-card/1" else (True, [])
                if not ok:
                    cards.append([f'<a href="/card/{e(name)}">{e(c["name"])}</a>', e("; ".join(lines[1:]))])
            body += "<h2>Agent cards waiting for review</h2>" + (self.table(["Card", "Why"], cards) if cards else
                                                                 "<p>None.</p>")
        body += "<p>Sign-offs are given with <code>shio signoff</code> and reviews with <code>shio registry review"
        body += "</code>: this console never changes anything.</p>"
        return self.page("Reviewer queue", body)

    def bundle_list(self, q):
        rows = []
        for b in self._bundle_names():
            bj = json.loads((self.bundles / b / "bundle.json").read_text())
            rows.append([f'<a href="/bundle/{e(b)}">{e(b)}</a>', e(bj["framework_name"]), e(" to ".join(bj["period"])),
                         e(", ".join(f"{n} {s.lower()}" for s, n in bj["summary"].items()))])
        return self.page("Evidence bundles", self.table(["Bundle", "Framework", "Period", "Controls"], rows))

    def bundle(self, q, name):
        if name not in self._bundle_names():
            return None
        bj = json.loads((self.bundles / name / "bundle.json").read_text())
        rows = [[f'<a href="/control/{e(bj["framework"]["id"])}/{e(c["id"])}">{e(c["id"])}</a>', e(c["title"]),
                 f"<span class={_status_class(c['status'])}>{e(c['status'])}</span>",
                 "<br>".join(e(x["proof"]) + ": " + e(x.get("status") or x.get("detail") or x.get("value")
                                                       or x.get("signoffs")) for x in c["evidence"])]
                for c in bj["controls"]]
        return self.page(f"Bundle {name}", f"<p>{e(bj['framework_name'])}, {e(' to '.join(bj['period']))}. Ledger "
                                           f"{'verified' if bj['ledger']['verified'] else 'NOT verified'}.</p>"
                         + self.table(["Control", "Title", "Status", "Evidence"], rows))

    # ---------------- the live monitor ----------------
    DECISION_PARAMS = ("limit", "offset", "agent", "status", "failed", "q")

    def api(self, section, q):
        """-> (status, JSON text) for /api/<section>."""
        from .monitor import SECTIONS
        if section not in SECTIONS:
            return HTTPStatus.NOT_FOUND, json.dumps({"error": f"no view {section!r}", "views": list(SECTIONS)})
        params = {k: q[k][0] for k in self.DECISION_PARAMS if k in q} if section == "decisions" else {}
        try:
            data = self.monitor.view(section, **params)
        except (ValueError, TypeError) as err:
            return HTTPStatus.BAD_REQUEST, json.dumps({"error": f"bad parameter: {type(err).__name__}"})
        except Exception as err:                       # a view that fails says so; it never takes the console down
            return HTTPStatus.INTERNAL_SERVER_ERROR, json.dumps({"error": f"{section} failed: {type(err).__name__}"})
        return HTTPStatus.OK, json.dumps(data, default=str, ensure_ascii=False)

    def respond(self, path):
        """-> (status, body, content type, content security policy) for any path. The socket handler serves this."""
        url = urlparse(path)
        route = unquote(url.path)
        if route in ("/monitor", "/monitor/"):
            return HTTPStatus.OK, (UI / "monitor.html").read_text(), "text/html; charset=utf-8", MONITOR_CSP
        m = re.match(r"^/static/([\w.-]+)$", route)
        if m:
            name = m.group(1)
            if name not in STATIC:                       # only the files this console ships, by name
                return HTTPStatus.NOT_FOUND, "not found", "text/plain; charset=utf-8", JSON_CSP
            return HTTPStatus.OK, (UI / name).read_text(), STATIC[name], MONITOR_CSP
        m = re.match(r"^/api/([a-z]+)$", route)
        if m:
            status, body = self.api(m.group(1), parse_qs(url.query))
            return status, body, "application/json; charset=utf-8", JSON_CSP
        if route.startswith(("/api/", "/static/")):
            return HTTPStatus.NOT_FOUND, json.dumps({"error": "not found"}), "application/json; charset=utf-8", JSON_CSP
        status, body = self._pages(path)
        return status, body, "text/html; charset=utf-8", HTML_CSP

    # ---------------- dispatch ----------------
    def handle(self, path):
        """-> (status, html). Pure function of the path, so it is tested without a socket."""
        status, body, _, _ = self.respond(path)
        return status, body

    def _pages(self, path):
        url = urlparse(path)
        q = parse_qs(url.query)
        for pattern, fn in self.routes:
            m = pattern.match(unquote(url.path))
            if m:
                try:
                    out = fn(q, **m.groupdict())
                except (OSError, ValueError, KeyError) as err:
                    return HTTPStatus.INTERNAL_SERVER_ERROR, self.page("Error", f"<p>{e(type(err).__name__)}</p>")
                if out is None:
                    return HTTPStatus.NOT_FOUND, self.page("Not found", "<p>Nothing here.</p>")
                return HTTPStatus.OK, out
        return HTTPStatus.NOT_FOUND, self.page("Not found", "<p>Nothing here.</p>")


LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}


def handler_for(console, allowed_hosts=None):
    """allowed_hosts: the Host headers to answer (None: any). Bound to loopback, serve() sets it to the loopback
    names, so a web page elsewhere can't read the console through DNS rebinding."""
    class Handler(BaseHTTPRequestHandler):
        server_version = "ShioConsole/1"

        def _send(self, status, body, ctype="text/html; charset=utf-8", csp=HTML_CSP, head=False):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", csp)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if not head:
                self.wfile.write(data)

        def _host_ok(self):
            if allowed_hosts is None:
                return True
            host = (self.headers.get("Host") or "").strip().lower()
            name = host.rsplit(":", 1)[0] if not host.endswith("]") else host
            return name in allowed_hosts

        def _serve(self, head=False):
            if not self._host_ok():
                return self._send(HTTPStatus.FORBIDDEN, "unknown host", "text/plain; charset=utf-8", JSON_CSP, head)
            status, body, ctype, csp = console.respond(self.path)
            self._send(status, body, ctype, csp, head)

        def do_GET(self):
            self._serve()

        def do_HEAD(self):
            self._serve(head=True)

        def _refuse(self):
            self._send(HTTPStatus.METHOD_NOT_ALLOWED, console.page("Read-only", "<p>This console is read-only.</p>"))

        do_POST = do_PUT = do_DELETE = do_PATCH = _refuse

        def log_message(self, fmt, *args):     # no request logging to stderr by default
            pass

    return Handler


def serve(console, host="127.0.0.1", port=8765):
    server = ThreadingHTTPServer((host, port), handler_for(console, LOOPBACK if host in LOOPBACK else None))
    return server
