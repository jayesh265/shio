"""The Shio Guard monitor: one read-only view of every checkpoint, for the dashboard at /monitor (D25, D27).

A Workspace is a folder laid out by convention (any part may be missing, and each can be given separately):

    records/    the signed decision ledger: decisions, sign-offs, labels, incidents
    cards/      agent cards (shio card build)
    reviews/    approvals of cards, monitoring reports and other subjects
    bundles/    framework evidence bundles (shio evidence --framework)
    evals/      sealed eval results and other sealed shio documents (assessments, safety cases)
    gates/      signed gate ledgers: Microsoft AGT decisions (agt-gate.jsonl) and other gate_decision chains
    policies/   AGT policy files (*.yaml) the gates enforce

MonitorService turns it into JSON views (summary, checks, decisions, gates, monitoring, evals, packs, cards, bundles,
policies). The summary is a list of checkpoints, each ok / warn / fail / none with the one line that explains it.

Read-only and private by construction: it opens files only inside the workspace, never opens a vault, and returns
check names, reason codes, outcome labels and counts, never a model's reading or a record's inputs. Gate entries
carry argument names, not values. Views are cached against a fingerprint of the files they read (path, size,
modification time), so a dashboard polling every few seconds re-reads only what changed.
"""
import datetime as dt
import json
import os
import threading
from collections import Counter, defaultdict
from pathlib import Path

from ..evidence import _outcome_label, pending_signoffs
from ..ledger import _entries, labels, signoff_state
from .monitors import _decided, _runs

SECTIONS = ("summary", "checks", "decisions", "gates", "preflight", "monitoring", "evals", "packs", "cards", "bundles",
            "policies")
OK, WARN, FAIL, NONE = "ok", "warn", "fail", "none"
SLA_DAYS = 2                     # a decision waiting longer than this for sign-off is overdue


class Workspace:
    """Where each kind of artefact lives. Explicit folders win over the root's conventional ones."""
    PARTS = ("records", "cards", "reviews", "bundles", "evals", "gates", "policies", "attestations")

    def __init__(self, root=None, **parts):
        self.root = Path(root) if root else None
        for name in self.PARTS:
            given = parts.get(name)
            if given:                                       # asked for by name: kept, even before it exists
                setattr(self, name, Path(given))
            else:
                path = self.root / name if self.root else None
                setattr(self, name, path if path is not None and path.exists() else None)

    def describe(self):
        return {name: str(getattr(self, name)) if getattr(self, name) else None for name in self.PARTS}


def _fingerprint(*folders):
    """(path, size, mtime) of every file directly in the folders: a cheap 'has anything changed' key."""
    out = []
    for f in folders:
        if f is None:
            continue
        try:
            with os.scandir(f) as it:
                for e in it:
                    if e.is_file():
                        st = e.stat()
                        out.append((e.path, st.st_size, st.st_mtime_ns))
                    elif e.is_dir():                       # one level down: bundles/<name>/bundle.json
                        p = Path(e.path) / "bundle.json"
                        if p.exists():
                            st = p.stat()
                            out.append((str(p), st.st_size, st.st_mtime_ns))
        except OSError:
            continue
    return tuple(sorted(out))


def _read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def _day(ts):
    return dt.date.fromtimestamp(ts).isoformat() if ts else None


class MonitorService:
    """The dashboard's data. Every public method returns plain JSON-ready data."""

    def __init__(self, workspace, packs=(), today=None, public_key=None):
        self.ws = workspace
        self.extra_packs = list(packs)
        self.today = today
        self.public_key = public_key
        self._cache, self._lock = {}, threading.Lock()

    # ---------------- cache ----------------
    def _cached(self, key, folders, fn):
        fp = (_fingerprint(*folders), self.today)
        with self._lock:
            hit = self._cache.get(key)
            if hit and hit[0] == fp:
                return hit[1]
        value = fn()
        with self._lock:
            self._cache[key] = (fp, value)
        return value

    def view(self, section, **params):
        if section not in SECTIONS:
            raise KeyError(section)
        if section == "decisions":
            return self.decisions(**params)
        return getattr(self, section)()

    def _now(self):
        return self.today or dt.date.today()

    # ---------------- the ledger, read once per change ----------------
    def _ledger(self):
        return self._cached("ledger", [self.ws.records], self._load_ledger)

    def _load_ledger(self):
        folder = self.ws.records
        if folder is None:
            return {"records": [], "entries": [], "verified": None, "problems": []}
        entries = _entries(folder)
        recs = []
        for e in entries:
            if e.get("kind") == "record" and (folder / e["file"]).exists():
                rec = _read_json(folder / e["file"])
                if rec is not None:
                    recs.append((e, rec))
        from ..ledger import verify
        try:
            ok, report, _ = verify(folder, self.public_key)
            problems = [] if ok else [x for x in report if "problem" in x.lower() or "broken" in x.lower()
                                      or "edited" in x.lower() or "missing" in x.lower()][:20] or report[:20]
        except Exception as err:                         # a ledger that can't be checked is not verified
            ok, problems = False, [f"{type(err).__name__}: {err}"]
        return {"records": recs, "entries": entries, "verified": ok, "problems": problems}

    # ---------------- checks: every check that ran, per check ----------------
    def checks(self):
        return self._cached("checks", [self.ws.records], self._checks)

    def _checks(self):
        led = self._ledger()
        stats = {}
        days = 30
        start = self._now() - dt.timedelta(days=days - 1)
        for e, rec in led["records"]:
            if rec.get("record_type", "decision") != "decision":
                continue
            day = dt.date.fromtimestamp(rec.get("started") or e.get("time", 0))
            for run in _runs(rec):
                for c in run.get("checks", []):
                    key = f"{run.get('agent')}.{c['name']}"
                    s = stats.setdefault(key, {"check": c["name"], "agent": run.get("agent"), "runs": 0, "passed": 0,
                                               "failed": 0, "skipped": 0, "controls": set(), "codes": Counter(),
                                               "series": defaultdict(lambda: [0, 0]), "last_failure": None,
                                               "last_run": None})
                    s["runs"] += 1
                    s["last_run"] = max(s["last_run"] or "", day.isoformat())
                    s["controls"].update(c.get("controls", []))
                    if c.get("skipped"):
                        s["skipped"] += 1
                        continue
                    if c["passed"]:
                        s["passed"] += 1
                    else:
                        s["failed"] += 1
                        s["codes"][c.get("code") or "(no code)"] += 1
                        s["last_failure"] = {"record": e["file"], "day": day.isoformat(), "code": c.get("code")}
                    if day >= start:
                        s["series"][day.isoformat()][0 if c["passed"] else 1] += 1
        out = []
        for key, s in sorted(stats.items()):
            judged = s["passed"] + s["failed"]
            out.append({**{k: v for k, v in s.items() if k not in ("controls", "codes", "series")}, "key": key,
                        "pass_rate": round(s["passed"] / judged, 4) if judged else None,
                        "controls": sorted(s["controls"]), "codes": s["codes"].most_common(5),
                        "series": [{"day": (start + dt.timedelta(days=i)).isoformat(),
                                    "passed": s["series"][(start + dt.timedelta(days=i)).isoformat()][0],
                                    "failed": s["series"][(start + dt.timedelta(days=i)).isoformat()][1]}
                                   for i in range(days)]})
        daily = [{"day": (start + dt.timedelta(days=i)).isoformat(), "passed": 0, "failed": 0} for i in range(days)]
        for c in out:
            for i, pt in enumerate(c["series"]):
                daily[i]["passed"] += pt["passed"]
                daily[i]["failed"] += pt["failed"]
        return {"checks": out, "daily": daily}

    # ---------------- decisions ----------------
    def _decision_rows(self):
        return self._cached("decision_rows", [self.ws.records], self._build_decision_rows)

    def _build_decision_rows(self):
        led = self._ledger()
        answers = defaultdict(list)
        for e in led["entries"]:
            if e.get("kind") == "signoff":
                answers[e.get("file")].append(e)
        verdicts = {f: ls[-1]["verdict"] for f, ls in labels(self.ws.records).items()} if self.ws.records else {}
        rows = []
        for e, rec in led["records"]:
            checks = [c for run in _runs(rec) for c in run.get("checks", []) if not c.get("skipped")]
            req = rec.get("signoff")
            state = signoff_state(req, answers[e["file"]])[0] if (req or {}).get("roles") else None
            rows.append({"file": e["file"], "agent": rec.get("agent"), "type": rec.get("record_type", "decision"),
                         "time": rec.get("started"), "day": _day(rec.get("started")),
                         "outcome": _outcome_label(rec.get("outcome")),
                         "decided": _outcome_label(_decided(rec.get("outcome"))),
                         "checks": len(checks), "failed": [c["name"] for c in checks if not c["passed"]],
                         "signoff": state, "roles": (req or {}).get("roles", []), "label": verdicts.get(e["file"]),
                         "packs": [f"{p['id']}@{p['version']}" for p in rec.get("packs", [])],
                         "signed": bool((rec.get("integrity") or {}).get("signature"))})
        rows.sort(key=lambda r: r["time"] or 0, reverse=True)
        return rows

    def decisions(self, limit=100, offset=0, agent=None, status=None, failed=None, q=None):
        rows = self._decision_rows()
        if agent:
            rows = [r for r in rows if r["agent"] == agent]
        if status:
            rows = [r for r in rows if status in (r["outcome"], r["decided"], r["signoff"])]
        if failed in ("1", "true", True):
            rows = [r for r in rows if r["failed"]]
        if q:
            ql = str(q).lower()
            rows = [r for r in rows if ql in r["file"].lower() or ql in " ".join(r["failed"]).lower()
                    or ql in str(r["outcome"]).lower()]
        limit, offset = max(1, min(int(limit), 500)), max(0, int(offset))
        return {"total": len(rows), "offset": offset, "rows": rows[offset:offset + limit],
                "agents": sorted({r["agent"] for r in self._decision_rows() if r["agent"]})}

    # ---------------- gates: AGT and other gate ledgers ----------------
    def gates(self):
        return self._cached("gates", [self.ws.gates], self._gates)

    def _gates(self):
        from .chain import SignedChain
        if self.ws.gates is None:
            return {"chains": [], "entries": [], "by_effect": {}, "by_rule": [], "by_action": [], "by_layer": {},
                    "daily": [], "total": 0}
        chains, entries = [], []
        for p in sorted(self.ws.gates.glob("*.jsonl")):
            chain = SignedChain(self.ws.gates, p.stem)
            try:
                ok, problems = chain.verify(self.public_key)
                es = chain.entries()
            except Exception as err:
                ok, problems, es = False, [f"{type(err).__name__}: {err}"], []
            es = [x for x in es if x.get("kind") == "gate_decision"]
            chains.append({"name": p.stem, "entries": len(es), "verified": ok, "problems": problems[:10],
                           "engines": sorted({x.get("engine", "?") for x in es})})
            for x in es:
                d = x.get("decision") or {}
                entries.append({"chain": p.stem, "seq": x.get("seq"), "time": x.get("time"), "day": _day(x.get("time")),
                                "engine": x.get("engine"), "engine_version": x.get("engine_version"),
                                "agent": x.get("agent"), "requester": x.get("requester"), "action": x.get("action"),
                                "args": x.get("args", []), "allowed": bool(d.get("allowed")),
                                "effect": d.get("effect"), "rule": d.get("rule"), "reason": d.get("reason"),
                                "layer": d.get("layer"), "approval": x.get("approval"),
                                "policy_sha256": (x.get("policy_sha256") or "")[:16]})
        entries.sort(key=lambda r: r["time"] or 0, reverse=True)

        def outcome(r):
            if r["allowed"]:
                return "approved" if (r["approval"] or {}).get("approved") else "allowed"
            return "held for approval" if r["effect"] == "require_approval" else "denied"

        by_rule = Counter((r["rule"], outcome(r)) for r in entries if r["rule"])
        days = 30
        start = self._now() - dt.timedelta(days=days - 1)
        daily = {(start + dt.timedelta(days=i)).isoformat(): Counter() for i in range(days)}
        for r in entries:
            if r["day"] in daily:
                daily[r["day"]][outcome(r)] += 1
        return {"chains": chains, "entries": entries[:300], "total": len(entries),
                "by_effect": dict(Counter(outcome(r) for r in entries)),
                "by_layer": dict(Counter(r["layer"] or "?" for r in entries)),
                "by_rule": [{"rule": k[0], "outcome": k[1], "n": n} for k, n in by_rule.most_common(20)],
                "by_action": [{"action": a, "n": n} for a, n in Counter(r["action"] for r in entries).most_common(20)],
                "daily": [{"day": d, **dict(c)} for d, c in daily.items()]}

    # ---------------- monitoring: drift, rates, incidents ----------------
    def monitoring(self):
        return self._cached("monitoring", [self.ws.records], self._monitoring)

    def _monitoring(self):
        from . import monitors
        if self.ws.records is None:
            return {"metrics": None, "alerts": [], "incidents": [], "window": None, "baseline": None}
        try:
            r = monitors.monitor(self.ws.records, self._now())
        except Exception as err:
            return {"metrics": None, "alerts": [{"kind": "monitor_error", "severity": "high",
                                                 "message": f"the monitor could not run: {type(err).__name__}"}],
                    "incidents": [], "window": None, "baseline": None}
        return {"metrics": r["metrics"], "alerts": r["alerts"], "window": r["window"], "baseline": r["baseline"],
                "thresholds": r["thresholds"], "incidents": monitors.incidents(self.ws.records)}

    # ---------------- evals and other sealed documents ----------------
    def evals(self):
        return self._cached("evals", [self.ws.evals], self._evals)

    def _evals(self):
        from .assess import check_seal
        out, docs = [], []
        if self.ws.evals is None:
            return {"results": [], "documents": []}
        for p in sorted(self.ws.evals.glob("*.json")):
            d = _read_json(p)
            if not isinstance(d, dict) or "sha256" not in d:
                continue
            sealed, problems = check_seal(d, self.public_key)
            if d.get("format", "").startswith("shio-eval/"):
                out.append({"file": p.name, "suite": d.get("suite"), "target": d.get("target"),
                            "generated": d.get("generated"), "cases": d.get("cases"), "passed": d.get("passed"),
                            "metrics": d.get("metrics", {}), "gates": d.get("gates", {}),
                            "gate_failures": d.get("gate_failures", []), "slices": d.get("slices", {}),
                            "failed_cases": [r for r in d.get("results", []) if not r["passed"]][:50],
                            "sealed": sealed, "seal_problems": problems, "signed": bool(d.get("signature")),
                            "subject": d.get("subject")})
            else:
                docs.append({"file": p.name, "format": d.get("format"), "sealed": sealed, "signed": bool(d.get("signature")),
                             "summary": _doc_summary(d)})
        return {"results": out, "documents": docs}

    # ---------------- packs ----------------
    def packs(self):
        from .packs import BUILTIN
        return self._cached("packs", [BUILTIN, *[Path(x) for x in self.extra_packs]], self._packs)

    def _packs(self):
        from .packs import builtin, resolve, validate
        folders = dict(builtin())
        for ref in self.extra_packs:
            p = resolve(ref)
            folders[p.name] = p
        out = []
        for pid, folder in sorted(folders.items()):
            ok, problems, pack = validate(folder)
            if pack is None:
                out.append({"id": pid, "ok": False, "problems": problems[:10]})
                continue
            out.append({"id": pack.id, "name": pack.name, "version": pack.version, "status": pack.status,
                        "licence": pack.licence, "ok": ok, "problems": problems[:10], "controls": [
                            {"id": c.id, "title": c.title, "proofs": [p.label() for p in c.proofs],
                             "refs": [f"{r.framework} {r.ref}" for r in c.refs]} for c in pack.controls],
                        "reviewed_by": [k for k, v in (pack.review or {}).items() if v]})
        return {"packs": out}

    # ---------------- cards and reviews ----------------
    def cards(self):
        return self._cached("cards", [self.ws.cards, self.ws.reviews], self._cards)

    def _cards(self):
        from .card import review_status, verify
        out = []
        if self.ws.cards is None:
            return {"cards": []}
        for p in sorted(self.ws.cards.glob("*.json")):
            c = _read_json(p)
            if not isinstance(c, dict) or c.get("format") != "shio-card/1":
                continue
            intact, problems = verify(c, self.public_key)
            reviewed, lines = review_status(c, self.ws.reviews) if self.ws.reviews else (False, ["no reviews folder"])
            out.append({"file": p.name, "name": c.get("name"), "purpose": c.get("purpose"), "owner": c.get("owner"),
                        "sha256": c.get("sha256", "")[:16], "intact": intact, "problems": problems[:5],
                        "reviewed": reviewed, "review": lines, "review_roles": c.get("review_roles", []),
                        "risk_tiers": [d.get("risk_tier") for d in c.get("deployments", [])],
                        "models": [{"name": m.get("name"), "pinned": bool(m.get("pinned"))} for m in c.get("models", [])],
                        "checks": len(c.get("checks", [])), "tools": [t.get("name") for t in c.get("tools", [])],
                        "packs": [f"{x['id']}@{x['version']}" for x in c.get("packs", [])],
                        "signoff_roles": c.get("signoff_roles", [])})
        return {"cards": out}

    # ---------------- evidence bundles ----------------
    def bundles(self):
        return self._cached("bundles", [self.ws.bundles], self._bundles)

    def _bundles(self):
        out = []
        if self.ws.bundles is None:
            return {"bundles": []}
        for d in sorted(p for p in self.ws.bundles.iterdir() if (p / "bundle.json").exists()):
            b = _read_json(d / "bundle.json") or {}
            out.append({"name": d.name, "framework": b.get("framework_name"), "period": b.get("period"),
                        "summary": b.get("summary", {}), "ledger_verified": (b.get("ledger") or {}).get("verified"),
                        "gaps": [{"id": c["id"], "title": c.get("title")} for c in b.get("controls", [])
                                 if c.get("status") in ("GAP", "MISSING", "FAILED")]})
        return {"bundles": out}

    # ---------------- the pre-model gate ----------------
    def preflight(self):
        return self._cached("preflight", [self.ws.gates, self.ws.attestations], self._preflight)

    def _preflight(self):
        from .chain import SignedChain
        from .preflight import coverage
        out = {"decisions": [], "total": 0, "by_outcome": {}, "by_control": [], "daily": [], "verified": None,
               "attestations": [], "coverage": None}
        m = coverage.matrix(today=self._now())
        out["coverage"] = {k: sum(x[k] for x in m["summary"].values()) for k in ("enforced", "measured", "attested",
                                                                                 "planned")}
        if self.ws.attestations is not None:
            from .preflight.attest import AttestationLedger
            from .preflight.gate import _spec_packs, attestation_controls
            led = AttestationLedger(self.ws.attestations)
            kinds = sorted({c.kind for c in attestation_controls(_spec_packs())} | {a.kind for a in led.all()})
            out["attestations"] = [{"kind": k, "state": st, "signed_by": a.signed_by if a else None,
                                    "expires": a.expires.isoformat() if a else None}
                                   for k, (st, a) in led.status(kinds, self._now()).items()]
            out["attestations_verified"] = led.verify(self.public_key)[0]
        if self.ws.gates is None or not (self.ws.gates / "preflight.jsonl").exists():
            return out
        chain = SignedChain(self.ws.gates, "preflight")
        ok, problems = chain.verify(self.public_key)
        es = [e for e in chain.entries() if e.get("kind") == "preflight_decision"]
        by_control = Counter()
        days = 30
        start = self._now() - dt.timedelta(days=days - 1)
        daily = {(start + dt.timedelta(days=i)).isoformat(): Counter() for i in range(days)}
        for e in es:
            day = _day(e.get("time"))
            if day in daily:
                daily[day][e["outcome"]] += 1
            for r in e.get("results", []):
                if r["outcome"] != "allow" and not r.get("advisory"):
                    by_control[(r["control"], r["outcome"])] += 1
        out.update(verified=ok, problems=problems[:10], total=len(es),
                   by_outcome=dict(Counter(e["outcome"] for e in es)),
                   by_control=[{"control": k[0], "outcome": k[1], "n": n} for k, n in by_control.most_common(25)],
                   daily=[{"day": d, **dict(c)} for d, c in daily.items()],
                   decisions=[{"time": e.get("time"), "caller": e.get("caller"), "role": e.get("role"),
                               "purpose": e.get("purpose"), "asked_for": e.get("asked_for"),
                               "destination": e.get("destination"), "outcome": e.get("outcome"),
                               "source": e.get("source"), "classes": e.get("classes", []),
                               "reasons": [r["reason"] for r in e.get("results", []) if r["outcome"] != "allow"
                                           and not r.get("advisory")][:4], "hold": e.get("hold")}
                              for e in sorted(es, key=lambda x: x.get("time") or 0, reverse=True)[:200]])
        return out

    # ---------------- AGT policies ----------------
    def policies(self):
        return self._cached("policies", [self.ws.policies], self._policies)

    def _policies(self):
        from .adapters_ext import agt
        info = {"installed": agt.installed_version(), "pinned": agt.AGT_VERSION, "policies": []}
        if self.ws.policies is None:
            return info
        for p in sorted([*self.ws.policies.glob("*.yaml"), *self.ws.policies.glob("*.yml")]):
            try:
                desc = agt.AgtBackend(str(p)).describe()
                info["policies"].append({"file": p.name, "ok": True, "sha256": desc["sha256"][:16],
                                         "policies": desc["policies"]})
            except agt.AgtUnavailable as err:
                info["policies"].append({"file": p.name, "ok": None, "problem": str(err)})
            except Exception as err:
                info["policies"].append({"file": p.name, "ok": False, "problem": str(err)[:300]})
        return info

    # ---------------- the summary: every checkpoint ----------------
    def summary(self):
        cps = []

        def cp(area, title, status, detail, tab):
            cps.append({"area": area, "title": title, "status": status, "detail": detail, "tab": tab})

        led = self._ledger()
        rows = self._decision_rows()
        decisions = [r for r in rows if r["type"] == "decision"]
        if self.ws.records is None:
            cp("Ledger", "Decision ledger intact", NONE, "no records folder in this workspace", "decisions")
        else:
            cp("Ledger", "Decision ledger intact", OK if led["verified"] else FAIL,
               f"{len(led['entries'])} entries, hash chain and signatures verified" if led["verified"] else
               "; ".join(led["problems"][:2]) or "verification failed", "decisions")
        chk = self.checks()["checks"]
        judged = sum(c["passed"] + c["failed"] for c in chk)
        failed = sum(c["failed"] for c in chk)
        worst = min((c for c in chk if c["pass_rate"] is not None), key=lambda c: c["pass_rate"], default=None)
        cp("Checks", "Checks passing", NONE if not judged else OK if failed == 0 else
           WARN if failed / judged < 0.2 else FAIL,
           f"{judged - failed} of {judged} check runs passed" + (f"; lowest: {worst['key']} "
                                                                 f"{worst['pass_rate']:.0%}" if worst else ""), "checks")
        pending = pending_signoffs(self.ws.records, led["entries"], self._now()) if self.ws.records else []
        overdue = [p for p in pending if p["age_days"] > SLA_DAYS]
        cp("People", "Sign-offs waiting", OK if not pending else FAIL if overdue else WARN,
           f"{len(pending)} waiting" + (f", {len(overdue)} longer than {SLA_DAYS} days" if overdue else ""),
           "decisions")
        rejected = sum(1 for r in decisions if r["signoff"] == "REJECTED")
        if decisions:
            cp("People", "Decisions overturned by a person", OK if not rejected else WARN,
               f"{rejected} of {len(decisions)} rejected at sign-off", "decisions")
        cards = self.cards()["cards"]
        if cards:
            unreviewed = [c["name"] for c in cards if not c["reviewed"]]
            broken = [c["name"] for c in cards if not c["intact"]]
            cp("Agents", "Agent cards intact", FAIL if broken else OK,
               f"edited: {', '.join(broken)}" if broken else f"{len(cards)} card(s), hashes match", "cards")
            cp("Agents", "Agent cards reviewed", OK if not unreviewed else WARN,
               "every card approved by its review roles" if not unreviewed else f"needs review: {', '.join(unreviewed)}",
               "cards")
            unpinned = [f"{c['name']}.{m['name']}" for c in cards for m in c["models"] if not m["pinned"]]
            cp("Agents", "Models pinned", OK if not unpinned else FAIL,
               "every model pinned" if not unpinned else f"unpinned: {', '.join(unpinned)}", "cards")
        else:
            cp("Agents", "Agent cards", NONE, "no cards in this workspace", "cards")
        packs = self.packs()["packs"]
        bad = [p["id"] for p in packs if not p["ok"]]
        cp("Packs", "Control packs valid, fixtures pass", OK if not bad else FAIL,
           f"{len(packs)} packs, {sum(len(p.get('controls', [])) for p in packs)} controls" if not bad else
           f"failing: {', '.join(bad)}", "packs")
        drafts = [p["id"] for p in packs if p.get("status") in ("draft", "research")]
        cp("Packs", "Packs reviewed by counsel / clinical lead", OK if not drafts else WARN,
           "every pack reviewed" if not drafts else f"{len(drafts)} still draft or research: no compliance claim",
           "packs")
        ev = self.evals()
        if ev["results"]:
            missed = [r["suite"] for r in ev["results"] if r["gate_failures"]]
            unsealed = [r["file"] for r in ev["results"] if not r["sealed"]]
            cp("Evals", "Eval gates met", OK if not missed else FAIL,
               f"{len(ev['results'])} suite run(s), every gate met" if not missed else f"gates missed: {', '.join(missed)}",
               "evals")
            cp("Evals", "Eval results sealed", OK if not unsealed else FAIL,
               "hashes match" if not unsealed else f"edited: {', '.join(unsealed)}", "evals")
        else:
            cp("Evals", "Eval results", NONE, "no eval results in this workspace", "evals")
        mon = self.monitoring()
        if mon["metrics"] is not None:
            high = [a for a in mon["alerts"] if a.get("severity") in ("high", "critical")]
            cp("Monitoring", "Drift and failure-rate monitors", OK if not mon["alerts"] else FAIL if high else WARN,
               "no alerts in the window" if not mon["alerts"] else "; ".join(a["message"] for a in mon["alerts"][:2]),
               "monitoring")
            open_inc = [i for i in mon["incidents"] if i["status"] != "CLOSED"]
            cp("Monitoring", "Incidents", OK if not open_inc else
               FAIL if any(i["severity"] in ("high", "critical") for i in open_inc) else WARN,
               f"{len(open_inc)} open of {len(mon['incidents'])}" if mon["incidents"] else "none recorded", "monitoring")
        g = self.gates()
        if g["chains"]:
            broken = [c["name"] for c in g["chains"] if not c["verified"]]
            cp("Gates", "Gate ledgers intact", OK if not broken else FAIL,
               f"{g['total']} tool-call decisions, chains verified" if not broken else f"broken: {', '.join(broken)}",
               "gates")
            denied = g["by_effect"].get("denied", 0) + g["by_effect"].get("held for approval", 0)
            cp("Gates", "Tool calls stopped", OK if not denied else WARN,
               f"{denied} of {g['total']} stopped or held"
               + (f"; top rule: {g['by_rule'][0]['rule']}" if g["by_rule"] else ""), "gates")
        else:
            cp("Gates", "Tool-call gates", NONE, "no gate ledgers in this workspace", "gates")
        pol = self.policies()
        if pol["policies"]:
            bad = [p["file"] for p in pol["policies"] if p["ok"] is False]
            cp("Gates", "AGT policies load (strict)", OK if not bad and pol["installed"] else
               WARN if not pol["installed"] else FAIL,
               (f"Microsoft AGT {pol['installed']}, {len(pol['policies'])} policy file(s)" if pol["installed"] else
                "AGT is not installed here (pip install \"shio-lang[agt]\")") if not bad else f"refused: {', '.join(bad)}",
               "gates")
        pf = self.preflight()
        if pf["total"]:
            cp("Pre-model gate", "Gate ledger intact", OK if pf["verified"] else FAIL,
               f"{pf['total']} model calls decided before sending" if pf["verified"] else "; ".join(pf["problems"][:2]),
               "preflight")
            stopped = sum(n for k, n in pf["by_outcome"].items() if k in ("deny", "hold"))
            cp("Pre-model gate", "Model calls denied or held", OK if not stopped else WARN,
               f"{stopped} of {pf['total']} denied or held; {pf['by_outcome'].get('redact', 0)} redacted, "
               f"{pf['by_outcome'].get('route', 0)} routed", "preflight")
        if pf["attestations"]:
            lapsed = [a["kind"] for a in pf["attestations"] if a["state"] in ("missing", "expired")]
            soon = [a["kind"] for a in pf["attestations"] if a["state"] == "expiring"]
            cp("Pre-model gate", "Attestations current", FAIL if lapsed else WARN if soon else OK,
               f"{len(lapsed)} missing or expired (the gate holds or denies health data until they are signed)"
               if lapsed else f"{len(soon)} expiring within 30 days" if soon else
               f"{len(pf['attestations'])} current", "preflight")
        cov = pf["coverage"]
        cp("Pre-model gate", "Spec coverage", WARN if cov["planned"] else OK,
           f"{cov['enforced']} enforced, {cov['measured']} measured, {cov['attested']} attested, {cov['planned']} "
           f"planned (not covered)", "preflight")
        b = self.bundles()["bundles"]
        if b:
            gaps = sum(len(x["gaps"]) for x in b)
            cp("Evidence", "Framework evidence bundles", OK if not gaps else WARN,
               f"{len(b)} bundle(s), no gaps" if not gaps else f"{gaps} control(s) with no evidence", "evidence")
        counts = Counter(c["status"] for c in cps)
        return {"generated": dt.datetime.now().isoformat(timespec="seconds"), "workspace": self.ws.describe(),
                "counts": dict(counts), "checkpoints": cps,
                "kpis": {"decisions": len(decisions), "check_runs": judged, "check_failures": failed,
                         "pending_signoffs": len(pending), "overdue_signoffs": len(overdue),
                         "gate_decisions": g["total"],
                         "gate_stopped": g["by_effect"].get("denied", 0) + g["by_effect"].get("held for approval", 0),
                         "open_incidents": sum(1 for i in mon.get("incidents", []) if i["status"] != "CLOSED"),
                         "alerts": len(mon.get("alerts", [])), "packs": len(packs),
                         "controls": sum(len(p.get("controls", [])) for p in packs), "cards": len(cards)},
                "pending": pending[:20], "daily": self.checks()["daily"]}


def _doc_summary(d):
    fmt = d.get("format", "")
    if fmt.startswith("shio-assessment"):
        return ", ".join(f"{n} {s.lower().replace('_', ' ')}" for s, n in (d.get("summary") or {}).items() if n) \
            or "assessment"
    if fmt.startswith("shio-monitoring"):
        return f"{len(d.get('alerts', []))} alert(s), window {' to '.join(d.get('window', []))}"
    if fmt.startswith("shio-safety"):
        return d.get("status", "")
    return d.get("suite") or d.get("agent") or d.get("status") or ""
