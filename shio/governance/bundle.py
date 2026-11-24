"""Framework evidence bundles (`shio evidence --framework PACK`, D9).

The period evidence pack (shio.evidence) says what was decided and how it was overseen. A framework bundle adds the
mapping an auditor asks for: for each control of a framework pack, the evidence that proves it, by proof kind:

  lint      the proof's status in the signed assessment of the program (shio assess)
  runtime   the checks in the period's records that cite the control (pack@version:control), passed and failed
  eval      the eval result for the suite: its metric against the control's threshold (shio eval)
  signoff   sign-offs by the role, in the ledger (decisions) and in the approval log (cards, drafts, promotions)

A control is EVIDENCED when every one of its proofs is satisfied, GAP when one is not, and MISSING when evidence for a
proof was not supplied. The bundle never says "compliant": whether evidence meets a framework is the auditor's call.

Everything is hashed into one manifest signed with the ledger's key, and each attachment (card, assessment, eval
results) is itself signed. `shio verify BUNDLE --pubkey KEY` checks all of it offline, with only the public key.
"""
import datetime as dt
import hashlib
import json
import shutil
from collections import defaultdict
from pathlib import Path

from ..ledger import _check_signature, _entries, sha256
from .assess import check_seal
from .packs import ProofKind, read, resolve

FORMAT = "shio-bundle/1"
EVIDENCED, GAP, MISSING = "EVIDENCED", "GAP", "MISSING"
_OPS = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b, ">": lambda a, b: a > b, "<": lambda a, b: a < b}


def _runs(run):
    yield run
    for c in run.get("children", []):
        yield from _runs(c)


def _cited(folder, start, end):
    """{'pack@version:control': [(record file, check name, passed)]} for the records decided in the period."""
    folder, out = Path(folder), defaultdict(list)
    for e in _entries(folder):
        if e.get("kind") != "record" or not (folder / e["file"]).exists():
            continue
        rec = json.loads((folder / e["file"]).read_text())
        if rec.get("record_type", "decision") != "decision":
            continue
        day = dt.date.fromtimestamp(rec.get("started") or e.get("time", 0))
        if not start <= day <= end:
            continue
        for run in _runs(rec):
            for c in run.get("checks", []):
                for ctl in c.get("controls", []):
                    out[ctl].append((e["file"], c["name"], bool(c.get("passed")), bool(c.get("skipped"))))
    return out


def _signoffs(folder, approvals, start, end):
    """{role: [(where, subject, decision)]} from the ledger's sign-offs and the approval logs, in the period."""
    out = defaultdict(list)
    for e in _entries(Path(folder)) if folder else []:
        if e.get("kind") == "signoff" and start <= dt.date.fromtimestamp(e.get("time", 0)) <= end:
            out[e["role"]].append(("ledger", e["file"], e.get("decision", "approved"), "decision"))
    for folder_ in approvals or []:
        from .chain import SignedChain
        for name in sorted(Path(folder_).glob("*.jsonl")):
            for e in SignedChain(folder_, name.stem).entries():
                if e.get("kind") == "approval" and start <= dt.date.fromtimestamp(e.get("time", 0)) <= end:
                    out[e["role"]].append((name.name, f"{e['subject']['kind']} {e['subject']['sha256'][:12]}",
                                           e["decision"], e["subject"]["kind"]))
    return out


def _evidence(proof, pack, assessment, cited, evals, signoffs, own=None):
    """-> (status, evidence dict) for one proof of one control."""
    if proof.kind is ProofKind.LINT:
        if not assessment:
            return MISSING, {"proof": proof.label(), "detail": "no assessment supplied (shio assess)"}
        r = next((p for p in assessment["proofs"] if p["proof"] == proof.target), None)
        if r is None:
            return MISSING, {"proof": proof.label(), "detail": "the assessment did not run this proof"}
        ok = r["status"] in ("PROVEN", "NOT_APPLICABLE")     # nothing to prove (no acting tools) is not a gap
        return (EVIDENCED if ok else GAP), {"proof": proof.label(), "status": r["status"], "covered": r["covered"],
                                            "findings": r["findings"], "notes": r.get("notes", []),
                                            "assessment": assessment["sha256"]}
    if proof.kind is ProofKind.RUNTIME:
        src = proof.param("pack")
        keys = [k for k in cited if (k.split("@")[0] == (src or pack.id)) and k.endswith(f":{proof.param('control') or own}")]
        hits = [h for k in keys for h in cited[k]]
        if not hits:
            return MISSING, {"proof": proof.label(), "detail": "no record in the period cites this control"}
        ran = [h for h in hits if not h[3]]
        passed = sum(1 for h in ran if h[2])
        return EVIDENCED, {"proof": proof.label(), "cited_as": sorted(keys), "checks_run": len(ran),
                           "passed": passed, "failed": len(ran) - passed,
                           "records": sorted({h[0] for h in hits})[:50],
                           "detail": "the check ran and decided in every cited record (failures are the control "
                                     "working, and are listed with their records)"}
    if proof.kind is ProofKind.EVAL:
        r = next((e for e in evals if e.get("suite") == proof.target), None)
        if r is None:
            return MISSING, {"proof": proof.label(), "detail": f"no eval result for suite {proof.target}"}
        metric, thr, op = proof.param("metric"), proof.param("threshold"), proof.param("op", ">=")
        val = r.get("metrics", {}).get(metric)
        if val is None:
            return MISSING, {"proof": proof.label(), "detail": f"the eval result has no metric {metric}"}
        ok = _OPS[op](val, thr)
        return (EVIDENCED if ok else GAP), {"proof": proof.label(), "value": val, "threshold": thr, "op": op,
                                            "eval": r.get("sha256"), "cases": r.get("cases")}
    subject = proof.param("subject")          # what the sign-off must be of: a decision, a card, a monitoring report
    rows = [r for r in signoffs.get(proof.target, []) if subject is None or r[3] == subject]
    if not rows:
        return MISSING, {"proof": proof.label(), "detail": f"no sign-off by {proof.target}"
                                                           + (f" of a {subject}" if subject else "") + " in the period"}
    return EVIDENCED, {"proof": proof.label(), "signoffs": len(rows),
                       "approved": sum(1 for r in rows if r[2] == "approved"),
                       "rejected": sum(1 for r in rows if r[2] == "rejected"), "where": sorted({r[0] for r in rows})}


def build(folder, framework, out, start, end, card=None, assessment=None, evals=(), approvals=(), signer=None,
          public_key=None, secret=None, store=None):
    """Write a framework evidence bundle. -> (bundle dict, out path).

    folder: the records folder (its ledger). framework: a pack id or folder. card, assessment: paths to a signed agent
    card and assessment. evals: paths to eval results. approvals: folders holding approval logs."""
    from .. import evidence
    out = Path(out)
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"{out} exists and is not empty")
    pack = read(resolve(framework))
    data, _ = evidence.build(folder, out, start, end, store, public_key, secret, signer, write_manifest=False)
    att = out / "attachments"
    att.mkdir()
    attached, verified = {}, {}
    docs = {"card": card, "assessment": assessment}
    for kind, path in docs.items():
        if path:
            target = att / f"{kind}.json"
            shutil.copyfile(path, target)
            attached[kind] = json.loads(target.read_text())
    eval_docs = []
    for i, path in enumerate(evals):
        target = att / f"eval-{i + 1}-{Path(path).stem}.json"
        shutil.copyfile(path, target)
        eval_docs.append(json.loads(target.read_text()))
    for name, doc in [*attached.items(), *[(f"eval {d.get('suite')}", d) for d in eval_docs]]:
        ok, problems = _verify_doc(doc, public_key, secret)
        verified[name] = {"ok": ok, "problems": problems, "sha256": doc.get("sha256")}
    cited = _cited(folder, start, end)
    signoffs = _signoffs(folder, approvals, start, end)
    controls = []
    for c in pack.controls:
        items = [(*_evidence(p, pack, attached.get("assessment"), cited, eval_docs, signoffs, c.id),) for p in c.proofs]
        statuses = [s for s, _ in items]
        status = GAP if GAP in statuses else MISSING if MISSING in statuses else EVIDENCED
        controls.append({"id": c.id, "title": c.title, "requirement": c.requirement,
                         "refs": [{"framework": r.framework, "ref": r.ref} for r in c.refs],
                         "status": status, "evidence": [e for _, e in items]})
    bundle = {"format": FORMAT, "framework": pack.stamp(), "framework_name": pack.name,
              "period": [start.isoformat(), end.isoformat()], "records": str(folder),
              "ledger": {"verified": data["integrity"]["verified"], "head": data["integrity"]["head"]},
              "attachments": verified, "controls": controls,
              "summary": {s: sum(1 for c in controls if c["status"] == s) for s in (EVIDENCED, GAP, MISSING)},
              "limits": pack.limits}
    (out / "bundle.json").write_text(json.dumps(bundle, indent=1, ensure_ascii=False))
    (out / "bundle.md").write_text(markdown(bundle))
    _manifest(out, bundle, signer)
    return bundle, out


def _verify_doc(doc, public_key, secret):
    if doc.get("format") == "shio-card/1":
        from .card import verify
        return verify(doc, public_key, secret)
    return check_seal(doc, public_key, secret)


def _manifest(out, bundle, signer):
    files = {str(f.relative_to(out)): hashlib.sha256(f.read_bytes()).hexdigest()
             for f in sorted(out.rglob("*")) if f.is_file() and f.name != "manifest.json"}
    m = {"type": FORMAT, "framework": bundle["framework"], "period": bundle["period"], "head": bundle["ledger"]["head"],
         "files": files, "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    m["sha256"] = sha256(m)
    if signer:
        m.update(key_id=signer.key_id, signature=signer.sign(m["sha256"]))
    (out / "manifest.json").write_text(json.dumps(m, indent=1))
    return m


def verify(path, public_key=None, secret=None):
    """-> (ok, lines). Offline: the manifest's hash and signature, every file's hash, and every signed attachment
    (card, assessment, eval results) against the same key. With a key, everything must be signed by it."""
    path = Path(path)
    mf = path / "manifest.json"
    if not mf.exists():
        return False, [f"{path}: no manifest.json"]
    m = json.loads(mf.read_text())
    problems, lines = [], []
    body = {k: v for k, v in m.items() if k not in ("sha256", "key_id", "signature")}
    if sha256(body) != m.get("sha256"):
        problems.append("manifest.json: edited")
    state = _check_signature(m, public_key, secret) if m.get("signature") else "unsigned"
    if state.startswith("BAD") or ((public_key is not None or secret is not None) and state != "ok"):
        problems.append(f"manifest.json: {state}")
    lines.append(f"manifest signature: {state}")
    for name, h in m.get("files", {}).items():
        f = path / name
        if not f.exists():
            problems.append(f"{name}: missing")
        elif hashlib.sha256(f.read_bytes()).hexdigest() != h:
            problems.append(f"{name}: changed")
    on_disk = {str(f.relative_to(path)) for f in path.rglob("*") if f.is_file() and f.name != "manifest.json"}
    problems += [f"{x}: not in the manifest (added after the bundle was signed)" for x in sorted(on_disk - set(m["files"]))]
    for f in sorted((path / "attachments").glob("*.json")) if (path / "attachments").exists() else []:
        ok, why = _verify_doc(json.loads(f.read_text()), public_key, secret)
        lines.append(f"attachment {f.name}: {'verified' if ok else 'NOT VERIFIED'}")
        problems += [f"attachments/{f.name}: {w}" for w in why]
    if m.get("type") == FORMAT and (path / "bundle.json").exists():
        b = json.loads((path / "bundle.json").read_text())
        lines.append(f"framework {b['framework']['id']}@{b['framework']['version']}: "
                     + ", ".join(f"{n} {s.lower()}" for s, n in b["summary"].items()))
    lines += [f"  PROBLEM: {p}" for p in problems]
    return not problems, lines


def markdown(b):
    fw = b["framework"]
    lines = [f"# Evidence bundle: {b['framework_name']} ({fw['id']} v{fw['version']})", "",
             f"Period {b['period'][0]} to {b['period'][1]}. Records: `{b['records']}`. Ledger "
             f"{'VERIFIED' if b['ledger']['verified'] else 'NOT VERIFIED'}, head `{b['ledger']['head']}`.", "",
             f"Pack status: **{fw['status']}** (sha256 `{fw['sha256'][:16]}…`). This bundle maps evidence to controls; "
             f"it does not state compliance. Whether the evidence meets the framework is the auditor's judgement.", "",
             "| Control | Status | Evidence |", "|---|---|---|"]
    for c in b["controls"]:
        ev = "<br>".join(f"{e['proof']}: " + (e.get("status") or e.get("detail") or
                                               (f"{e.get('passed')}/{e.get('checks_run')} passed" if "checks_run" in e
                                                else f"{e.get('value')} vs {e.get('threshold')}" if "value" in e
                                                else f"{e.get('signoffs')} sign-offs")) for e in c["evidence"])
        refs = ", ".join(f"{r['framework']} {r['ref']}" for r in c["refs"])
        lines.append(f"| **{c['id']}** {c['title']} ({refs}) | {c['status']} | {ev} |")
    lines += ["", "## Attachments", ""]
    lines += [f"- {k}: {'verified' if v['ok'] else 'NOT VERIFIED: ' + '; '.join(v['problems'])}"
              for k, v in b["attachments"].items()] or ["- none"]
    if b.get("limits"):
        lines += ["", "## Limits of this pack", "", b["limits"]]
    lines += ["", "The period evidence report is in `evidence.md`; the figures behind it in `data.json`.", ""]
    return "\n".join(lines)
