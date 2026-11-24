"""Agent cards (`shio registry scan`, D5) and the re-review trigger (D6).

A card says what an agent is, generated from the program itself and its agent manifest, never written by hand:

  purpose, owner, audience      from the agent manifest (the only parts a person writes)
  program                       path, sha256, regulated, the Shio version
  models                        each model a read calls, with its pinned digest (declared, or pinned per deployment)
  tools                         every declared tool: reads or acts, trusted or not, argument kinds
  sources                       what each read reads, and which earlier readings it sees
  checks                        every check and when, with reason codes and lines
  sign-off roles                every signoff, its condition and roles
  packs                         id, version, effective date and sha256 of each pack in force
  adapters and SBOM             each adapter's trust class and pin, and a CycloneDX-style bill of materials
  dependencies                  sha256 of each local Python module the program imports (trusted code)
  deployments                   risk tier, environment and regulated mode, per deployment

The card's sha256 covers all of that (not the time it was generated), so changing a tool, a check, a model pin or a
pack changes the hash. The card is signed with the ledger's key. `shio verify CARD` rejects an edited card.

The re-review trigger: the manifest names the roles that must review the agent (review.roles). A review is an
approval of one card hash in the approval log. When the card's hash changes, the old reviews no longer apply, and
`shio registry check CARD --reviews DIR` fails (exit 1) until someone in each role signs off the new hash.
"""
import datetime as dt
import json
from pathlib import Path

from .assess import Program
from .chain import APPROVED, ApprovalLog

FORMAT = "shio-card/1"
MANIFEST_FORMAT = "shio-agent/1"
RISK_TIERS = ("minimal", "limited", "high", "unacceptable")


class CardError(ValueError):
    pass


def load_manifest(path):
    path = Path(path)
    m = json.loads(path.read_text())
    if m.get("format") != MANIFEST_FORMAT:
        raise CardError(f"{path}: format must be {MANIFEST_FORMAT!r}")
    for k in ("agent", "program", "purpose", "owner", "deployments"):
        if not m.get(k):
            raise CardError(f"{path}: the agent manifest needs \"{k}\"")
    for d in m["deployments"]:
        if d.get("risk_tier") not in RISK_TIERS:
            raise CardError(f"{path}: deployment {d.get('name')!r} needs risk_tier, one of {', '.join(RISK_TIERS)}")
    m["__dir__"] = str(path.parent.resolve())
    return m


def program_path(manifest):
    p = Path(manifest["program"])
    return p if p.is_absolute() else Path(manifest.get("__dir__", ".")) / p


def _model_name(expr):
    """'gate(llm)' -> ('llm', ['gate']): a wrapper passes on the identity of the model it wraps (see assess)."""
    import ast
    try:
        node = ast.parse(expr, mode="eval").body
    except SyntaxError:
        return expr, []
    wrappers = []
    while isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords and isinstance(node.func, ast.Name):
        wrappers.append(node.func.id)
        node = node.args[0]
    return (node.id if isinstance(node, ast.Name) else expr), wrappers


def _models(program, manifest):
    declared = {m["name"]: m for m in program.meta.get("models", [])}
    pins = manifest.get("models", {})
    seen, out = set(), []
    for a in program.meta.get("agents", []):
        for r in a["reads"]:
            name, wrappers = _model_name(r["model"])
            if wrappers and name in declared:
                wrappers = []
            if name in seen:
                continue
            seen.add(name)
            if name in declared:
                expr = declared[name]["expr"]
                out.append({"name": name, "declared": expr, "simulated": expr.startswith("replay("),
                            "pinned": "digest=" in expr or "pinned=" in expr or expr.startswith("replay(")})
            else:
                pin = pins.get(name, {})
                pinned = {("model" if k == "name" else k): pin[k] for k in sorted(pin)}   # "name" is the parameter's
                out.append({**pinned, "name": name, "parameter": True, "wrapped_by": wrappers,
                            "simulated": pin.get("kind") == "replay",
                            "pinned": bool(pin.get("digest") or pin.get("pinned") or pin.get("kind") == "replay")})
    return out


def scan(manifest, signer=None, regulated_check=True):
    """Build the card for an agent manifest (a dict from load_manifest, or a path). -> (card, problems).

    problems are why the build must fail: an adapter that fails conformance (in regulated mode, an unpinned one), a
    pack that doesn't validate or whose pinned hash differs, a model parameter with no pin in a regulated program,
    and, when the manifest declares a decision-support posture, any contradiction with it (med.cds)."""
    from .. import __version__
    from .adapters import Registry
    from .packs import PackError, read, resolve, validate
    if not isinstance(manifest, dict):
        manifest = load_manifest(manifest)
    program = Program.load(program_path(manifest))
    meta, problems = program.meta, []
    regulated = bool(meta.get("regulated")) or any(d.get("regulated") for d in manifest["deployments"])

    packs = []
    for ref in manifest.get("packs", []):
        pid = ref["id"] if isinstance(ref, dict) else ref
        try:
            folder = resolve(pid if not isinstance(ref, dict) or not ref.get("version") else f"{pid}@{ref['version']}")
            ok, why, pack = validate(folder)
            if not ok:
                problems.append(f"pack {pid} does not validate: " + "; ".join(why[:3]))
                pack = read(folder)
            if isinstance(ref, dict) and ref.get("sha256") and ref["sha256"] != pack.sha256:
                problems.append(f"pack {pack.label()} has sha256 {pack.sha256[:16]}…, the manifest pins "
                                f"{ref['sha256'][:16]}…")
            packs.append(pack.stamp())
        except PackError as e:
            problems.append(str(e))

    reg = Registry.from_manifest(manifest.get("adapters"))
    ok, results = reg.check(regulated=regulated and regulated_check)
    for r in results:
        problems += [f"adapter {r.adapter}: {x.test}" + (f" ({x.detail})" if x.detail else "")
                     for x in r.results if not x.ok]

    models = _models(program, manifest)
    if regulated:
        problems += [f"model {m['name']} is not pinned for this regulated agent" for m in models if not m["pinned"]]

    deps = program.dependencies()
    local = [{"type": "file", "name": n, "hashes": [{"alg": "SHA-256", "content": h}],
              "properties": [{"name": "shio:trust", "value": "trusted local module"}]} for n, h in sorted(deps.items())]
    agents = meta.get("agents", [])
    card = {
        "format": FORMAT,
        "name": manifest["agent"],
        "purpose": manifest["purpose"],
        "owner": manifest["owner"],
        "audience": manifest.get("audience"),
        "program": {"path": manifest["program"], "sha256": program.sha256, "regulated": bool(meta.get("regulated")),
                    "shio": __version__},
        "models": models,
        "tools": [{k: t[k] for k in ("name", "mode", "output", "opens")} | {"args": [list(a) for a in t["args"]]}
                  for t in meta.get("tools", [])],
        "sources": [{"agent": a["name"], "read": r["name"], "type": r["type"], "from": r["sources"],
                     "model": r["model"], "blind": r["blind"], "seeing": r["seeing"], "line": r["line"]}
                    for a in agents for r in a["reads"]],
        "checks": [{"agent": a["name"], "name": c["name"], "kind": c["kind"], "code": c["code"], "line": c["line"]}
                   for a in agents for c in a["checks"]],
        "signoffs": [{"agent": a["name"], "label": s["label"], "when": s.get("when"), "roles": s["roles"],
                      "line": s["line"]} for a in agents for s in a["signoffs"]],
        "signoff_roles": sorted({r for a in agents for s in a["signoffs"] for r in s["roles"]}),
        "packs": packs,
        "adapters": [{"ref": type(a).ref(), "trust": a.manifest.trust.value, "version": a.manifest.version,
                      "licence": a.manifest.licence, "sha256": type(a).implementation_sha256(), "pinned": pin}
                     for a, pin in reg.entries],
        "sbom": reg.sbom(local),
        "dependencies": deps,
        "deployments": [{k: d[k] for k in sorted(d)} for d in manifest["deployments"]],
        "review_roles": (manifest.get("review") or {}).get("roles", []),
        "decision_support": manifest.get("decision_support"),
        "requires_signoff": manifest.get("requires_signoff"),
    }
    if manifest.get("decision_support"):
        from .cds import check_posture
        problems += [f"decision-support posture: {v}" for v in check_posture(card)]
    return sign(card, signer), problems


def content(card):
    """What the card's hash covers: everything but when it was generated and its own hash and signature."""
    return {k: v for k, v in card.items() if k not in ("generated", "sha256", "key_id", "signature")}


def sign(card, signer=None):
    from ..ledger import sha256
    body = content(card)
    out = {**body, "generated": card.get("generated") or dt.datetime.now(dt.timezone.utc).isoformat(
        timespec="seconds"), "sha256": sha256(body)}
    if signer is not None:
        out.update(key_id=signer.key_id, signature=signer.sign(out["sha256"]))
    return out


def verify(card, public_key=None, secret=None, program=None):
    """-> (ok, problems). The card's hash and signature; and, if the program is given (or found where the card says),
    that the program has not changed since the card was built."""
    import hashlib
    from ..ledger import _check_signature, sha256
    if card.get("format") != FORMAT:
        return False, [f"not an agent card (format {card.get('format')!r})"]
    problems = []
    if sha256(content(card)) != card.get("sha256"):
        problems.append("card edited: its content no longer matches its sha256")
    state = _check_signature(card, public_key, secret)
    if state.startswith("BAD") or ((public_key is not None or secret is not None) and state != "ok"):
        problems.append(f"card signature: {state}")
    if program is not None and Path(program).exists():
        now = hashlib.sha256(Path(program).read_text().encode()).hexdigest()
        if now != card["program"]["sha256"]:
            problems.append(f"the program has changed since the card was built (sha256 {now[:12]} now, "
                            f"{card['program']['sha256'][:12]} on the card): run shio registry scan again")
    return not problems, problems


def review(card, reviews_dir, by, role, meaning, signer=None, reject=False):
    """Record a reviewer's sign-off of this exact card hash."""
    roles = card.get("review_roles") or []
    if roles and role not in roles:
        raise CardError(f"the card asks for review by {', '.join(roles)}, not {role}")
    return ApprovalLog(reviews_dir).record("card", card["sha256"], by, role, meaning,
                                           "rejected" if reject else "approved", makers=[card.get("owner", "")],
                                           signer=signer, title=card["name"])


def review_status(card, reviews_dir):
    """-> (ok, lines). ok only when every review role has approved this card's exact hash. When it hasn't, says which
    roles are missing and, if an earlier version of the same agent was approved, that its hash changed."""
    log = ApprovalLog(reviews_dir)
    roles = card.get("review_roles") or []
    if not roles:
        return False, [f"{card['name']}: the agent manifest names no review roles (review.roles); nothing can approve "
                       f"it"]
    state, missing = log.status(card["sha256"], roles)
    lines = [f"{card['name']} card {card['sha256'][:16]}…: {state}"]
    if state == APPROVED:
        return True, lines
    if missing:
        lines.append(f"  needs sign-off by: {', '.join(missing)}")
    earlier = [e for e in log.chain.entries() if e.get("subject", {}).get("kind") == "card"
               and e["subject"].get("title") == card["name"] and e["subject"]["sha256"] != card["sha256"]
               and e["decision"] == "approved"]
    if earlier:
        lines.append(f"  the card's hash changed since its last review ({earlier[-1]['subject']['sha256'][:16]}… was "
                     f"approved by {earlier[-1]['by']}): re-review required")
    return False, lines

