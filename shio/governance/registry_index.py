"""An open pack registry (D35): publish packs, resolve versions, install by hash.

A registry is an index file plus a folder of archives (both can be served over HTTPS as static files):

    index.json   {"format": "shio-pack-index/1", "packs": {id: {version: entry}}}
    store/       id/version/id-version.tar.gz

Publishing validates the pack (fixtures run), refuses a version already published with different content (versions
are immutable), writes a deterministic archive (sorted entries, fixed timestamps and owners, so the same pack always
gives the same bytes), and records the archive's sha256 and the pack's tree sha256 in a signed index entry.

Installing resolves a version constraint to the highest matching version, fetches the archive, checks its sha256 and
the entry's signature (with the registry's public key), extracts it refusing anything unsafe (absolute paths, "..",
links, devices), and validates the pack and its tree hash again. Any mismatch and nothing is installed.
"""
import datetime as dt
import hashlib
import io
import json
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

from ..ledger import _check_signature, sha256
from .packs import SEMVER, read, validate

FORMAT = "shio-pack-index/1"


class RegistryError(ValueError):
    pass


# ---------------- versions ----------------
def parse_version(v):
    m = SEMVER.match(v)
    if not m:
        raise RegistryError(f"{v!r} is not a semantic version")
    pre = m.group(4)
    # a release sorts after its pre-releases; pre-release parts compare numerically when numeric
    pre_key = (1,) if pre is None else (0,) + tuple((0, int(p)) if p.isdigit() else (1, p) for p in pre.split("."))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre_key)


def _constraint(text):
    """'^0.2.1', '~1.2.0', '>=0.1.0,<0.3.0', '1.2.3', '*' -> a predicate on version keys."""
    text = (text or "*").strip()
    if text in ("*", "", "latest"):
        return lambda k: k[3] == (1,)                        # releases only
    parts = [p.strip() for p in text.split(",")]
    tests = []
    for p in parts:
        m = re.match(r"^(\^|~|>=|<=|>|<|==|=)?\s*(.+)$", p)
        op, ver = m.group(1) or "==", m.group(2)
        if re.fullmatch(r"\d+(\.\d+)?", ver):          # "^0.1", "^3": shorthand for 0.1.0, 3.0.0
            ver += ".0" * (2 - ver.count("."))
        base = parse_version(ver)
        if op == "^":
            hi = (base[0] + 1, 0, 0) if base[0] else (0, base[1] + 1, 0) if base[1] else (0, 0, base[2] + 1)
            tests.append(lambda k, b=base, h=hi: b <= k and k[:3] < h)
        elif op == "~":
            tests.append(lambda k, b=base: b <= k and k[:2] == b[:2])
        else:
            cmp = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b, ">": lambda a, b: a > b,
                   "<": lambda a, b: a < b, "==": lambda a, b: a == b, "=": lambda a, b: a == b}[op]
            tests.append(lambda k, b=base, c=cmp: c(k, b))
    if not any("-" in p for p in parts):              # pre-releases match only a constraint that names one
        tests.append(lambda k: k[3] == (1,))
    return lambda k: all(t(k) for t in tests)


def best(versions, constraint):
    ok = _constraint(constraint)
    matching = [v for v in versions if ok(parse_version(v))]
    return max(matching, key=parse_version) if matching else None


# ---------------- archives ----------------
def archive(folder):
    """A deterministic tar.gz of a pack folder (no caches, no dotfiles). -> bytes."""
    import gzip
    folder = Path(folder)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for f in sorted(folder.rglob("*")):
            if not f.is_file() or "__pycache__" in f.parts or f.name.startswith("."):
                continue
            data = f.read_bytes()
            info = tarfile.TarInfo(f.relative_to(folder).as_posix())
            info.size, info.mtime, info.mode, info.uid, info.gid, info.uname, info.gname = \
                len(data), 0, 0o644, 0, 0, "", ""
            tar.addfile(info, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def safe_extract(data, target):
    """Extract a pack archive, refusing absolute paths, '..', links and special files."""
    target = Path(target).resolve()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = tar.getmembers()
        for m in members:
            p = Path(m.name)
            if p.is_absolute() or ".." in p.parts or not (m.isfile() or m.isdir()):
                raise RegistryError(f"unsafe entry in the archive: {m.name!r}")
            if not (target / p).resolve().is_relative_to(target):
                raise RegistryError(f"entry escapes the target folder: {m.name!r}")
        for m in members:
            dest = target / m.name
            if m.isdir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(tar.extractfile(m).read())


# ---------------- the index ----------------
def load_index(path):
    p = Path(path)
    if not p.exists():
        return {"format": FORMAT, "packs": {}}
    d = json.loads(p.read_text())
    if d.get("format") != FORMAT:
        raise RegistryError(f"{path}: not a pack index")
    return d


def _entry_body(e):
    return {k: v for k, v in e.items() if k not in ("signature", "key_id", "entry_sha256")}


def publish(folder, index_path, store, publisher, signer=None, base_url=None):
    """Validate and publish a pack. -> the index entry. Raises RegistryError if it doesn't validate, or if this
    version was already published with different content."""
    ok, problems, pack = validate(folder)
    if not ok:
        raise RegistryError(f"{folder} does not validate:\n  " + "\n  ".join(problems))
    index = load_index(index_path)
    existing = index["packs"].get(pack.id, {}).get(pack.version)
    if existing:
        if existing["tree_sha256"] == pack.sha256:
            return existing
        raise RegistryError(f"{pack.label()} is already published with different content: versions are immutable, "
                            f"publish a new version")
    data = archive(folder)
    rel = f"{pack.id}/{pack.version}/{pack.id}-{pack.version}.tar.gz"
    dest = Path(store) / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    entry = {"id": pack.id, "version": pack.version, "effective": pack.effective.isoformat(), "status": pack.status,
             "licence": pack.licence, "name": pack.name, "publisher": publisher,
             "published": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
             "archive": (base_url.rstrip("/") + "/" + rel) if base_url else rel,
             "archive_sha256": hashlib.sha256(data).hexdigest(), "tree_sha256": pack.sha256}
    entry["entry_sha256"] = sha256(_entry_body(entry))
    if signer is not None:
        entry.update(key_id=signer.key_id, signature=signer.sign(entry["entry_sha256"]))
    index["packs"].setdefault(pack.id, {})[pack.version] = entry
    Path(index_path).write_text(json.dumps(index, indent=1, sort_keys=True))
    return entry


def resolve(index_path, ref):
    """'med.phi@^0.1' -> the index entry of the highest matching version."""
    index = load_index(index_path)
    pid, _, constraint = ref.partition("@")
    versions = index["packs"].get(pid)
    if not versions:
        raise RegistryError(f"no pack {pid!r} in the registry")
    v = best(versions, constraint)
    if v is None:
        raise RegistryError(f"no version of {pid} matches {constraint!r} (published: {', '.join(sorted(versions))})")
    return versions[v]


def _fetch(location, index_path, opener=None):
    if re.match(r"^https://", location):
        import urllib.request
        with (opener or urllib.request.urlopen)(location, timeout=30) as resp:
            return resp.read()
    if re.match(r"^[a-z]+://", location):
        raise RegistryError(f"only https:// or a local path may serve archives, not {location!r}")
    base = Path(index_path).parent
    return (base / location).read_bytes() if not Path(location).is_absolute() else Path(location).read_bytes()


def install(index_path, ref, target, public_key=None, secret=None, store=None, opener=None):
    """Install a pack into target/<id>. -> the installed Pack. With a key, the index entry must be signed by it."""
    entry = resolve(index_path, ref)
    if sha256(_entry_body(entry)) != entry.get("entry_sha256"):
        raise RegistryError(f"index entry for {entry['id']}@{entry['version']} was edited")
    state = _check_signature({"sha256": entry["entry_sha256"], **{k: entry.get(k) for k in ("signature", "key_id")}},
                             public_key, secret)
    if state.startswith("BAD") or ((public_key is not None or secret is not None) and state != "ok"):
        raise RegistryError(f"index entry signature: {state}")
    location = entry["archive"] if store is None or entry["archive"].startswith("https://") else \
        str(Path(store) / entry["archive"])
    data = _fetch(location, index_path, opener)
    if hashlib.sha256(data).hexdigest() != entry["archive_sha256"]:
        raise RegistryError("the archive's sha256 does not match the index: not installed")
    with tempfile.TemporaryDirectory() as tmp:
        safe_extract(data, tmp)
        ok, problems, pack = validate(tmp)
        if not ok:
            raise RegistryError("the installed pack does not validate: " + "; ".join(problems[:3]))
        if pack.sha256 != entry["tree_sha256"]:
            raise RegistryError("the pack's tree hash differs from the index: not installed")
        dest = Path(target) / pack.id
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(tmp, dest)
    return read(dest)
