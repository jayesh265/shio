"""The licence and dependency policy (D4), and the check CI runs against it.

Policy: MIT and Apache-2.0 only in the core; extras may also use the permissive licences the policy lists; AGPL, SSPL
and source-available licences never. Each new dependency is confirmed by counsel; until counsel has approved the
policy file itself, it says so in its status and `shio licences check` prints that on every run.

Licences are read as SPDX expressions (PEP 639 `License-Expression`, else the trove classifiers, else the free-text
`License` field), parsed by a small recursive-descent parser, and evaluated against the allow-list: `A OR B` needs
one of them allowed, `A AND B` needs both. A licence that can't be identified is a violation: the check fails closed.
"""
import json
import re
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

POLICY_FILE = Path(__file__).with_name("licence-policy.json")


class LicenceError(ValueError):
    pass


# ---------------- SPDX expressions ----------------
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+:-]+)")


@dataclass(frozen=True)
class Lic:
    id: str
    exception: str = None

    def satisfied(self, allowed):
        return self.id in allowed

    def ids(self):
        return {self.id}

    def __str__(self):
        return self.id + (f" WITH {self.exception}" if self.exception else "")


@dataclass(frozen=True)
class Any_:
    terms: tuple

    def satisfied(self, allowed):
        return any(t.satisfied(allowed) for t in self.terms)

    def ids(self):
        return set().union(*(t.ids() for t in self.terms))

    def __str__(self):
        return "(" + " OR ".join(map(str, self.terms)) + ")"


@dataclass(frozen=True)
class All_:
    terms: tuple

    def satisfied(self, allowed):
        return all(t.satisfied(allowed) for t in self.terms)

    def ids(self):
        return set().union(*(t.ids() for t in self.terms))

    def __str__(self):
        return "(" + " AND ".join(map(str, self.terms)) + ")"


def parse_spdx(text):
    """'MIT OR (Apache-2.0 AND BSD-3-Clause)' -> an expression tree. OR binds looser than AND, as SPDX says."""
    tokens, pos, text = [], 0, (text or "").strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise LicenceError(f"not an SPDX expression: {text!r} (at {text[pos:pos + 10]!r})")
        tokens.append(m.group(1))
        pos = m.end()
    if not tokens:
        raise LicenceError("empty licence expression")
    i = 0

    def peek():
        return tokens[i] if i < len(tokens) else None

    def take():
        nonlocal i
        if i >= len(tokens):
            raise LicenceError(f"licence expression ends early: {text!r}")
        i += 1
        return tokens[i - 1]

    def or_expr():
        terms = [and_expr()]
        while peek() and peek().upper() == "OR":
            take()
            terms.append(and_expr())
        return terms[0] if len(terms) == 1 else Any_(tuple(terms))

    def and_expr():
        terms = [atom()]
        while peek() and peek().upper() == "AND":
            take()
            terms.append(atom())
        return terms[0] if len(terms) == 1 else All_(tuple(terms))

    def atom():
        t = peek()
        if t is None:
            raise LicenceError(f"licence expression ends early: {text!r}")
        if t == "(":
            take()
            e = or_expr()
            if take() != ")":
                raise LicenceError(f"unbalanced parentheses in {text!r}")
            return e
        if t.upper() in ("AND", "OR", "WITH") or t == ")":
            raise LicenceError(f"unexpected {t!r} in {text!r}")
        lic = take().rstrip("+")
        if peek() and peek().upper() == "WITH":
            take()
            return Lic(lic, take())
        return Lic(lic)

    expr = or_expr()
    if i != len(tokens):
        raise LicenceError(f"unexpected {tokens[i]!r} in {text!r}")
    return expr


# ---------------- identifying a distribution's licence ----------------
CLASSIFIERS = {
    "MIT License": "MIT", "Apache Software License": "Apache-2.0", "BSD License": "BSD-3-Clause",
    "ISC License (ISCL)": "ISC", "Python Software Foundation License": "PSF-2.0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0", "GNU Affero General Public License v3": "AGPL-3.0-only",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only", "GNU Lesser General Public License v3 (LGPLv3)":
        "LGPL-3.0-only", "The Unlicense (Unlicense)": "Unlicense", "Server Side Public License (SSPL)": "SSPL-1.0",
}
FREE_TEXT = [  # (pattern over the License field, SPDX id); first match wins
    (r"^\s*mit\b", "MIT"), (r"\bmit license\b", "MIT"), (r"apache[ -]?(license)?[ ,-]*(version )?2", "Apache-2.0"),
    (r"^\s*apache\s*$", "Apache-2.0"), (r"\bbsd[- ]?3", "BSD-3-Clause"), (r"\bbsd[- ]?2", "BSD-2-Clause"),
    (r"^\s*bsd\s*$", "BSD-3-Clause"), (r"\bisc\b", "ISC"), (r"affero", "AGPL-3.0-only"),
    (r"server side public", "SSPL-1.0"), (r"business source", "BUSL-1.1"), (r"\bpsf\b|python software foundation",
                                                                            "PSF-2.0"),
]


def identify(dist):
    """-> (SPDX expression text or None, where it came from) for an installed distribution."""
    md = dist.metadata
    expr = md.get("License-Expression")
    if expr:
        return expr.strip(), "License-Expression"
    found = []
    for c in md.get_all("Classifier") or []:
        if c.startswith("License ::"):
            name = c.split("::")[-1].strip()
            if name in CLASSIFIERS:
                found.append(CLASSIFIERS[name])
    if found:
        return " OR ".join(dict.fromkeys(found)), "classifier"
    text = (md.get("License") or "").strip()
    if text:
        try:
            parse_spdx(text)
            if len(text) < 60 and " " not in text.replace(" OR ", "").replace(" AND ", "").strip():
                return text, "License"
        except LicenceError:
            pass
        low = text.lower()
        for pat, spdx in FREE_TEXT:
            if re.search(pat, low):
                return spdx, "License (free text)"
    return None, "not stated"


def _canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements(dist, extras=()):
    """The distributions `dist` requires, with the given extras, as canonical names."""
    out = []
    for req in dist.requires or []:
        name = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", req)
        if not name:
            continue
        marker = req.split(";", 1)[1] if ";" in req else ""
        wanted = re.findall(r"extra\s*==\s*['\"]([^'\"]+)['\"]", marker)
        if wanted and not set(map(_canonical, wanted)) & set(map(_canonical, extras)):
            continue
        out.append(_canonical(name.group(1)))
    return out


def closure(root="shio-lang", extras=()):
    """{distribution name: (Distribution or None, path from the root)}: everything the root needs, breadth first, so
    each dependency is reported with the shortest chain that pulls it in."""
    from collections import deque
    seen, queue = {}, deque([(_canonical(root), (), tuple(extras))])
    while queue:
        name, path, ex = queue.popleft()
        if name in seen:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            seen[name] = (None, path)
            continue
        seen[name] = (dist, path)
        for dep in _requirements(dist, ex):
            if dep not in seen:
                queue.append((dep, path + (name,), ()))
    return seen


# ---------------- the policy ----------------
@dataclass
class Policy:
    version: str
    status: str
    approved_by: object
    core_allow: frozenset
    extras_allow: frozenset
    deny: frozenset
    exceptions: list = field(default_factory=list)

    @classmethod
    def load(cls, path=None):
        d = json.loads(Path(path or POLICY_FILE).read_text())
        return cls(d["version"], d["status"], d.get("approved_by"), frozenset(d["core"]["allow"]),
                   frozenset(d["core"]["allow"]) | frozenset(d["extras"]["allow"]), frozenset(d["deny"]),
                   d.get("exceptions", []))

    @property
    def approved(self):
        return bool(self.approved_by)

    def exception_for(self, package, scope):
        for e in self.exceptions:
            if _canonical(e["package"]) == _canonical(package) and e.get("scope", "core") in (scope, "any"):
                return e
        return None

    def judge(self, package, expression, scope="core"):
        """-> (ok, why, exception or None) for one dependency's licence expression in the core or an extra."""
        if not expression:
            exc = self.exception_for(package, scope)
            if exc:
                return True, f"licence not stated; allowed by exception ({exc.get('status')})", exc
            return False, "licence could not be identified (fails closed)", None
        try:
            expr = parse_spdx(expression)
        except LicenceError as e:
            return False, str(e), None
        if expr.ids() <= self.deny or (isinstance(expr, (Lic, All_)) and expr.ids() & self.deny):
            return False, f"{expression}: denied by policy", None
        allowed = (self.core_allow if scope == "core" else self.extras_allow) - self.deny
        if expr.satisfied(allowed):
            return True, f"{expression}: allowed", None
        exc = self.exception_for(package, scope)
        if exc and expr.satisfied(allowed | {exc["licence"]}):
            return True, f"{expression}: allowed by exception ({exc.get('status')}: {exc.get('reason')})", exc
        return False, f"{expression}: not on the {scope} allow-list ({', '.join(sorted(allowed))})", None


@dataclass
class Finding:
    package: str
    version: str
    expression: str
    source: str
    scope: str
    ok: bool
    why: str
    via: tuple
    exception: dict = None


def check(policy=None, root="shio-lang", extras=(), strict=False):
    """-> (ok, findings, notes). The core is the root's closure without extras; each extra adds its own closure,
    judged against the extras allow-list. strict: an exception counsel hasn't approved yet is a failure."""
    policy = policy or Policy.load()
    core = closure(root)
    findings = []
    for name, (dist, via) in sorted(core.items()):
        findings.append(_finding(policy, name, dist, via, "core"))
    for extra in extras:
        for name, (dist, via) in sorted(closure(root, (extra,)).items()):
            if name not in core:
                findings.append(_finding(policy, name, dist, via, f"extra:{extra}"))
    notes = []
    if not policy.approved:
        notes.append(f"licence policy v{policy.version} is {policy.status}: counsel has not approved it yet")
    ok = True
    for f in findings:
        if not f.ok:
            ok = False
        elif f.exception and "approved" not in str(f.exception.get("status", "")).lower():
            notes.append(f"{f.package}: allowed only by an exception counsel has not approved "
                         f"({f.exception.get('reason')})")
            if strict:
                ok = False
    return ok, findings, notes


def _finding(policy, name, dist, via, scope):
    if dist is None:
        return Finding(name, "-", None, "not installed", scope, True, "not installed here (not checked)", via)
    expr, source = identify(dist)
    ok, why, exc = policy.judge(name, expr, "core" if scope == "core" else "extra")
    return Finding(name, dist.version, expr, source, scope, ok, why, via, exc)


def check_manifest_licence(expression, scope="extra", package="(adapter)", policy=None):
    """For adapter manifests and packs: is this declared licence allowed? -> (ok, why)."""
    ok, why, _ = (policy or Policy.load()).judge(package, expression, scope)
    return ok, why
