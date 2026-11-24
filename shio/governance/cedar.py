"""Policy-engine interop (D31): Cedar policies imported, enforced and exported; OPA/Rego exported and queried.

Cedar (https://www.cedarpolicy.com) is parsed here by a small recursive-descent parser covering the subset agents need:

    @id("no-large-refunds")
    forbid (principal, action == Action::"refund", resource)
    when { context.amount > 500 }
    unless { principal in Role::"finance" };

    permit (principal in Role::"support", action in [Action::"refund", Action::"lookup"], resource);

  scope       principal / action / resource, each unconstrained, `== Entity`, or `in Entity` (action: `in [...]`)
  conditions  when / unless blocks: || && ! == != < <= > >= in has like, attribute access (a.b, a["b"]),
              literals (integers, strings, true, false), sets [...], entity references Type::"id"

Semantics, as Cedar's: a request is allowed when at least one permit applies and no forbid applies (forbid wins;
nothing applies: denied). A policy whose condition errors (a missing attribute, a type mismatch) is skipped, and the
error is reported. `in` follows entity parents transitively (breadth-first, so cycles can't loop).

CedarGate enforces a policy set on any agent's tool calls, Shio or not: wrap each tool, and a call the policies don't
allow raises PermissionError before the tool runs. CedarCheck is the same decision as a check adapter. to_cedar()
writes policies back out; to_rego() writes them as an OPA Rego module; OpaBackend asks a running OPA server.

The Microsoft Agent Governance Toolkit is a third PolicyBackend: shio.governance.adapters_ext.agt (shio-lang[agt]).

Not built: importing Rego (Rego is a full language; translate by hand, or query OPA with OpaBackend).
"""
import abc
import fnmatch
import json
import re
from collections import deque
from dataclasses import dataclass, field

from .adapters import CheckAdapter, Manifest, TrustClass


class CedarError(ValueError):
    pass


# ---------------- tokens ----------------
TOKEN = re.compile(r"""\s*(?:
    (?P<comment>//[^\n]*)
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<int>-?\d+)
  | (?P<op>==|!=|<=|>=|&&|\|\||::|[(){}\[\],;.<>!@])
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
)""", re.X)


def tokenize(text):
    out, pos = [], 0
    while pos < len(text):
        if text[pos:].strip() == "":
            break
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise CedarError(f"unexpected character at {pos}: {text[pos:pos + 15]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind == "comment":
            continue
        val = m.group(kind)
        out.append((kind, json.loads(val) if kind == "string" else int(val) if kind == "int" else val))
    return out


# ---------------- AST ----------------
@dataclass(frozen=True)
class Entity:
    type: str
    id: str

    def __str__(self):
        return f'{self.type}::{json.dumps(self.id)}'


@dataclass
class Policy:
    id: str
    effect: str                          # permit | forbid
    principal: tuple = (None, None)      # (op, Entity) ; op in None, "==", "in"
    action: tuple = (None, None)         # (op, Entity | [Entity])
    resource: tuple = (None, None)
    conditions: list = field(default_factory=list)   # [("when"|"unless", expr)]
    annotations: dict = field(default_factory=dict)


class Parser:
    def __init__(self, text):
        self.toks, self.i = tokenize(text), 0

    def peek(self, k=0):
        return self.toks[self.i + k] if self.i + k < len(self.toks) else (None, None)

    def take(self, value=None, kind=None):
        tk, tv = self.peek()
        if (value is not None and tv != value) or (kind is not None and tk != kind):
            raise CedarError(f"expected {value or kind}, found {tv!r} (token {self.i})")
        self.i += 1
        return tv

    def at(self, value):
        return self.peek()[1] == value and self.peek()[0] in ("op", "ident")

    def policies(self):
        out = []
        while self.peek()[0] is not None:
            out.append(self.policy(len(out)))
        return out

    def policy(self, n):
        ann = {}
        while self.at("@"):
            self.take("@")
            key = self.take(kind="ident")
            self.take("(")
            ann[key] = self.take(kind="string")
            self.take(")")
        effect = self.take(kind="ident")
        if effect not in ("permit", "forbid"):
            raise CedarError(f"a policy starts with permit or forbid, not {effect!r}")
        self.take("(")
        p = Policy(ann.get("id", f"policy{n}"), effect, annotations=ann)
        p.principal = self.scope("principal")
        self.take(",")
        p.action = self.scope("action")
        self.take(",")
        p.resource = self.scope("resource")
        self.take(")")
        while self.at("when") or self.at("unless"):
            kind = self.take()
            self.take("{")
            p.conditions.append((kind, self.expr()))
            self.take("}")
        self.take(";")
        return p

    def scope(self, var):
        self.take(var)
        if self.at("=="):
            self.take("==")
            return ("==", self.entity())
        if self.at("in"):
            self.take("in")
            if self.at("["):
                return ("in", self.list_of(self.entity))
            return ("in", self.entity())
        return (None, None)

    def list_of(self, item):
        self.take("[")
        out = []
        while not self.at("]"):
            out.append(item())
            if not self.at("]"):
                self.take(",")
        self.take("]")
        return out

    def entity(self):
        path = [self.take(kind="ident")]
        while self.at("::") and self.peek(1)[0] == "ident":
            self.take("::")
            path.append(self.take(kind="ident"))
        self.take("::")
        return Entity("::".join(path), self.take(kind="string"))

    # expressions: or > and > unary > comparison > member/primary
    def expr(self):
        left = self.and_()
        while self.at("||"):
            self.take()
            left = ("||", left, self.and_())
        return left

    def and_(self):
        left = self.unary()
        while self.at("&&"):
            self.take()
            left = ("&&", left, self.unary())
        return left

    def unary(self):
        if self.at("!"):
            self.take()
            return ("!", self.unary())
        return self.comparison()

    def comparison(self):
        left = self.member()
        for op in ("==", "!=", "<=", ">=", "<", ">", "in", "has", "like"):
            if self.at(op):
                self.take()
                if op == "has":
                    return ("has", left, self.take(kind="ident") if self.peek()[0] == "ident" else self.take(kind="string"))
                return (op, left, self.member())
        return left

    def member(self):
        node = self.primary()
        while self.at(".") or self.at("["):
            if self.at("."):
                self.take(".")
                node = ("attr", node, self.take(kind="ident"))
            else:
                self.take("[")
                key = self.take(kind="string")
                self.take("]")
                node = ("attr", node, key)
        return node

    def primary(self):
        tk, tv = self.peek()
        if tk == "int" or tk == "string":
            self.i += 1
            return ("lit", tv)
        if tv in ("true", "false") and tk == "ident":
            self.i += 1
            return ("lit", tv == "true")
        if tv == "(":
            self.take("(")
            e = self.expr()
            self.take(")")
            return e
        if tv == "[":
            return ("set", self.list_of(self.expr))
        if tv in ("principal", "action", "resource", "context") and tk == "ident":
            self.i += 1
            return ("var", tv)
        if tk == "ident" and self.peek(1)[1] == "::":
            return ("lit", self.entity())
        raise CedarError(f"unexpected {tv!r} in a condition")


def parse(text):
    return Parser(text).policies()


# ---------------- evaluation ----------------
class EvalError(Exception):
    pass


@dataclass
class Decision:
    allowed: bool
    permits: list
    forbids: list
    errors: list

    @property
    def reasons(self):
        return self.forbids if self.forbids else self.permits


class Entities:
    """{Entity: {"attrs": {...}, "parents": [Entity]}}, with transitive `in`."""

    def __init__(self, data=None):
        self.data = {}
        for uid, v in (data or {}).items():
            self.data[uid if isinstance(uid, Entity) else _entity(uid)] = {
                "attrs": v.get("attrs", {}), "parents": [p if isinstance(p, Entity) else _entity(p)
                                                         for p in v.get("parents", [])]}

    def is_in(self, child, ancestor):
        if child == ancestor:
            return True
        seen, queue = set(), deque([child])
        while queue:
            n = queue.popleft()
            if n in seen:
                continue
            seen.add(n)
            for p in self.data.get(n, {}).get("parents", []):
                if p == ancestor:
                    return True
                queue.append(p)
        return False

    def attrs(self, uid):
        return self.data.get(uid, {}).get("attrs", {})


def _entity(x):
    if isinstance(x, Entity):
        return x
    if isinstance(x, dict) and "type" in x:
        return Entity(x["type"], x["id"])
    m = re.match(r'^(.+)::"(.*)"$', str(x))
    if not m:
        raise CedarError(f"not an entity reference: {x!r}")
    return Entity(m.group(1), m.group(2))


def _scope_ok(scope, value, entities):
    op, target = scope
    if op is None:
        return True
    if op == "==":
        return value == target
    targets = target if isinstance(target, list) else [target]
    return any(entities.is_in(value, t) for t in targets)


def _eval(node, env, entities):
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "var":
        return env[node[1]]
    if kind == "set":
        return [_eval(x, env, entities) for x in node[1]]
    if kind == "attr":
        obj = _eval(node[1], env, entities)
        attrs = entities.attrs(obj) if isinstance(obj, Entity) else obj
        if not isinstance(attrs, dict) or node[2] not in attrs:
            raise EvalError(f"no attribute {node[2]!r}")
        return attrs[node[2]]
    if kind == "!":
        v = _eval(node[1], env, entities)
        if not isinstance(v, bool):
            raise EvalError("! needs a boolean")
        return not v
    if kind in ("&&", "||"):
        a = _eval(node[1], env, entities)
        if not isinstance(a, bool):
            raise EvalError(f"{kind} needs booleans")
        if (kind == "&&" and not a) or (kind == "||" and a):
            return a                                   # short-circuit, as Cedar does
        b = _eval(node[2], env, entities)
        if not isinstance(b, bool):
            raise EvalError(f"{kind} needs booleans")
        return b
    if kind == "has":
        obj = _eval(node[1], env, entities)
        attrs = entities.attrs(obj) if isinstance(obj, Entity) else obj
        return isinstance(attrs, dict) and node[2] in attrs
    a, b = _eval(node[1], env, entities), _eval(node[2], env, entities)
    if kind == "==":
        return a == b
    if kind == "!=":
        return a != b
    if kind == "in":
        if isinstance(b, list):
            return any(entities.is_in(a, x) if isinstance(a, Entity) else a == x for x in b)
        if isinstance(a, Entity) and isinstance(b, Entity):
            return entities.is_in(a, b)
        raise EvalError("in needs entities or a set")
    if kind == "like":
        if not isinstance(a, str) or not isinstance(b, str):
            raise EvalError("like needs strings")
        return fnmatch.fnmatchcase(a, b)
    if not (isinstance(a, int) and isinstance(b, int)) or isinstance(a, bool) or isinstance(b, bool):
        raise EvalError(f"{kind} needs integers")
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[kind]


def authorize(policies, principal, action, resource, context=None, entities=None):
    """-> Decision. principal, action, resource: Entity or 'Type::"id"'."""
    entities = entities if isinstance(entities, Entities) else Entities(entities)
    env = {"principal": _entity(principal), "action": _entity(action), "resource": _entity(resource),
           "context": context or {}}
    permits, forbids, errors = [], [], []
    for p in policies:
        if not (_scope_ok(p.principal, env["principal"], entities) and _scope_ok(p.action, env["action"], entities)
                and _scope_ok(p.resource, env["resource"], entities)):
            continue
        try:
            applies = all((_eval(e, env, entities) is True) == (k == "when") for k, e in p.conditions)
        except (EvalError, KeyError) as err:
            errors.append(f"{p.id}: {err}")
            continue
        if applies:
            (permits if p.effect == "permit" else forbids).append(p.id)
    return Decision(bool(permits) and not forbids, permits, forbids, errors)


# ---------------- enforcing on any agent ----------------
class CedarGate:
    """Enforce Cedar policies on tool calls. `gate.wrap(fn, action="refund")` returns a function that asks the
    policies first: context is the call's keyword arguments, the principal is `gate.principal` (set per task), and
    the resource is resource(kwargs) if given, else Tool::"<action>". Every decision is kept in gate.log."""

    def __init__(self, policies, entities=None, principal='User::"anonymous"'):
        self.policies = parse(policies) if isinstance(policies, str) else list(policies)
        self.entities = entities if isinstance(entities, Entities) else Entities(entities)
        self.principal = principal
        self.log = []

    def decide(self, action, context, resource=None):
        d = authorize(self.policies, self.principal, f'Action::{json.dumps(action)}',
                      resource or f'Tool::{json.dumps(action)}', context, self.entities)
        self.log.append({"principal": str(self.principal), "action": action, "allowed": d.allowed,
                         "permits": d.permits, "forbids": d.forbids, "errors": d.errors})
        return d

    def wrap(self, fn, action=None, resource=None):
        name = action or fn.__name__

        def gated(*args, **kwargs):
            d = self.decide(name, _context(kwargs), resource(kwargs) if resource else None)
            if not d.allowed:
                why = f"forbidden by {', '.join(d.forbids)}" if d.forbids else "no policy permits it"
                raise PermissionError(f"{name}: {why}")
            return fn(*args, **kwargs)
        gated.__name__, gated.__doc__ = getattr(fn, "__name__", name), fn.__doc__
        return gated


def _context(kwargs):
    """Cedar has integers, strings, booleans, sets and records: floats become integers (amounts in whole units)."""
    def conv(v):
        if isinstance(v, bool) or isinstance(v, (int, str)) or v is None:
            return v
        if isinstance(v, float):
            return int(v)
        if isinstance(v, dict):
            return {k: conv(x) for k, x in v.items()}
        if isinstance(v, (list, tuple, set)):
            return [conv(x) for x in v]
        return str(v)
    return {k: conv(v) for k, v in kwargs.items()}


class CedarCheck(CheckAdapter):
    """The Cedar decision as a check adapter: decide(action, context) -> allowed. Deterministic and pinned."""
    manifest = Manifest("cedar-policy-check", "0.1.0", TrustClass.CHECK, "MIT OR Apache-2.0",
                        "Cedar policies evaluated by Shio's built-in Cedar subset", reviewed_by="shio maintainers")
    fixtures = ((("refund", {"amount": 100}), True), (("refund", {"amount": 900}), False),
                (("delete_account", {}), False))
    DEMO = ('@id("refunds") permit (principal, action == Action::"refund", resource);\n'
            '@id("large-refunds") forbid (principal, action == Action::"refund", resource) when { context.amount > 500 };')

    def __init__(self, policies=None, entities=None, principal='User::"agent"'):
        self.gate = CedarGate(policies or self.DEMO, entities, principal)

    def decide(self, action, context):
        d = authorize(self.gate.policies, self.gate.principal, f'Action::{json.dumps(action)}',
                      f'Tool::{json.dumps(action)}', context, self.gate.entities)
        return (d.allowed, f"permitted by {', '.join(d.permits)}" if d.allowed else
                f"forbidden by {', '.join(d.forbids)}" if d.forbids else "no policy permits it")


# ---------------- export ----------------
def _expr_text(node):
    kind = node[0]
    if kind == "lit":
        v = node[1]
        return "true" if v is True else "false" if v is False else json.dumps(v) if isinstance(v, str) else str(v)
    if kind == "var":
        return node[1]
    if kind == "set":
        return "[" + ", ".join(_expr_text(x) for x in node[1]) + "]"
    if kind == "attr":
        return f"{_expr_text(node[1])}.{node[2]}" if re.match(r"^[A-Za-z_]\w*$", node[2]) else \
            f'{_expr_text(node[1])}[{json.dumps(node[2])}]'
    if kind == "!":
        return f"!({_expr_text(node[1])})"
    if kind == "has":
        return f"{_expr_text(node[1])} has {node[2]}"
    return f"({_expr_text(node[1])} {kind} {_expr_text(node[2])})"


def _scope_text(var, scope):
    op, t = scope
    if op is None:
        return var
    if isinstance(t, list):
        return f"{var} in [{', '.join(map(str, t))}]"
    return f"{var} {op} {t}"


def to_cedar(policies):
    out = []
    for p in policies:
        ann = "".join(f'@{k}({json.dumps(v)})\n' for k, v in p.annotations.items())
        body = f"{p.effect} ({_scope_text('principal', p.principal)}, {_scope_text('action', p.action)}, " \
               f"{_scope_text('resource', p.resource)})"
        conds = "".join(f"\n{k} {{ {_expr_text(e)} }}" for k, e in p.conditions)
        out.append(f"{ann}{body}{conds};")
    return "\n\n".join(out) + "\n"


def _rego_expr(node):
    kind = node[0]
    if kind == "lit":
        v = node[1]
        if isinstance(v, Entity):
            return json.dumps(str(v))
        return "true" if v is True else "false" if v is False else json.dumps(v)
    if kind == "var":
        return f"input.{node[1]}"
    if kind == "attr":
        return f"{_rego_expr(node[1])}[{json.dumps(node[2])}]"
    if kind == "set":
        return "[" + ", ".join(_rego_expr(x) for x in node[1]) + "]"
    if kind == "!":
        return f"not {_rego_expr(node[1])}"
    if kind == "has":
        return f"{_rego_expr(node[1])}[{json.dumps(node[2])}]"
    if kind == "&&":
        return f"{_rego_expr(node[1])}\n    {_rego_expr(node[2])}"
    if kind == "||":
        raise CedarError("|| has no single-rule form in Rego; split the policy in two before exporting")
    if kind == "in":
        return f"{_rego_expr(node[1])} in {_rego_expr(node[2])}"
    op = {"==": "==", "!=": "!=", "<": "<", "<=": "<=", ">": ">", ">=": ">="}.get(kind)
    if op is None:
        raise CedarError(f"{kind} has no Rego export here")
    return f"{_rego_expr(node[1])} {op} {_rego_expr(node[2])}"


def to_rego(policies, package="shio.authz"):
    """A Rego module with Cedar's semantics: allow if some permit applies and no forbid does. Entities are strings
    ('Action::"refund"'); entity hierarchy (`in` over parents) is not exported and must be supplied as data."""
    lines = [f"package {package}", "", "import rego.v1", "", "default allow := false", "",
             "allow if {", "    some_permit", "    not some_forbid", "}", ""]
    for p in policies:
        head = "some_permit" if p.effect == "permit" else "some_forbid"
        body = []
        for var in ("principal", "action", "resource"):
            op, t = getattr(p, var)
            if op == "==":
                body.append(f"input.{var} == {json.dumps(str(t))}")
            elif op == "in":
                ts = t if isinstance(t, list) else [t]
                body.append(f"input.{var} in {json.dumps([str(x) for x in ts])}")
        for k, e in p.conditions:
            text = _rego_expr(e)
            body.append(text if k == "when" else f"not ({text})" if "\n" not in text else None)
            if body[-1] is None:
                raise CedarError(f"{p.id}: an unless block with several conditions has no single Rego form")
        lines += [f"# {p.id}", f"{head} if {{"] + [f"    {b}" for b in body or ["true"]] + ["}", ""]
    return "\n".join(lines)


# ---------------- external policy engines ----------------
class PolicyBackend(abc.ABC):
    """An external policy decision point. A deterministic engine is a check (trust class check): pinned, reviewed."""

    @abc.abstractmethod
    def allowed(self, principal, action, resource, context):
        ...


class CedarBackend(PolicyBackend):
    def __init__(self, policies, entities=None):
        self.policies = parse(policies) if isinstance(policies, str) else policies
        self.entities = Entities(entities)

    def allowed(self, principal, action, resource, context):
        return authorize(self.policies, principal, action, resource, context, self.entities).allowed


class OpaBackend(PolicyBackend):
    """Ask a running OPA server: POST {url}/v1/data/{path} with {"input": ...}; allowed when result is true."""

    def __init__(self, url, path="shio/authz/allow", timeout=5, opener=None):
        if not url.startswith(("http://", "https://")):
            raise ValueError("OPA url must be http:// or https://")
        self.url, self.path, self.timeout = url.rstrip("/"), path.strip("/"), timeout
        self.opener = opener

    def allowed(self, principal, action, resource, context):
        import urllib.request
        body = json.dumps({"input": {"principal": str(principal), "action": str(action), "resource": str(resource),
                                     "context": context}}).encode()
        req = urllib.request.Request(f"{self.url}/v1/data/{self.path}", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        with (self.opener or urllib.request.urlopen)(req, timeout=self.timeout) as resp:
            return json.loads(resp.read()).get("result") is True        # anything but true is a denial
