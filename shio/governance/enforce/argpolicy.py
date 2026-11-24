"""CORE-2: argument-level policies for tool calls: ranges, allow-lists, patterns and relationships.

    policy = ArgPolicy.from_dict({"format": "shio-argpolicy/1", "tools": {"pay_invoice": {
        "on_fail": "hold",
        "args": {"amount": {"type": "number", "min": 0, "max": 5000, "le": "$ctx.invoice.total"},
                 "recipient": {"allow": ["acme-supplies", "northwind-traders"]},
                 "currency": {"allow": ["USD", "EUR"]}, "memo": {"pattern": "^[A-Za-z0-9 .,-]{0,80}$"}}}}})
    policy.check("pay_invoice", {"amount": 900, "recipient": "acme-supplies"}, ctx={"invoice": {"total": 450}})

A relationship compares an argument with another argument ($args.name) or with a fact the caller trusts ($ctx.path):
the invoice total read from the system of record, not from the model. Comparisons: lt, le, gt, ge, eq, ne, in.

The plan may narrow, a person widens. `policy.narrow(tool, constraints)` returns a policy for one task that is at most
as permissive as the standing one: a lower max, fewer allowed values. Anything the plan tries to widen (a higher max,
a new recipient) is not applied; calls that need the wider value are held for a person instead.

Values are normalised before they are judged, and refused when they can't be read unambiguously, because an
attacker controls them: numbers must be real numbers or plain decimal strings ("1e3", "1,000", "٥٠٠", "NaN", true
are not numbers), strings are NFKC-normalised with zero-width and control characters removed before allow-lists and
patterns, and patterns must match the whole value. A missing argument a rule constrains is a violation. A tool the
policy doesn't list is refused unless the policy says `default: "allow"`.
"""
import dataclasses
import json
import math
import re
import unicodedata
from decimal import Decimal, InvalidOperation
from pathlib import Path

FORMAT = "shio-argpolicy/1"
OUTCOMES = ("allow", "hold", "deny")
RANK = {"allow": 0, "hold": 1, "deny": 2}
CMP = {"lt": lambda a, b: a < b, "le": lambda a, b: a <= b, "gt": lambda a, b: a > b, "ge": lambda a, b: a >= b,
       "eq": lambda a, b: a == b, "ne": lambda a, b: a != b, "in": lambda a, b: a in b}
NUMBER = re.compile(r"^-?(0|[1-9]\d*)(\.\d+)?$")
INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁤﻿­]")


class PolicyError(ValueError):
    pass


class Unreadable(ValueError):
    pass


def number(v):
    """A value as a Decimal, or Unreadable. Strict: no exponents, separators, non-ASCII digits, NaN, inf or bools."""
    if isinstance(v, bool) or v is None:
        raise Unreadable(f"{v!r} is not a number")
    if isinstance(v, int):
        return Decimal(v)
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            raise Unreadable(f"{v!r} is not a finite number")
        return Decimal(repr(v))
    if isinstance(v, Decimal):
        if not v.is_finite():
            raise Unreadable(f"{v!r} is not a finite number")
        return v
    if isinstance(v, str):
        s = v.strip()
        if not NUMBER.match(s) or not s.isascii():
            raise Unreadable(f"{v!r} is not a plain decimal number")
        try:
            return Decimal(s)
        except InvalidOperation:
            raise Unreadable(f"{v!r} is not a number") from None
    raise Unreadable(f"{type(v).__name__} is not a number")


def strict_text(v):
    """Text for an allow-list or pattern: refused when normalising would change it. A value that only matches after
    invisible characters are removed or look-alike forms are folded is not the value the tool would receive."""
    t = text(v)
    if t != str(v).strip():
        raise Unreadable(f"{v!r} contains invisible, control or look-alike characters")
    return t


def text(v):
    """A value as normalised text: NFKC, invisible and control characters removed, surrounding space trimmed."""
    if not isinstance(v, (str, int)) or isinstance(v, bool):
        raise Unreadable(f"{type(v).__name__} is not text")
    s = unicodedata.normalize("NFKC", str(v))
    s = INVISIBLE.sub("", s)
    s = "".join(ch for ch in s if unicodedata.category(ch)[0] != "C" or ch in "\t")
    return s.strip()


@dataclasses.dataclass(frozen=True)
class Rule:
    arg: str
    kind: str                 # type | min | max | allow | pattern | relation | required
    value: object
    on_fail: str

    def describe(self):
        return f"{self.arg} {self.kind} {self.value}"


@dataclasses.dataclass(frozen=True)
class Violation:
    arg: str
    rule: str
    detail: str
    outcome: str


@dataclasses.dataclass(frozen=True)
class ArgDecision:
    tool: str
    outcome: str
    violations: tuple = ()
    widened: tuple = ()

    @property
    def allowed(self):
        return self.outcome == "allow"

    def explain(self):
        if self.allowed:
            return f"{self.tool}: every argument within policy"
        return f"{self.tool}: {self.outcome}: " + "; ".join(f"{v.arg} {v.detail}" for v in self.violations)


def _resolve(ref, args, ctx):
    """$args.x or $ctx.a.b -> value; anything else is a literal."""
    if not (isinstance(ref, str) and ref.startswith("$")):
        return ref
    root, _, path = ref[1:].partition(".")
    cur = {"args": args, "ctx": ctx}.get(root)
    if cur is None:
        raise PolicyError(f"reference {ref!r} must start with $args. or $ctx.")
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise Unreadable(f"{ref} is not available")
        cur = cur[part]
    return cur


class ToolPolicy:
    def __init__(self, tool, spec):
        self.tool, self.spec = tool, json.loads(json.dumps(spec))
        self.on_fail = spec.get("on_fail", "deny")
        if self.on_fail not in OUTCOMES:
            raise PolicyError(f"{tool}: on_fail must be one of {', '.join(OUTCOMES)}")
        self.rules = []
        for arg, cons in spec.get("args", {}).items():
            of = cons.get("on_fail", self.on_fail)
            for kind, val in cons.items():
                if kind == "on_fail":
                    continue
                if kind not in ("type", "min", "max", "allow", "pattern", "required", *CMP):
                    raise PolicyError(f"{tool}.{arg}: unknown constraint {kind!r}")
                if kind == "pattern":
                    try:
                        re.compile(val)
                    except re.error as e:
                        raise PolicyError(f"{tool}.{arg}: pattern does not compile ({e})") from None
                if kind == "type" and val not in ("number", "integer", "text", "boolean"):
                    raise PolicyError(f"{tool}.{arg}: type must be number, integer, text or boolean")
                self.rules.append(Rule(arg, kind, val, of))

    def check(self, args, ctx):
        out, done = [], set()
        for r in self.rules:
            if r.arg in done:
                continue                              # one unreadable or missing report per argument
            try:
                bad = self._broken(r, args, ctx)
                outcome = r.on_fail
            except Unreadable as e:
                bad, outcome = f"can't be read unambiguously: {e}", "deny"
            if bad:
                out.append(Violation(r.arg, r.describe(), bad, outcome))
                if bad == "is missing" or outcome == "deny" and "unambiguously" in bad:
                    done.add(r.arg)
        return out

    def _broken(self, r, args, ctx):
        if r.arg not in args:
            # an argument with a range, type, allow-list or relation must be there; a pattern alone is optional
            if r.kind == "required":
                return "is missing" if r.value else None
            return "is missing" if r.kind in ("type", "min", "max", "allow", *CMP) else None
        v = args[r.arg]
        if r.kind == "required":
            return None
        if r.kind == "type":
            if r.value in ("number", "integer"):
                n = number(v)
                return "must be a whole number" if r.value == "integer" and n != n.to_integral_value() else None
            if r.value == "boolean":
                return None if isinstance(v, bool) else "must be true or false"
            text(v)
            return None
        if r.kind in ("min", "max"):
            n, bound = number(v), number(_resolve(r.value, args, ctx))
            return f"is {n}, below the minimum {bound}" if r.kind == "min" and n < bound else \
                f"is {n}, above the maximum {bound}" if r.kind == "max" and n > bound else None
        if r.kind == "allow":
            t = strict_text(v)
            allowed = [text(x) for x in (_resolve(r.value, args, ctx) or [])]
            return None if t in allowed else f"{t!r} is not on the allow-list"
        if r.kind == "pattern":
            return None if re.fullmatch(r.value, strict_text(v)) else "does not match its pattern"
        other = _resolve(r.value, args, ctx)
        if r.kind == "in":
            return None if text(v) in [text(x) for x in other] else f"{v!r} is not in {r.value}"
        try:
            a, b = number(v), number(other)
        except Unreadable:
            a, b = text(v), text(other)
        return None if CMP[r.kind](a, b) else f"is {a}, which breaks {r.kind} {r.value} ({b})"


class ArgPolicy:
    def __init__(self, tools, default="deny"):
        self.tools, self.default = tools, default

    @classmethod
    def from_dict(cls, d):
        if d.get("format") != FORMAT:
            raise PolicyError(f"format must be {FORMAT!r}")
        default = d.get("default", "deny")
        if default not in ("allow", "deny"):
            raise PolicyError("default must be allow or deny")
        return cls({t: ToolPolicy(t, s) for t, s in d.get("tools", {}).items()}, default)

    @classmethod
    def load(cls, path):
        return cls.from_dict(json.loads(Path(path).read_text()))

    def check(self, tool, args, ctx=None, narrowed=None):
        """-> ArgDecision. narrowed: a policy for this task from narrow(); widened values hold."""
        tp = (narrowed or {}).get(tool) or self.tools.get(tool)
        if tp is None:
            if self.default == "allow":
                return ArgDecision(tool, "allow")
            return ArgDecision(tool, "deny", (Violation("*", "unlisted tool", "is not in the policy", "deny"),))
        if not isinstance(args, dict):
            return ArgDecision(tool, "deny", (Violation("*", "arguments", "must be named arguments", "deny"),))
        vs = tp.check(args, ctx or {})
        widened = ()
        if narrowed and tool in narrowed and vs and self.tools.get(tool) is not None:
            # a call the narrowed policy refuses but the standing one allows needs a person, not a silent pass
            if not self.tools[tool].check(args, ctx or {}):
                widened = tuple(sorted({v.arg for v in vs}))
                vs = [dataclasses.replace(v, outcome="hold", detail=v.detail + " (outside this task's plan)")
                      for v in vs]
        outcome = max((v.outcome for v in vs), key=RANK.get, default="allow")
        return ArgDecision(tool, outcome, tuple(vs), widened)

    def narrow(self, tool, constraints):
        """-> ({tool: ToolPolicy}, refused): this task's policy, never wider than the standing one."""
        base = self.tools.get(tool)
        if base is None:
            raise PolicyError(f"{tool} is not in the policy, so a plan can't use it")
        spec = json.loads(json.dumps(base.spec))
        refused = []
        for arg, cons in constraints.items():
            cur = spec.setdefault("args", {}).setdefault(arg, {})
            for kind, val in cons.items():
                old = cur.get(kind)
                if kind == "max":
                    if old is None or (not str(old).startswith("$") and number(val) <= number(old)):
                        cur[kind] = val
                    else:
                        refused.append(f"{arg}.max {val} (standing max {old})")
                elif kind == "min":
                    if old is None or (not str(old).startswith("$") and number(val) >= number(old)):
                        cur[kind] = val
                    else:
                        refused.append(f"{arg}.min {val} (standing min {old})")
                elif kind == "allow":
                    if old is None:
                        cur[kind] = list(val)
                    else:
                        keep = [x for x in val if text(x) in {text(o) for o in old}]
                        refused += [f"{arg}.allow {x!r}" for x in val if x not in keep]
                        cur[kind] = keep
                elif kind in ("pattern", "required", *CMP) and old is None:
                    cur[kind] = val                      # an added constraint only narrows
                else:
                    refused.append(f"{arg}.{kind} (would replace the standing rule)")
        return {tool: ToolPolicy(tool, spec)}, refused


class ArgGate:
    """Wrap tools so every call is checked: deny raises PermissionError; hold calls the approver (or raises)."""

    def __init__(self, policy, ctx=None, approver=None, log=None):
        self.policy, self.ctx, self.approver = policy, ctx or {}, approver
        self.narrowed, self.log = {}, log if log is not None else []

    def plan(self, tool, constraints):
        narrowed, refused = self.policy.narrow(tool, constraints)
        self.narrowed.update(narrowed)
        return refused

    def wrap(self, fn, tool=None):
        name = tool or fn.__name__

        def gated(**kwargs):
            d = self.policy.check(name, kwargs, self.ctx, self.narrowed)
            self.log.append(d)
            if d.outcome == "hold" and self.approver is not None:
                ok = False
                try:
                    ok = bool(self.approver(d))
                except Exception:
                    ok = False                           # an approver that fails refuses
                if ok:
                    return fn(**kwargs)
            if not d.allowed:
                raise PermissionError(d.explain())
            return fn(**kwargs)
        gated.__name__ = getattr(fn, "__name__", name)
        return gated
