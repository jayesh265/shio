"""Policy-to-checks compiler, beta (D23): a plain-language policy becomes draft checks and tests, with a
clause -> check -> test trace. Every draft needs a recorded human approval before it can be used.

The compiler is deterministic: clauses are matched against templates (thresholds, ranges, required fields, allowed
values, matching a source, forbidden content, sign-off conditions). A clause no template matches is listed as
"no check drafted: needs a person", never guessed. Each draft check comes with tests the compiler runs itself, on
synthetic values either side of the rule, so a draft that doesn't do what its clause says is caught before review.

    drafts = compile_policy(text, subject="claim")
    approve(drafts, "c-1", approvals_dir, by=..., role="policy_owner")
    export(drafts, approvals_dir)          # .shio check lines, only for approved drafts
"""
import datetime as dt
import re
import types
from dataclasses import dataclass, field

from ..ledger import sha256
from .chain import APPROVED, ApprovalLog

FORMAT = "shio-policy-drafts/1"
NUM = r"(-?\d+(?:[.,]\d+)*)"
UNIT = r"\s*(?:%|percent|days?|hours?|years?|usd|eur|gbp|inr|\$|£|€|rs\.?|kg|mg)?"


def snake(text):
    words = re.findall(r"[a-z0-9]+", text.lower())
    words = [w for w in words if w not in ("the", "a", "an", "each", "every", "any", "all", "its", "their")]
    return "_".join(words) or "field"


def _num(text):
    v = float(text.replace(",", ""))
    return int(v) if v.is_integer() else v


@dataclass
class Draft:
    id: str
    clause_id: str
    clause: str
    kind: str                    # check | signoff
    code: str                    # .shio source of the draft
    expr: str = None             # the check's condition, over `subject` (for the self-tests)
    tests: list = field(default_factory=list)   # [{"id", "value", "expect"}]
    field_name: str = None

    def as_dict(self):
        return {k: getattr(self, k) for k in ("id", "clause_id", "clause", "kind", "code", "expr", "tests",
                                              "field_name")}


TEMPLATES = []


def template(pattern):
    def deco(fn):
        TEMPLATES.append((re.compile(pattern, re.I), fn))
        return fn
    return deco


@template(rf"^(?P<f>.+?)\s+(?:must|shall|may)\s+not\s+(?:exceed|be more than|be greater than|be over|be above)\s+{NUM}{UNIT}$")
def _max(m, subj):
    f, n = snake(m["f"]), _num(m[2])
    return "check", f"{subj}.{f} <= {n!r}", f, [(n, True), (n - 1 if isinstance(n, int) else n * 0.9, True),
                                             (n + 1 if isinstance(n, int) else n * 1.1, False)]


@template(rf"^(?P<f>.+?)\s+(?:must|shall)\s+be\s+(?:at least|no less than|not less than|a minimum of)\s+{NUM}{UNIT}$")
def _min(m, subj):
    f, n = snake(m["f"]), _num(m[2])
    return "check", f"{subj}.{f} >= {n!r}", f, [(n, True), (n + 1, True), (n - 1, False)]


@template(rf"^(?P<f>.+?)\s+(?:must|shall)\s+be\s+between\s+{NUM}{UNIT}\s+and\s+{NUM}{UNIT}$")
def _range(m, subj):
    f, lo, hi = snake(m["f"]), _num(m[2]), _num(m[3])
    return "check", f"{lo!r} <= {subj}.{f} <= {hi!r}", f, [(lo, True), (hi, True), (lo - 1, False), (hi + 1, False)]


@template(r"^(?P<f>.+?)\s+(?:is|are)\s+(?:required|mandatory)$|^(?:the\s+)?(?:\w+\s+)?(?:must|shall)\s+(?:include|state|record|have)\s+(?:a|an|the)?\s*(?P<g>.+)$")
def _required(m, subj):
    f = snake(m["f"] or m["g"])
    return "check", f"{subj}.{f} not in (None, '', [], {{}})", f, [("present", True), ("", False), (None, False)]


@template(r"^(?P<f>.+?)\s+(?:must|shall)\s+be\s+one\s+of\s+(?P<opts>.+)$")
def _one_of(m, subj):
    f = snake(m["f"])
    opts = [o.strip(" .'\"") for o in re.split(r",\s*(?:or\s+)?|\s+or\s+", m["opts"]) if o.strip(" .'\"")]
    return "check", f"{subj}.{f} in {tuple(sorted(set(opts)))!r}", f, [(opts[0], True), (opts[-1], True),
                                                                      ("__other__", False)]


@template(r"^(?P<f>.+?)\s+(?:must|shall)\s+(?:match|appear in|be found in|agree with)\s+(?:the\s+)?(?P<src>.+)$")
def _matches(m, subj):
    f, src = snake(m["f"]), snake(m["src"])
    return "check", f"{subj}.{f} in {src}", f, None      # needs the source at run time: tested by a person


@template(r"^(?P<f>.+?)\s+(?:must|shall)\s+not\s+(?:contain|include|mention)\s+(?P<what>.+)$")
def _forbid(m, subj):
    f, what = snake(m["f"]), m["what"].strip(" .'\"").lower()
    return "check", f"{what!r} not in str({subj}.{f}).lower()", f, [("clean text", True), (f"text with {what}", False)]


@template(rf"^(?:any|an?|every)\s+(?P<o>\w+)\s+(?:over|above|of more than|greater than|exceeding)\s+{NUM}{UNIT}\s+(?:requires|needs|must have)\s+(?:the\s+)?(?:approval|sign-?off)\s+(?:of|by|from)\s+(?:the\s+|a\s+|an\s+)?(?P<role>[\w\s-]+?)$")
def _signoff(m, subj):
    label, n, role = m["o"].upper(), _num(m[2]), m["role"].strip().lower().replace(" ", "_")
    return "signoff", f'signoff {label} when amount > {n!r} by role "{role}"', "amount", None


def clauses(text):
    """Numbered clauses ("1.", "2)", "a.") or sentences, with their ids."""
    out = []
    for i, line in enumerate(l.strip() for l in text.splitlines() if l.strip()):
        m = re.match(r"^(\d+(?:\.\d+)*|[a-z])[.)]\s+(.+)$", line)
        cid, body = (m.group(1), m.group(2)) if m else (str(i + 1), line)
        for j, sentence in enumerate(s for s in re.split(r"(?<=[.;])\s+", body) if s.strip()):
            out.append((cid if j == 0 else f"{cid}.{j}", sentence.strip().rstrip(".;")))
    return out


def compile_policy(text, subject="item", source="policy"):
    """-> the drafts document: {format, source, sha256 of the policy, drafts, unmatched, matrix}."""
    drafts, unmatched = [], []
    for cid, clause in clauses(text):
        for pat, fn in TEMPLATES:
            m = pat.match(clause)
            if not m:
                continue
            kind, body, fname, tests = fn(m, subject)
            did = f"D{len(drafts) + 1}"
            name = f"{fname}_{did.lower()}"
            why = clause[:60].replace("\\", "/").replace('"', "'").replace("{", "(").replace("}", ")")
            code = f"check {name}: {body}, \"policy clause {cid}: {why}\"" if kind == "check" else body
            tlist = [{"id": f"{did}-T{k + 1}", "value": v, "expect": e} for k, (v, e) in enumerate(tests or [])]
            drafts.append(Draft(did, cid, clause, kind, code, body if kind == "check" else None, tlist, fname))
            break
        else:
            unmatched.append({"clause_id": cid, "clause": clause, "status": "no check drafted: needs a person"})
    for d in drafts:
        d.results = run_tests(d, subject)
    doc = {"format": FORMAT, "source": source, "policy_sha256": sha256(text.encode()), "subject": subject,
           "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
           "drafts": [{**d.as_dict(), "sha256": sha256(d.as_dict()), "test_results": d.results} for d in drafts],
           "unmatched": unmatched}
    doc["matrix"] = matrix(doc)
    return doc


def run_tests(draft, subject):
    """Run a draft check's own tests: the condition evaluated over a synthetic subject. -> [{"id", "ok", "got"}]."""
    if not draft.expr or not draft.tests:
        return []
    out = []
    code = compile(draft.expr, f"<draft {draft.id}>", "eval")
    for t in draft.tests:
        env = {subject: types.SimpleNamespace(**{draft.field_name: t["value"]}), "str": str}
        try:
            got = bool(eval(code, {"__builtins__": {}}, env))
        except Exception as e:                     # a comparison with None, say: the check fails, as Shio's would
            got = False if t["expect"] is False else f"error: {type(e).__name__}"
        out.append({"id": t["id"], "ok": got == t["expect"], "got": got})
    return out


def matrix(doc):
    """The traceability matrix: one row per clause, its draft check, its tests, and whether they pass."""
    rows = []
    for d in doc["drafts"]:
        ok = all(r["ok"] for r in d["test_results"]) if d["test_results"] else None
        rows.append({"clause": d["clause_id"], "text": d["clause"], "draft": d["id"], "kind": d["kind"],
                     "tests": [t["id"] for t in d["tests"]],
                     "tests_pass": ok, "status": "DRAFT"})
    rows += [{"clause": u["clause_id"], "text": u["clause"], "draft": None, "kind": None, "tests": [],
              "tests_pass": None, "status": u["status"]} for u in doc["unmatched"]]
    return sorted(rows, key=lambda r: [int(x) if x.isdigit() else x for x in re.split(r"\.", r["clause"])])


def approve(doc, draft_id, approvals, by, role, meaning="draft check approved for use", signer=None, reject=False):
    """Record a person's approval (or rejection) of one draft, bound to its sha256."""
    d = next((x for x in doc["drafts"] if x["id"] == draft_id), None)
    if d is None:
        raise KeyError(f"no draft {draft_id}")
    if d["test_results"] and not all(r["ok"] for r in d["test_results"]) and not reject:
        raise ValueError(f"draft {draft_id} fails its own tests; fix it before approving")
    return ApprovalLog(approvals, "policy-approvals").record("draft-check", d["sha256"], by, role, meaning,
                                                             "rejected" if reject else "approved", signer=signer,
                                                             title=f"{doc['source']} clause {d['clause_id']}")


def status(doc, approvals, roles=("policy_owner",)):
    log = ApprovalLog(approvals, "policy-approvals")
    return {d["id"]: log.status(d["sha256"], list(roles))[0] for d in doc["drafts"]}


def export(doc, approvals, roles=("policy_owner",)):
    """-> (.shio lines for approved drafts, [ids not approved]). Unapproved drafts are never exported."""
    st = status(doc, approvals, roles)
    lines = [f"# from {doc['source']} (policy sha256 {doc['policy_sha256'][:12]}); approved drafts only"]
    lines += [f"{d['code']}    # clause {d['clause_id']}, draft {d['id']}" for d in doc["drafts"] if st[d["id"]] == APPROVED]
    return lines, [i for i, s in st.items() if s != APPROVED]


def matrix_markdown(doc, approvals=None):
    st = status(doc, approvals) if approvals else {}
    out = ["| Clause | Text | Draft | Tests | Tests pass | Status |", "|---|---|---|---|---|---|"]
    for r in doc["matrix"]:
        state = st.get(r["draft"], r["status"]) if r["draft"] else r["status"]
        out.append(f"| {r['clause']} | {r['text'][:80]} | {r['draft'] or '-'} | {', '.join(r['tests']) or '-'} | "
                   f"{'-' if r['tests_pass'] is None else 'yes' if r['tests_pass'] else 'NO'} | {state} |")
    return "\n".join(out)
