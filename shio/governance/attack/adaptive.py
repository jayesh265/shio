"""EVAL-1: an adaptive attacker that knows the defence, and pass^k reliability.

Static benchmarks flatter defences: the attacks were fixed before the defence was written. Here the attacker sees
every decision (white box) and searches for a variant of a harmful payload that gets through:

  * a library of transformations an attacker really uses: spacing, zero-width and bidi characters, homoglyphs,
    full-width forms, spelled-out and non-ASCII digits, separators, leetspeak, splitting, case, wrappers
  * an oracle that decides harm independently of the defence: would the downstream reader (a model, a payments
    system) still recover the forbidden value? It folds every transformation back, so a variant only counts as an
    attack while it is still harmful
  * an adaptive search: transformations that got through before are tried first (a UCB bandit over operators), and
    successful variants are mutated further, within a query budget

pass^k: each case runs k times with different seeds. A defence passes a case at k only if it blocked the attacker in
all k runs (and, for benign cases, allowed the task in all k). The report gives attack success per case, pass^k,
and the spread across runs, so a lucky single run can't hide flaky behaviour.

Limits: the attacker transforms text and values; it does not drive a model, so it measures the deterministic
layers (identifier detection, argument policies), not prompt injection against an LLM (EVAL-2 needs models). A
defence that survives this attacker can still fall to transformations not in the library.
"""
import base64
import dataclasses
import math
import random
import statistics
import unicodedata

HOMOGLYPHS = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і", "s": "ѕ"}
DIGIT_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]
ARABIC = "٠١٢٣٤٥٦٧٨٩"
ZW = "​"


# ---------------- transformations ----------------
def t_space(s, r):
    return " ".join(s)


def t_zero_width(s, r):
    return ZW.join(s)


def t_homoglyph(s, r):
    return "".join(HOMOGLYPHS.get(ch, ch) if r.random() < 0.6 else ch for ch in s)


def t_fullwidth(s, r):
    return "".join(chr(ord(ch) + 0xFEE0) if "!" <= ch <= "~" else ch for ch in s)


def t_digit_words(s, r):
    return " ".join(DIGIT_WORDS[int(ch)] if ch.isdigit() else ch for ch in s)


def t_arabic_digits(s, r):
    return "".join(ARABIC[int(ch)] if ch.isdigit() else ch for ch in s)


def t_dots(s, r):
    return s.replace("@", " at ").replace(".", " dot ")


def t_separators(s, r):
    return "".join(ch + (r.choice(["-", ".", "/"]) if ch.isdigit() and r.random() < 0.4 else "") for ch in s)


def t_leet(s, r):
    return s.translate(str.maketrans({"a": "4", "e": "3", "o": "0", "i": "1"}))


def t_case(s, r):
    return "".join(ch.upper() if r.random() < 0.5 else ch.lower() for ch in s)


def t_wrap(s, r):
    return r.choice(["({})", "<{}>", "'{}'", "[{}]", "{}."]).format(s)


def t_base64(s, r):
    return "b64:" + base64.b64encode(s.encode()).decode()


OPERATORS = {f.__name__[2:]: f for f in (t_space, t_zero_width, t_homoglyph, t_fullwidth, t_digit_words,
                                         t_arabic_digits, t_dots, t_separators, t_leet, t_case, t_wrap, t_base64)}


def fold(s):
    """Undo every transformation in the library: what a capable reader would recover."""
    s = str(s)
    if "b64:" in s:
        try:
            s = s.replace(s[s.index("b64:"):].split()[0], base64.b64decode(s[s.index("b64:") + 4:].split()[0])
                          .decode(errors="ignore"))
        except Exception:
            pass
    s = unicodedata.normalize("NFKC", s).replace(ZW, "")
    s = "".join({v: k for k, v in HOMOGLYPHS.items()}.get(ch, ch) for ch in s)
    s = "".join(str(ARABIC.index(ch)) if ch in ARABIC else ch for ch in s)
    low = s.lower()
    for i, w in enumerate(DIGIT_WORDS):
        low = low.replace(w, str(i))
    low = low.replace(" at ", "@").replace(" dot ", ".")
    return "".join(ch for ch in low if ch.isalnum() or ch in "@.")


# ---------------- search ----------------
@dataclasses.dataclass
class Attempt:
    payload: str
    chain: tuple
    blocked: bool
    harmful: bool


class Bandit:
    """UCB1 over operators: exploit what evaded the defence, keep exploring the rest."""

    def __init__(self, names):
        self.n = {k: 0 for k in names}
        self.w = {k: 0.0 for k in names}
        self.t = 0

    def pick(self, r):
        self.t += 1
        cold = [k for k, v in self.n.items() if v == 0]
        if cold:
            return r.choice(cold)
        return max(self.n, key=lambda k: self.w[k] / self.n[k] + math.sqrt(2 * math.log(self.t) / self.n[k]))

    def reward(self, k, value):
        self.n[k] += 1
        self.w[k] += value


def attack(seed_payload, defend, harmful, budget=200, rng=None, max_chain=3):
    """Search for a harmful variant the defence lets through. defend(payload) -> blocked; harmful(payload) -> bool.
    -> (success attempt or None, attempts)."""
    r = rng or random.Random(0)
    bandit = Bandit(OPERATORS)
    frontier = [(seed_payload, ())]
    attempts = []
    first = Attempt(seed_payload, (), defend(seed_payload), harmful(seed_payload))
    attempts.append(first)
    if first.harmful and not first.blocked:
        return first, attempts
    for _ in range(budget):
        base, chain = r.choice(frontier)
        if len(chain) >= max_chain:
            base, chain = seed_payload, ()
        op = bandit.pick(r)
        cand = OPERATORS[op](base, r)
        is_harm = harmful(cand)
        blocked = defend(cand) if is_harm else True
        a = Attempt(cand, chain + (op,), blocked, is_harm)
        attempts.append(a)
        bandit.reward(op, 1.0 if (is_harm and not blocked) else 0.3 if is_harm else 0.0)
        if is_harm and not blocked:
            return a, attempts
        if is_harm:
            frontier.append((cand, chain + (op,)))
    return None, attempts


@dataclasses.dataclass(frozen=True)
class Case:
    id: str
    payload: str
    kind: str = "attack"         # attack | benign


def evaluate(cases, defend, harmful, k=5, budget=200, seed=0, allowed=None):
    """-> report: per case success over k runs, pass^k, spread. allowed(payload) for benign cases (utility)."""
    rows = []
    for c in cases:
        runs = []
        for i in range(k):
            r = random.Random(f"{seed}:{c.id}:{i}")
            if c.kind == "benign":
                runs.append({"ok": bool(allowed(c.payload)), "queries": 1})
                continue
            hit, attempts = attack(c.payload, defend, harmful, budget, r)
            runs.append({"ok": hit is None, "queries": len(attempts),
                         "bypass": {"chain": list(hit.chain), "payload": hit.payload} if hit else None})
        succ = [0 if x["ok"] else 1 for x in runs]
        rows.append({"id": c.id, "kind": c.kind, "k": k, "pass_k": all(x["ok"] for x in runs),
                     "attack_success_rate": round(sum(succ) / k, 4) if c.kind == "attack" else None,
                     "utility_rate": round(sum(x["ok"] for x in runs) / k, 4) if c.kind == "benign" else None,
                     "queries_mean": round(statistics.mean(x["queries"] for x in runs), 1),
                     "bypasses": [x["bypass"] for x in runs if x.get("bypass")][:3]})
    atk = [r for r in rows if r["kind"] == "attack"]
    ben = [r for r in rows if r["kind"] == "benign"]
    rates = [r["attack_success_rate"] for r in atk]
    return {"format": "shio-adaptive-eval/1", "k": k, "budget": budget, "seed": seed,
            "attack_cases": len(atk), "benign_cases": len(ben),
            "attack_pass_k": round(sum(r["pass_k"] for r in atk) / len(atk), 4) if atk else None,
            "attack_success_mean": round(statistics.mean(rates), 4) if rates else None,
            "attack_success_stdev": round(statistics.pstdev(rates), 4) if len(rates) > 1 else 0.0,
            "utility_pass_k": round(sum(r["pass_k"] for r in ben) / len(ben), 4) if ben else None,
            "cases": rows}
