"""Generate-then-verify for free-text output (D16), and the three-option ladder.

Free text can't be fully checked, so the team picks, per use, how much free text to allow:

  option 1  STRUCTURED_ONLY    no free text: the model returns claims with quotes, and only quoted claims are shown
  option 2  VERIFY_AND_DROP    free text, sentence by sentence: unsupported sentences are removed (and listed)
  option 3  VERIFY_AND_REJECT  free text, all or nothing: one unsupported sentence sends the whole text to a person

A sentence is supported when every figure in it appears in the source (value and unit) and enough of its content
words appear in the source (coverage, default 0.75). That is a deterministic heuristic, not understanding, which is
why the wrongful-rejection rate of good text is measured on a labelled set (measure) and reported per option before
the team picks.
"""
import enum
import re
from dataclasses import dataclass, field

from .packs import load_pack

STOP = set("""a an and are as at be been by for from has have he her his i in is it its of on or she that the their
them they this to was were which who will with not no but if then than there these those so such into over under very
also may can could would should does did do had having patient patients""".split())
WORD = re.compile(r"[a-z][a-z0-9-]{2,}")


class Option(enum.IntEnum):
    STRUCTURED_ONLY = 1
    VERIFY_AND_DROP = 2
    VERIFY_AND_REJECT = 3


def sentences(text):
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Za-z0-9])|\n+", (text or "").strip())
    return [p.strip() for p in parts if p.strip()]


@dataclass
class SentenceCheck:
    sentence: str
    supported: bool
    coverage: float
    missing_figures: list = field(default_factory=list)


def check_sentence(sentence, index, min_coverage=0.75):
    g = load_pack("med.grounding").lib
    words = [w for w in WORD.findall(g.normalise(sentence)) if w not in STOP]
    present = sum(1 for w in words if w in index.text)
    coverage = present / len(words) if words else 1.0
    missing = [w for v, u, w in g.figures(sentence) if not index.has_figure(v, u)]
    return SentenceCheck(sentence, coverage >= min_coverage and not missing, round(coverage, 3), missing)


@dataclass
class Result:
    option: Option
    output: str = None           # what may be shown; None when the text goes to a person instead
    rejected: bool = False
    kept: list = field(default_factory=list)
    dropped: list = field(default_factory=list)
    checks: list = field(default_factory=list)


def verify(text, source, option, claims=None, min_coverage=0.75):
    """Verify a generated text (or, for option 1, its claims) against its source under one option."""
    g = load_pack("med.grounding").lib
    index = g.SourceIndex(source)
    option = Option(option)
    if option is Option.STRUCTURED_ONLY:
        kept, dropped = [], []
        for c in claims or []:
            (kept if index.find_quote(c.get("quote", "")) == "ok" else dropped).append(c)
        out = "\n".join(f"- {c['text']} (\"{c['quote']}\")" for c in kept) if kept else None
        return Result(option, out, not kept, kept, dropped)
    checks = [check_sentence(s, index, min_coverage) for s in sentences(text)]
    kept = [c.sentence for c in checks if c.supported]
    dropped = [c.sentence for c in checks if not c.supported]
    if option is Option.VERIFY_AND_REJECT:
        return Result(option, None if dropped else " ".join(kept), bool(dropped), kept, dropped, checks)
    note = f" [{len(dropped)} unsupported sentence{'s' if len(dropped) != 1 else ''} removed]" if dropped else ""
    return Result(option, (" ".join(kept) + note) if kept else None, not kept, kept, dropped, checks)


def generate_then_verify(generate, source, option, min_coverage=0.75):
    """generate(source) -> text (options 2, 3) or {"claims": [...]} (option 1). Then verify."""
    out = generate(source)
    if Option(option) is Option.STRUCTURED_ONLY:
        return verify(None, source, option, out.get("claims") if isinstance(out, dict) else None, min_coverage)
    return verify(out if isinstance(out, str) else out.get("text", ""), source, option, None, min_coverage)


def measure(cases, min_coverage=0.75):
    """Rates per option on a labelled set. Each case: {source, text, sentences: [true|false per sentence of text],
    claims: [{text, quote, good}]}. -> {option: {...}}.

    wrongful_rejection   good units the option withheld (good sentences dropped; good texts rejected; good claims
                         dropped), as a share of good units
    pass_through         bad units the option let through, as a share of bad units (hallucinations shown)"""
    out = {}
    for option in Option:
        good = withheld = bad = through = 0
        for case in cases:
            if option is Option.STRUCTURED_ONLY:
                r = verify(None, case["source"], option, case.get("claims", []), min_coverage)
                kept = {c["quote"] for c in r.kept}
                for c in case.get("claims", []):
                    if c["good"]:
                        good += 1
                        withheld += c["quote"] not in kept
                    else:
                        bad += 1
                        through += c["quote"] in kept
                continue
            r = verify(case["text"], case["source"], option, None, min_coverage)
            labels = case["sentences"]
            sents = sentences(case["text"])
            if len(labels) != len(sents):
                raise ValueError(f"case {case.get('id')}: {len(sents)} sentences but {len(labels)} labels")
            if option is Option.VERIFY_AND_REJECT:
                all_good = all(labels)
                good += all_good
                withheld += all_good and r.rejected
                bad += not all_good
                through += (not all_good) and not r.rejected
            else:
                kept = set(r.kept)
                for s, ok in zip(sents, labels):
                    if ok:
                        good += 1
                        withheld += s not in kept
                    else:
                        bad += 1
                        through += s in kept
        out[option.name] = {"option": int(option), "good": good, "bad": bad,
                            "wrongful_rejection": round(withheld / good, 4) if good else None,
                            "pass_through": round(through / bad, 4) if bad else None}
    return out
