"""HAR-3: the context engine. What the model sees, assembled from segments that keep their source, trust and hash.

  Segment     text plus where it came from (source), whether it is trusted, and its sha256
  @file refs  "@docs/plan.md" in a request loads that file (inside the project root only, no symlink escapes) as an
              untrusted segment unless the file is a project instruction file
  project     AGENTS.md and CLAUDE.md at the project root load as trusted instruction segments
  compress    fits segments into a budget: segments are kept whole while they fit; the rest are summarised by a
              summariser (default: first and last lines) into one segment that names the hashes of everything it came
              from (its lineage) and is trusted only if every source was. Untrusted text stays untrusted after
              compression, and a summary never loses track of what it summarised.
"""
import dataclasses
import hashlib
import re
from pathlib import Path

INSTRUCTION_FILES = ("AGENTS.md", "CLAUDE.md")
FILE_REF = re.compile(r"(?<![\w@])@([\w./-]+\.\w+)")


def _sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


@dataclasses.dataclass(frozen=True)
class Segment:
    text: str
    source: str
    trusted: bool = False
    lineage: tuple = ()                    # sha256 of the segments a summary was made from

    @property
    def sha256(self):
        return _sha(self.text)

    def render(self):
        tag = "TRUSTED" if self.trusted else "UNTRUSTED"
        return f"<<{tag} source={self.source} sha={self.sha256[:12]}>>\n{self.text}\n<</{tag}>>"


class ContextEngine:
    def __init__(self, root, max_file_bytes=200_000):
        self.root, self.max_file_bytes = Path(root).resolve(), max_file_bytes

    def _inside(self, rel):
        p = (self.root / rel).resolve()
        if p != self.root and self.root not in p.parents:
            raise PermissionError(f"@{rel} is outside the project root")
        return p

    def project_instructions(self):
        out = []
        for name in INSTRUCTION_FILES:
            p = self.root / name
            if p.is_file() and not p.is_symlink():
                out.append(Segment(p.read_text()[: self.max_file_bytes], f"project:{name}", trusted=True))
        return out

    def file_refs(self, request):
        out = []
        for rel in FILE_REF.findall(request or ""):
            p = self._inside(rel)
            if p.is_file():
                out.append(Segment(p.read_text(errors="replace")[: self.max_file_bytes], f"file:{rel}",
                                   trusted=p.name in INSTRUCTION_FILES and p.parent == self.root))
        return out

    def assemble(self, request, extra=()):
        return [*self.project_instructions(), Segment(request, "user request", trusted=True),
                *self.file_refs(request), *extra]


def first_last(segments, budget):
    lines = [ln for s in segments for ln in s.text.splitlines() if ln.strip()]
    head, tail = lines[:3], lines[-3:] if len(lines) > 6 else []
    text = "\n".join(head + (["..."] if tail else []) + tail)
    return text[:budget]


def compress(segments, budget, summariser=first_last):
    """-> segments fitting `budget` characters. Whole segments in order while they fit (trusted first), the rest as one
    summary segment with lineage. A summary's trust is the AND of its sources' trust."""
    ordered = sorted(segments, key=lambda s: not s.trusted)
    kept, rest, used = [], [], 0
    for s in ordered:
        if used + len(s.text) <= budget * 0.8 or (s.trusted and s.source == "user request"):
            kept.append(s)
            used += len(s.text)
        else:
            rest.append(s)
    if rest:
        room = max(200, budget - used)
        summary = summariser(rest, room)
        lineage = tuple(sorted({h for s in rest for h in (s.lineage or (s.sha256,))}))
        kept.append(Segment(summary, f"summary of {len(rest)} segment(s)", trusted=all(s.trusted for s in rest),
                            lineage=lineage))
    return kept


def lineage_of(segments):
    """Every source hash the context came from, through any number of compressions."""
    return sorted({h for s in segments for h in (s.lineage or (s.sha256,))})
