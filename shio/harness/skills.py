"""HAR-5: skills: versioned bundles of prompts, tools and checks, loaded on demand, hashed and signed.

A skill is a folder with skill.json:
    {"format": "shio-skill/1", "name": "refunds", "version": "1.2.0", "description": "...",
     "prompts": {"system": "..."}, "tools": [{"name": "lookup_order", "kind": "reads"},
                                             {"name": "issue_refund", "kind": "acts"}],
     "checks": ["refund_cap"]}
plus any prompt files it references. The whole folder is hashed (the pack tree hash).

  SkillRegistry.pin(folder, by)          records the skill's hash: the version people looked at
  SkillRegistry.review(folder, by, role) a review entry for exactly that hash; required before a skill that declares
                                         any acts tool can load (maker-checker: the person who pinned it can't review)
  SkillRegistry.load(folder)             verifies the folder still has the pinned hash (a changed file fails), that
                                         acts tools are reviewed, and returns a Skill
  Skill.tools(available)                 only the ToolSpecs the skill declares, each with the declared kind; a skill
                                         that declares a tool as reads can't get it as acts. Calling anything else
                                         through Skill.call raises
"""
import dataclasses
import json
from pathlib import Path

from ..governance.chain import ApprovalLog, ChainError, SignedChain
from ..governance.packs import tree_sha256


class SkillError(ChainError):
    pass


@dataclasses.dataclass(frozen=True)
class Skill:
    name: str
    version: str
    sha256: str
    prompts: dict
    declared: dict                     # tool name -> kind
    checks: tuple

    def tools(self, available):
        by = {t.name: t for t in available}
        out = []
        for name, kind in self.declared.items():
            t = by.get(name)
            if t is None:
                raise SkillError(f"skill {self.name} declares {name}, which this agent doesn't provide")
            if t.kind != kind:
                raise SkillError(f"skill {self.name} declares {name} as {kind}, but the tool {name} {t.kind}: "
                                 f"a skill can't widen a tool")
            out.append(t)
        return out

    def call(self, name, fn, *a, **kw):
        if name not in self.declared:
            raise SkillError(f"skill {self.name} did not declare {name}")
        return fn(*a, **kw)


class SkillRegistry:
    def __init__(self, folder, signer=None):
        self.chain, self.reviews, self.signer = SignedChain(folder, "skills"), ApprovalLog(folder, "skill-reviews"), \
            signer

    @staticmethod
    def read(folder):
        d = json.loads((Path(folder) / "skill.json").read_text())
        if d.get("format") != "shio-skill/1":
            raise SkillError(f"{folder}: format must be shio-skill/1")
        for k in ("name", "version", "tools"):
            if k not in d:
                raise SkillError(f"{folder}: skill.json needs {k}")
        for t in d["tools"]:
            if t.get("kind") not in ("reads", "acts"):
                raise SkillError(f"{folder}: tool {t.get('name')} must say reads or acts")
        return d

    def pin(self, folder, by):
        d = self.read(folder)
        sha = tree_sha256(folder)
        self.chain.append("skill_pinned", {"name": d["name"], "version": d["version"], "tree_sha256": sha, "by": by},
                          self.signer)
        return sha

    def _pins(self, name):
        return [e for e in self.chain.entries() if e.get("name") == name and e["kind"] == "skill_pinned"]

    def review(self, folder, by, role, meaning="reviewed the skill's prompts, tools and checks"):
        d = self.read(folder)
        sha = tree_sha256(folder)
        pins = [e for e in self._pins(d["name"]) if e["tree_sha256"] == sha]
        if not pins:
            raise SkillError(f"{d['name']}: pin this version before reviewing it")
        self.reviews.record("skill", sha, by, role, meaning, makers=[p["by"] for p in pins], signer=self.signer,
                            title=f"{d['name']}@{d['version']}")

    def load(self, folder):
        d = self.read(folder)
        sha = tree_sha256(folder)
        pins = self._pins(d["name"])
        if not pins:
            raise SkillError(f"skill {d['name']} has never been pinned")
        if pins[-1]["tree_sha256"] != sha:
            raise SkillError(f"skill {d['name']} changed since it was pinned ({pins[-1]['tree_sha256'][:12]} -> "
                             f"{sha[:12]}): pin and review it again")
        acts = [t["name"] for t in d["tools"] if t["kind"] == "acts"]
        approved = [a for a in self.reviews.for_subject(sha) if a["decision"] == "approved"]
        if acts and not approved:
            raise SkillError(f"skill {d['name']} declares acts tools ({', '.join(acts)}) and has no review entry for "
                             f"this version")
        return Skill(d["name"], d["version"], sha, d.get("prompts", {}), {t["name"]: t["kind"] for t in d["tools"]},
                     tuple(d.get("checks", [])))
