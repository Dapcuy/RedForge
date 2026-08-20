"""Skill Registry: loads all SKILL.md files into an index."""
from __future__ import annotations

import glob
import os
from collections.abc import Iterable

from .parser import Skill, parse_skill


class SkillRegistry:
    """Holds all known skills, indexed by name (and optionally domain)."""

    def __init__(self) -> None:
        self._skills: dict[str, Skill] = {}

    def register(self, skill: Skill) -> None:
        if skill.name in self._skills:
            raise ValueError(f"duplicate skill name: {skill.name}")
        self._skills[skill.name] = skill

    def load_dir(self, path: str) -> int:
        """Load every ``SKILL.md`` under a directory tree. Returns count loaded."""
        count = 0
        for fname in sorted(glob.glob(os.path.join(path, "**", "SKILL.md"), recursive=True)):
            with open(fname, "r", encoding="utf-8") as fh:
                skill = parse_skill(fh.read(), path=fname)
            self.register(skill)
            count += 1
        return count

    def get(self, name: str) -> Skill | None:
        return self._skills.get(name)

    def by_domain(self, domain: str) -> list[Skill]:
        return [s for s in self._skills.values() if s.domain == domain]

    @property
    def skills(self) -> dict[str, Skill]:
        return dict(self._skills)

    def names(self) -> list[str]:
        return sorted(self._skills)

    def required_capabilities(self, skills: Iterable[str]) -> list[str]:
        """Union of ``requires`` across the given skill names, deduplicated."""
        caps: list[str] = []
        seen: set[str] = set()
        for name in skills:
            skill = self._skills.get(name)
            if skill is None:
                continue
            for cap in skill.requires:
                if cap not in seen:
                    seen.add(cap)
                    caps.append(cap)
        return caps
