"""Skill Resolver: match a TargetProfile to relevant skills.

Resolution is specificity-first:

1. Match ``triggers.framework`` against the profile's frameworks.
2. Match ``triggers.technology`` against the profile's technologies.
3. Match ``triggers.indicators`` against the profile's indicators (raw fingerprints).

More specific skills sort before generic ones, so a ``nextjs-security`` skill
outranks a generic ``web-security`` skill for a Next.js target.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..models import TargetProfile
from .registry import SkillRegistry


@dataclass
class SkillMatch:
    skill: str
    specificity: int  # higher = more specific match
    matched_on: list[str]


class SkillResolver:
    def __init__(self, registry: SkillRegistry) -> None:
        self.registry = registry

    def resolve(self, profile: TargetProfile) -> list[SkillMatch]:
        matches: list[SkillMatch] = []
        tech = set(profile.technologies)
        fw = set(profile.frameworks)
        ind = set(profile.indicators)

        for skill in self.registry.skills.values():
            matched: list[str] = []
            for t in skill.frameworks:
                if t.lower() in {x.lower() for x in fw}:
                    matched.append(f"framework:{t}")
            for t in skill.technologies:
                if t.lower() in {x.lower() for x in tech}:
                    matched.append(f"technology:{t}")
            for t in skill.indicators:
                if t.lower() in {x.lower() for x in ind}:
                    matched.append(f"indicator:{t}")
            if not matched:
                continue

            # specificity: framework match weighs most, then technology, then indicator
            spec = 0
            for m in matched:
                if m.startswith("framework:"):
                    spec += 3
                elif m.startswith("technology:"):
                    spec += 2
                else:
                    spec += 1
            matches.append(SkillMatch(skill=skill.name, specificity=spec, matched_on=matched))

        matches.sort(key=lambda m: (-m.specificity, m.skill))
        return matches

    def skill_names(self, profile: TargetProfile) -> list[str]:
        return [m.skill for m in self.resolve(profile)]

    def expanded_skill_names(self, profile: TargetProfile) -> list[str]:
        """Resolve matches, then expand ``composes`` dependencies.

        A composable cross-framework skill may declare ``composes: [other]``.
        We return matched skills plus their transitive dependencies (in
        dependency-first order), so the planner sees the full knowledge set.
        """
        matched = self.skill_names(profile)
        ordered: list[str] = []
        seen: set[str] = set()

        def visit(name: str) -> None:
            if name in seen:
                return
            seen.add(name)
            skill = self.registry.get(name)
            if skill is None:
                return
            for dep in skill.composes:
                visit(dep)
            ordered.append(name)

        for name in matched:
            visit(name)
        return ordered

    def required_capabilities(self, profile: TargetProfile) -> list[str]:
        names = self.expanded_skill_names(profile)
        return self.registry.required_capabilities(names)
