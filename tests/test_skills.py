"""Tests for the SKILL.md parser, registry, and resolver."""
import os

import pytest

from core.models import Target, TargetKind, TargetProfile
from core.skills.parser import parse_skill, SkillParseError
from core.skills.registry import SkillRegistry
from core.skills.resolver import SkillResolver

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "skills")

VALID_FM = """---
name: test-skill
domain: web
version: 0.1.0
requires:
  - http-analysis
triggers:
  framework: [nextjs]
---
## Objective
Test.
"""


def test_parse_valid_skill():
    skill = parse_skill(VALID_FM)
    assert skill.name == "test-skill"
    assert skill.domain == "web"
    assert skill.requires == ["http-analysis"]
    assert skill.frameworks == ["nextjs"]
    assert "## Objective" in skill.body


def test_parse_missing_frontmatter():
    with pytest.raises(SkillParseError):
        parse_skill("no frontmatter here")


def test_parse_missing_required_field():
    with pytest.raises(SkillParseError):
        parse_skill("---\nname: x\ndomain: web\nversion: 1\n---\n")


def test_parse_unknown_domain():
    with pytest.raises(SkillParseError):
        parse_skill(
            "---\nname: x\ndomain: quantum\nversion: 1\nrequires: [a]\n---\n"
        )


def test_parse_requires_must_be_list():
    with pytest.raises(SkillParseError):
        parse_skill("---\nname: x\ndomain: web\nversion: 1\nrequires: http-analysis\n---\n")


@pytest.fixture
def registry():
    reg = SkillRegistry()
    reg.load_dir(SKILLS_DIR)
    return reg


def test_registry_loads_skills(registry):
    names = set(registry.names())
    assert {"nextjs-security", "wordpress-security", "solidity-reentrancy", "api-authentication"} <= names


def test_resolver_matches_nextjs(registry):
    resolver = SkillResolver(registry)
    profile = TargetProfile(
        target=Target(TargetKind.REPO, "git@example.com/repo"),
        technologies=["react", "nodejs"],
        frameworks=["nextjs"],
    )
    names = resolver.skill_names(profile)
    assert "nextjs-security" in names


def test_resolver_specificity_order(registry):
    resolver = SkillResolver(registry)
    profile = TargetProfile(
        target=Target(TargetKind.URL, "https://wp.example.com"),
        technologies=["wordpress"],
        indicators=["wp-content"],
    )
    names = resolver.skill_names(profile)
    # wordpress-security should match and be present
    assert "wordpress-security" in names


def test_resolver_no_match(registry):
    resolver = SkillResolver(registry)
    profile = TargetProfile(
        target=Target(TargetKind.URL, "https://unknown.example.com"),
        technologies=["dotnet"],
    )
    assert resolver.skill_names(profile) == []


def test_resolver_required_capabilities(registry):
    resolver = SkillResolver(registry)
    profile = TargetProfile(
        target=Target(TargetKind.REPO, "x"),
        technologies=["react", "nodejs"],
        frameworks=["nextjs"],
    )
    caps = resolver.required_capabilities(profile)
    # nextjs-security requires technology-detection, source-scanning, http-analysis
    assert "source-scanning" in caps
    assert "http-analysis" in caps
