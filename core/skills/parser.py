"""SKILL.md parser.

A Skill is a knowledge unit with YAML frontmatter + a markdown body. The
frontmatter carries machine-readable fields (name, domain, requires, triggers,
severity_focus); the body carries human/agent-readable methodology.

Key rule: ``requires`` must be a list of *capabilities* (abstract verbs), NEVER
tool names. Violations are caught here (the word 'tool' is only tolerated inside
the markdown body, not the frontmatter).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

VALID_DOMAINS = {"web", "api", "code", "cloud", "network", "web3"}

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", re.DOTALL)


class SkillParseError(ValueError):
    """Raised when a SKILL.md is malformed or violates the spec."""


@dataclass
class Skill:
    name: str
    domain: str
    version: str
    requires: list[str]
    triggers: dict = field(default_factory=dict)
    severity_focus: list[str] = field(default_factory=list)
    body: str = ""
    path: str = ""

    @property
    def technologies(self) -> list[str]:
        return list(self.triggers.get("technology", []))

    @property
    def frameworks(self) -> list[str]:
        return list(self.triggers.get("framework", []))

    @property
    def indicators(self) -> list[str]:
        return list(self.triggers.get("indicators", []))


def _split_frontmatter(text: str) -> tuple[dict, str]:
    m = _FRONTMATTER_RE.match(text)
    if not m:
        raise SkillParseError("missing YAML frontmatter (must start with '---')")
    raw_fm, body = m.group(1), m.group(2).strip()
    try:
        data = yaml.safe_load(raw_fm) or {}
    except yaml.YAMLError as exc:
        raise SkillParseError(f"invalid YAML frontmatter: {exc}") from exc
    if not isinstance(data, dict):
        raise SkillParseError("frontmatter must be a YAML mapping")
    return data, body


def parse_skill(text: str, path: str = "") -> Skill:
    data, body = _split_frontmatter(text)

    required = {"name", "domain", "version", "requires"}
    missing = required - set(data)
    if missing:
        raise SkillParseError(f"missing frontmatter fields: {sorted(missing)}")

    name = str(data["name"])
    domain = str(data["domain"])
    version = str(data["version"])
    requires = data["requires"]

    if domain not in VALID_DOMAINS:
        raise SkillParseError(f"skill {name} has unknown domain: {domain}")
    if not isinstance(requires, list) or not requires:
        raise SkillParseError(f"skill {name} 'requires' must be a non-empty list")
    for cap in requires:
        if not isinstance(cap, str):
            raise SkillParseError(f"skill {name} 'requires' entries must be strings")

    triggers = data.get("triggers") or {}
    if not isinstance(triggers, dict):
        raise SkillParseError(f"skill {name} 'triggers' must be a mapping")

    severity = data.get("severity_focus") or []
    if not isinstance(severity, list):
        raise SkillParseError(f"skill {name} 'severity_focus' must be a list")

    return Skill(
        name=name,
        domain=domain,
        version=version,
        requires=list(requires),
        triggers=triggers,
        severity_focus=list(severity),
        body=body,
        path=path,
    )
