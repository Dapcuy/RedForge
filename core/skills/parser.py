"""SKILL.md parser (schema v2).

A Skill is a knowledge unit with YAML frontmatter + a markdown body. The
frontmatter carries machine-readable fields; the body carries
human/agent-readable methodology.

New in schema v2 (P1 hardening):
  - ``schema_version``: semantic version of the SKILL.md schema itself.
  - ``validation``: how a candidate finding is validated (required).
  - ``evidence_requirements``: what evidence a finding must carry (required).
  - ``composes``: list of other skill names this skill composes (cross-framework).

Key rule (unchanged): ``requires`` must be a list of *capabilities* (abstract
verbs), NEVER tool names.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

VALID_DOMAINS = {"web", "api", "code", "cloud", "network", "web3"}
SUPPORTED_SCHEMA_VERSIONS = {"1.0", "2.0"}

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", re.DOTALL)


class SkillParseError(ValueError):
    """Raised when a SKILL.md is malformed or violates the spec."""


@dataclass
class Skill:
    name: str
    domain: str
    version: str
    requires: list[str]
    schema_version: str = "2.0"
    validation: list[str] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)
    composes: list[str] = field(default_factory=list)
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


def _str_list(data: dict, key: str, skill_name: str) -> list[str]:
    value = data.get(key) or []
    if not isinstance(value, list):
        raise SkillParseError(f"skill {skill_name} '{key}' must be a list")
    for item in value:
        if not isinstance(item, str):
            raise SkillParseError(f"skill {skill_name} '{key}' entries must be strings")
    return list(value)


def parse_skill(text: str, path: str = "") -> Skill:
    data, body = _split_frontmatter(text)

    required = {"name", "domain", "version", "requires"}
    missing = required - set(data)
    if missing:
        raise SkillParseError(f"missing frontmatter fields: {sorted(missing)}")

    name = str(data["name"])
    domain = str(data["domain"])
    version = str(data["version"])

    schema_version = str(data.get("schema_version", "2.0"))
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise SkillParseError(
            f"skill {name} has unsupported schema_version {schema_version!r} "
            f"(supported: {sorted(SUPPORTED_SCHEMA_VERSIONS)})"
        )

    if domain not in VALID_DOMAINS:
        raise SkillParseError(f"skill {name} has unknown domain: {domain}")

    requires = data["requires"]
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
        schema_version=schema_version,
        requires=list(requires),
        validation=_str_list(data, "validation", name),
        evidence_requirements=_str_list(data, "evidence_requirements", name),
        composes=_str_list(data, "composes", name),
        triggers=triggers,
        severity_focus=list(severity),
        body=body,
        path=path,
    )
