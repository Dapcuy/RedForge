"""Tests for the Tool Registry (capability -> tool resolution)."""
import os

import pytest

from core.models import Tool
from core.tools.registry import ToolRegistry

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")


@pytest.fixture
def registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.load_dir(TOOLS_DIR)
    return reg


def test_loads_all_tools(registry):
    names = set(registry.tools)
    assert {"httpx", "nuclei", "ffuf", "nmap", "semgrep", "slither"} <= names


def test_resolve_vulnerability_scanning(registry):
    tool = registry.resolve_capability("vulnerability-scanning")
    assert tool.name == "nuclei"


def test_resolve_static_analysis_prefers_semgrep(registry):
    # both semgrep and slither satisfy static-analysis; default order -> semgrep
    tool = registry.resolve_capability("static-analysis")
    assert tool.name in {"semgrep", "slither"}


def test_resolve_unknown_capability_raises(registry):
    with pytest.raises(KeyError):
        registry.resolve_capability("does-not-exist")


def test_resolve_preferred_tool(registry):
    tool = registry.resolve_capability("static-analysis", preferred="slither")
    assert tool.name == "slither"


def test_duplicate_registration_raises():
    reg = ToolRegistry()
    t = Tool(
        name="x", domain="web", capabilities=["a"],
        runtime={"image": "i"}, inputs={"target": "url"}, output={"format": "json"},
    )
    reg.register(t)
    with pytest.raises(ValueError):
        reg.register(t)


def test_manifest_missing_field_raises():
    with pytest.raises(ValueError):
        Tool.from_manifest({"name": "broken", "domain": "web"})
