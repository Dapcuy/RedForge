"""Tests for the Hermes agent adapter (EmitRequest contract)."""
import pytest

from agents.hermes.adapter import HermesAgent, parse_emit_request
from core.agents.interface import AgentResult

EMIT = {
    "agent": "hermes",
    "observations": [
        {"content": "server: nginx", "kind": "fingerprint"},
    ],
    "decisions": [
        {"action": "run-tool", "rationale": "profile the target"},
    ],
    "tool_requests": [
        {"capability": "technology-detection", "arguments": {"u": "http://example.com"}},
        {"capability": "vulnerability-scanning", "arguments": {}},
    ],
    "finding_candidates": [
        {
            "title": "nginx outdated",
            "severity": "medium",
            "confidence": "low",
            "affected_component": "http://example.com",
            "root_cause": "server version",
        }
    ],
}


def test_parse_emit_request_dict():
    res = parse_emit_request(EMIT)
    assert res.agent == "hermes"
    assert len(res.observations) == 1
    assert res.observations[0].content == "server: nginx"
    assert len(res.decisions) == 1
    assert res.decisions[0].action == "run-tool"
    assert len(res.tool_requests) == 2
    assert res.tool_requests[0].capability == "technology-detection"
    assert res.tool_requests[0].arguments["u"] == "http://example.com"
    assert len(res.finding_candidates) == 1
    assert res.finding_candidates[0].title == "nginx outdated"
    assert res.finding_candidates[0].severity == "medium"


def test_parse_emit_request_json_string():
    import json
    res = parse_emit_request(json.dumps(EMIT))
    assert res.agent == "hermes"
    assert len(res.tool_requests) == 2


def test_parse_emit_request_malformed():
    with pytest.raises((TypeError, ValueError)):
        parse_emit_request("[1,2,3]")
    with pytest.raises((TypeError, ValueError)):
        parse_emit_request("not json")


def test_parse_emit_unknown_fields_ignored():
    data = dict(EMIT)
    data["unknown_future_field"] = {"x": 1}
    res = parse_emit_request(data)
    assert res.agent == "hermes"


def test_hermes_agent_with_emit_payload():
    agent = HermesAgent(emit_payload=EMIT)
    res = agent.analyze({})
    assert isinstance(res, AgentResult)
    assert res.agent == "hermes"
    assert len(res.tool_requests) == 2


def test_hermes_agent_with_delegate():
    def delegate(task):
        r = AgentResult(agent="hermes")
        r.tool_requests.append(__import__(
            "core.agents.interface", fromlist=["AgentToolRequest"]
        ).AgentToolRequest(capability="technology-detection", target_value="http://x"))
        return r

    agent = HermesAgent(delegate=delegate)
    res = agent.analyze({"target": "http://x"})
    assert len(res.tool_requests) == 1


def test_hermes_agent_empty():
    agent = HermesAgent()
    res = agent.analyze({})
    assert res.agent == "hermes"
    assert res.tool_requests == []
