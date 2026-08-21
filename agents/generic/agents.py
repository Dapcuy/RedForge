"""Reference domain agents (structured output).

These are deterministic reference implementations that show how a concrete
agent plugs into the dispatcher. Real deployments replace these with LLM-backed
agents (Hermes/Claude/custom/local); the interface is identical.

Agents emit structured AgentResult (observations / tool_requests /
finding_candidates). They never produce shell commands and never touch the
runtime directly — a request to scan is an AgentToolRequest (a capability),
which the execution service resolves and policy-checks.
"""
from __future__ import annotations

import re
from typing import Any, ClassVar

from core.agents.interface import (
    Agent,
    AgentFindingCandidate,
    AgentResult,
    AgentToolRequest,
)


class ReconAgent(Agent):
    """Detects technology surface, flags recon-worthy signals, requests scanning."""

    name = "recon"

    def analyze(self, task: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.name)
        files = task.get("files", [])
        target = task.get("target", "") or ""
        for f in files:
            if re.search(r"(secret|password|api[_-]?key|token)", f, re.IGNORECASE):
                result.finding_candidates.append(AgentFindingCandidate(
                    title=f"Potential secret in {f}",
                    severity="high",
                    confidence="medium",
                    affected_component=f,
                    root_cause="hardcoded secret",
                ))
        if target:
            result.tool_requests.append(AgentToolRequest(
                capability="technology-detection", target_value=target,
            ))
            result.tool_requests.append(AgentToolRequest(
                capability="vulnerability-scanning", target_value=target,
            ))
        return result


class CodeAgent(Agent):
    """Static-analysis style agent: flags risky patterns in source."""

    name = "code"

    _PATTERNS: ClassVar[list[tuple[str, str, str]]] = [
        (r"eval\s*\(", "use of eval()", "high"),
        (r"subprocess\.(call|Popen|run)\(.*shell\s*=\s*True", "shell=True subprocess", "high"),
        (r"execute\s*\(\s*['\"].*\+", "SQL string concatenation", "medium"),
    ]

    def analyze(self, task: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.name)
        for f in task.get("files", []):
            try:
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    src = fh.read()
            except OSError:
                continue
            for pat, label, sev in self._PATTERNS:
                if re.search(pat, src, re.IGNORECASE):
                    result.finding_candidates.append(AgentFindingCandidate(
                        title=f"{label} in {f}",
                        severity=sev,
                        confidence="medium",
                        affected_component=f,
                        root_cause=label,
                    ))
            if src.strip():
                result.tool_requests.append(AgentToolRequest(
                    capability="source-scanning",
                    # No target_value: the orchestrator injects the authorized
                    # workspace root (opaque id) for source scans.
                ))
        return result


class Web3Agent(Agent):
    """Solidity-focused agent: flags reentrancy / unchecked external calls."""

    name = "web3"

    def analyze(self, task: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.name)
        for f in task.get("files", []):
            if not f.endswith(".sol"):
                continue
            try:
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    src = fh.read()
            except OSError:
                continue
            if re.search(r"\.call\{", src):
                result.finding_candidates.append(AgentFindingCandidate(
                    title=f"Potential reentrancy in {f}",
                    severity="high",
                    confidence="low",
                    affected_component=f,
                    root_cause="external call before state update",
                ))
                result.tool_requests.append(AgentToolRequest(
                    capability="solidity-analysis", target_value=f,
                ))
        return result
