"""Reference domain agents.

These are deterministic reference implementations that show how a concrete
agent plugs into the dispatcher. Real deployments replace these with LLM-backed
agents (Hermes/Claude/custom/local); the interface is identical.
"""
from __future__ import annotations

import re
from typing import Any

from core.agents.interface import Agent, AgentResult


class ReconAgent(Agent):
    """Detects technology surface and flags recon-worthy signals."""

    name = "recon"

    def analyze(self, task: dict[str, Any]) -> AgentResult:
        candidates = []
        files = task.get("files", [])
        for f in files:
            if re.search(r"(secret|password|api[_-]?key|token)", f, re.IGNORECASE):
                candidates.append({
                    "title": f"Potential secret in {f}",
                    "severity": "high",
                    "affected_component": f,
                    "root_cause": "hardcoded secret",
                    "confidence": "medium",
                })
        return AgentResult(agent=self.name, candidates=candidates)


class CodeAgent(Agent):
    """Static-analysis style agent: flags risky patterns in source."""

    name = "code"

    _PATTERNS = [
        (r"eval\s*\(", "use of eval()", "high"),
        (r"subprocess\.(call|Popen|run)\(.*shell\s*=\s*True", "shell=True subprocess", "high"),
        (r"execute\s*\(\s*['\"].*\+", "SQL string concatenation", "medium"),
    ]

    def analyze(self, task: dict[str, Any]) -> AgentResult:
        candidates = []
        files = task.get("files", [])
        for f in files:
            try:
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    src = fh.read()
            except OSError:
                continue
            for pat, label, sev in self._PATTERNS:
                if re.search(pat, src, re.IGNORECASE):
                    candidates.append({
                        "title": f"{label} in {f}",
                        "severity": sev,
                        "affected_component": f,
                        "root_cause": label,
                        "confidence": "medium",
                    })
        return AgentResult(agent=self.name, candidates=candidates)


class Web3Agent(Agent):
    """Solidity-focused agent: flags reentrancy / unchecked external calls."""

    name = "web3"

    def analyze(self, task: dict[str, Any]) -> AgentResult:
        candidates = []
        files = task.get("files", [])
        for f in files:
            if not f.endswith(".sol"):
                continue
            try:
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    src = fh.read()
            except OSError:
                continue
            if re.search(r"\.call\{", src) and re.search(r"=\s*msg\.sender", src) is None:
                candidates.append({
                    "title": f"Potential reentrancy in {f}",
                    "severity": "high",
                    "affected_component": f,
                    "root_cause": "external call before state update",
                    "confidence": "low",
                })
        return AgentResult(agent=self.name, candidates=candidates)
