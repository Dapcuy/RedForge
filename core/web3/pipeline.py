"""Web3/Solidity security pipeline.

Stages (methodology from Pashov):

    X-Ray -> Threat Model -> Entrypoint -> Invariant -> Static -> AI review
           -> Fuzzing -> PoC -> Validation

The MVP implements the deterministic, evidence-producing stages. AI review and
fuzzing are pluggable hooks so the core stays agent-agnostic and dependency-free.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from ..evidence.models import Evidence, make_evidence
from ..findings.engine import FindingEngine
from ..findings.models import Severity


class PipelineStage(str, Enum):
    XRAY = "x-ray"
    THREAT_MODEL = "threat-model"
    ENTRYPOINT = "entrypoint"
    INVARIANT = "invariant"
    STATIC = "static"
    AI_REVIEW = "ai-review"
    FUZZING = "fuzzing"
    POC = "poc"
    VALIDATION = "validation"


@dataclass
class ContractArtifact:
    name: str
    path: str
    functions: list[str] = field(default_factory=list)
    state_vars: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)


@dataclass
class XRayResult:
    contracts: list[ContractArtifact]
    summary: dict[str, Any] = field(default_factory=dict)


_FUNC_RE = re.compile(r"function\s+(\w+)\s*\(")
_STATEVAR_RE = re.compile(
    r"(?:mapping\([^)]*\)|uint\d*|int\d*|bool|address|bytes\d*|string|contract|struct\s+\w+)\s+"
    r"(?:public\s+|private\s+|internal\s+)?(\w+)\s*[;=]"
)
_EXT_CALL_RE = re.compile(r"\.call\{|\.call\(|\.delegatecall|\.transfer\(|\.send\(")


def xray_solidity(root: str) -> XRayResult:
    """X-Ray: enumerate contracts, functions, state vars, and external calls."""
    contracts: list[ContractArtifact] = []
    for dirpath, _dirs, files in os.walk(root):
        if any(s in {".git", "node_modules", "lib", "out", "cache"} for s in dirpath.split(os.sep)):
            continue
        for fname in files:
            if not fname.endswith(".sol"):
                continue
            path = os.path.join(dirpath, fname)
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                src = fh.read()
            for cname in re.findall(r"contract\s+(\w+)", src):
                contracts.append(ContractArtifact(
                    name=cname,
                    path=path,
                    functions=_FUNC_RE.findall(src),
                    state_vars=_STATEVAR_RE.findall(src),
                    external_calls=_EXT_CALL_RE.findall(src),
                ))
    return XRayResult(contracts=contracts)


class Web3Pipeline:
    def __init__(self, root: str, run_id: str) -> None:
        self.root = root
        self.run_id = run_id
        self.stages_run: list[PipelineStage] = []
        self.evidence: list[Evidence] = []
        self.engine = FindingEngine()
        # pluggable hooks (agent-agnostic; no LLM import in core)
        self.ai_review_hook: Callable[[ContractArtifact], list[dict]] | None = None
        self.fuzz_hook: Callable[[ContractArtifact], str] | None = None

    def _emit(self, stage: PipelineStage, tool: str, raw: str) -> Evidence:
        self.stages_run.append(stage)
        ev = make_evidence(run_id=self.run_id, tool=tool, target=self.root, raw=raw)
        self.evidence.append(ev)
        return ev

    def run(self) -> list:
        """Execute the pipeline; returns the judged findings list."""
        # 1. X-Ray
        xray = xray_solidity(self.root)
        self._emit(PipelineStage.XRAY, "xray", str([c.to_dict() if hasattr(c, "to_dict") else c.name for c in xray.contracts]))

        # 2. Static analysis (slither signal) — deterministic heuristic MVP
        for c in xray.contracts:
            if c.external_calls and c.state_vars:
                # classic reentrancy shape: external call + state mutation
                self.engine.add_candidate(
                    title=f"Potential reentrancy in {c.name}",
                    severity=Severity.HIGH,
                    affected_component=c.name,
                    root_cause="external call before state update",
                    evidence_ids=[e.id for e in self.evidence if e.tool == "xray"],
                )

        # 3. AI review hook (optional, pluggable)
        if self.ai_review_hook:
            for c in xray.contracts:
                for cand in self.ai_review_hook(c):
                    self.engine.add_candidate(
                        title=cand.get("title", "AI finding"),
                        severity=Severity(cand.get("severity", "medium")),
                        affected_component=c.name,
                        root_cause=cand.get("root_cause", ""),
                    )

        # 4. Fuzz hook (optional)
        if self.fuzz_hook:
            for c in xray.contracts:
                raw = self.fuzz_hook(c)
                self._emit(PipelineStage.FUZZING, "echidna", raw)

        return self.engine.judge()
