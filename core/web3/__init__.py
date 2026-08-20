"""Web3 domain: Solidity security pipeline (X-Ray -> static -> audit -> invariant -> fuzz -> PoC -> finding).

Phase 6 MVP is EVM/Solidity only. The pipeline is deterministic and staged; the
AI audit step is a pluggable hook (no LLM dependency in core).
"""
from .pipeline import Web3Pipeline, PipelineStage

__all__ = ["Web3Pipeline", "PipelineStage"]
