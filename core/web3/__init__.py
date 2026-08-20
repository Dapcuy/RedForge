"""Web3 domain: Solidity security pipeline (X-Ray -> static -> audit -> invariant -> fuzz -> PoC -> finding).

Phase 6 MVP is EVM/Solidity only. The pipeline is deterministic and staged; the
AI audit step is a pluggable hook (no LLM dependency in core).
"""
from .pipeline import PipelineStage, Web3Pipeline

__all__ = ["PipelineStage", "Web3Pipeline"]
