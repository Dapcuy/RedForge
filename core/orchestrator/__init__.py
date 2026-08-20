"""Orchestrator: plan and drive the pipeline (single-agent first).

Phase 4 introduces the code-security orchestration model inspired by
open·kritt:

    repository -> break into focused tasks -> parallel agents -> research
               -> dedup -> validate -> prioritize -> report

The orchestrator coordinates profiling, skill resolution, and task planning.
It does NOT do multi-agent dispatch yet (that is Phase 8); the MVP is a
deterministic single-agent planner.
"""
from .planner import (
    Plan,
    Task,
    break_repository_into_tasks,
)
from .scan import Orchestrator, ScanResult

__all__ = ["Orchestrator", "Plan", "ScanResult", "Task", "break_repository_into_tasks"]
