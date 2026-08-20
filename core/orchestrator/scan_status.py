"""Scan lifecycle states.

Formal scan states, used by the orchestrator to track a scan from submission
to terminal state. Exceptions from policy, runtime, agent, tool, or persistence
must update the scan state correctly.
"""
from __future__ import annotations

from enum import Enum


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"      # some work succeeded, some failed
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

    @property
    def terminal(self) -> bool:
        return self in {
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.PARTIAL,
            ScanStatus.CANCELLED,
            ScanStatus.TIMEOUT,
        }
