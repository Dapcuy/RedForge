"""Integration adapter base + config.

An adapter wraps an external tool and produces Evidence. The adapter interface
is intentionally small: configure -> run -> Evidence.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass

from core.evidence.models import Evidence, make_evidence
from core.models import Target


@dataclass
class IntegrationConfig:
    endpoint: str = ""       # e.g. Caido GraphQL endpoint or Strix endpoint
    token: str = ""
    timeout_s: int = 60


class IntegrationAdapter(abc.ABC):
    """Base class for external capability adapters."""

    name = "generic"

    def __init__(self, config: IntegrationConfig) -> None:
        self.config = config

    @abc.abstractmethod
    def run(self, target: Target, run_id: str) -> Evidence:
        """Run the external tool against a target and return Evidence."""

    def _evidence(self, run_id: str, tool: str, target: Target, raw: str) -> Evidence:
        return make_evidence(run_id=run_id, tool=tool, target=target.value, raw=raw)
