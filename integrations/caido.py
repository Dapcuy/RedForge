"""Caido adapter.

Caido is an HTTP/web traffic analysis *capability*, not AI. This adapter turns
Caido's recorded HTTP interactions into evidence.

MVP: connects to a Caido instance's GraphQL API to pull recent requests for a
target. If no endpoint is configured, it records an empty interaction and notes
the requirement, so the pipeline never crashes on a missing tool.
"""
from __future__ import annotations

import json
import urllib.request

from core.evidence.models import Evidence
from core.models import Target

from .base import IntegrationAdapter


class CaidoAdapter(IntegrationAdapter):
    name = "caido"

    def run(self, target: Target, run_id: str) -> Evidence:
        if not self.config.endpoint:
            return self._evidence(
                run_id, "caido", target,
                json.dumps({"status": "unconfigured", "note": "set integration endpoint"}),
            )

        # Query Caido GraphQL for host metadata (safe, read-only).
        query = {
            "query": "query { sitemap { edges { node { host } } } }"
        }
        req = urllib.request.Request(
            self.config.endpoint,
            data=json.dumps(query).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_s) as resp:
                body = resp.read().decode()
        except Exception as exc:  # network/connection errors -> evidence, not crash
            return self._evidence(run_id, "caido", target, json.dumps({"error": str(exc)}))

        return self._evidence(run_id, "caido", target, body)
