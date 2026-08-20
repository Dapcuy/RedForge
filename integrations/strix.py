"""Strix adapter.

Strix is a dynamic security testing capability: source analysis + running
target -> dynamic security testing. This adapter submits a target to a Strix
endpoint and records the dynamic-testing evidence it returns.

MVP: if no endpoint is configured, it records the target + a "stub" note so the
pipeline remains functional and evidence is always captured.
"""
from __future__ import annotations

import json
import urllib.request

from core.evidence.models import Evidence
from core.models import Target

from .base import IntegrationAdapter


class StrixAdapter(IntegrationAdapter):
    name = "strix"

    def run(self, target: Target, run_id: str) -> Evidence:
        if not self.config.endpoint:
            return self._evidence(
                run_id, "strix", target,
                json.dumps({"status": "stub", "target": target.value, "note": "set integration endpoint"}),
            )

        payload = json.dumps({"target": target.value}).encode()
        req = urllib.request.Request(
            self.config.endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_s) as resp:
                body = resp.read().decode()
        except Exception as exc:
            return self._evidence(run_id, "strix", target, json.dumps({"error": str(exc)}))

        return self._evidence(run_id, "strix", target, body)
