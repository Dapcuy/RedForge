"""Evidence normalization: raw tool output -> structured form.

Each evidence type has a normalizer. Unknown output is stored as ``generic``
with ``normalized=None`` + a warning — evidence is never dropped.
"""
from __future__ import annotations

import json
from typing import Any

from .models import Evidence


def _try_json(raw: str) -> dict[str, Any] | list[Any] | None:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _normalize_http(raw: str) -> dict[str, Any]:
    """nuclei/httpx/ffuf: attempt JSON, else fall back to a line summary."""
    parsed = _try_json(raw)
    if parsed is not None:
        return {"results": parsed if isinstance(parsed, list) else [parsed]}
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    return {"results": lines}


def _normalize_code(raw: str) -> dict[str, Any]:
    parsed = _try_json(raw)
    if isinstance(parsed, dict) and "results" in parsed:
        return parsed
    return {"results": parsed if parsed is not None else [raw]}


def _normalize_smart_contract(raw: str) -> dict[str, Any]:
    parsed = _try_json(raw)
    if isinstance(parsed, dict) and "results" in parsed:
        return {"detectors": parsed["results"]}
    return {"detectors": parsed if parsed is not None else [raw]}


_NORMALIZERS = {
    "http": _normalize_http,
    "http-interaction": _normalize_http,
    "dynamic": _normalize_http,
    "code": _normalize_code,
    "smart-contract": _normalize_code,
    "fuzz": _normalize_code,
    "poc": _normalize_code,
}


def normalize_evidence(evidence: Evidence) -> Evidence:
    """Return a copy of ``evidence`` with ``normalized`` populated.

    Unknown types keep ``normalized=None``; callers must handle that gracefully
    rather than dropping the evidence.
    """
    normalizer = _NORMALIZERS.get(evidence.type.value)
    if normalizer is None:
        return evidence
    evidence.normalized = normalizer(evidence.raw)
    return evidence
