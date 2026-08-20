"""Evidence Store: an append-only, in-memory store of evidence records.

Real persistence (SQLite/file) can be swapped in later; the store's contract is
append + iterate, and evidence is never deleted — only superseded.
"""
from __future__ import annotations

from typing import Iterator

from .models import Evidence


class EvidenceStore:
    def __init__(self) -> None:
        self._items: list[Evidence] = []
        self._by_id: dict[str, Evidence] = {}

    def add(self, evidence: Evidence) -> None:
        self._items.append(evidence)
        self._by_id[evidence.id] = evidence

    def get(self, evidence_id: str) -> Evidence | None:
        return self._by_id.get(evidence_id)

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[Evidence]:
        return iter(self._items)

    def by_tool(self, tool: str) -> list[Evidence]:
        return [e for e in self._items if e.tool == tool]

    def by_target(self, target: str) -> list[Evidence]:
        return [e for e in self._items if e.target == target]
