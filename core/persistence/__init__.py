"""Persistence layer: repository interfaces (Protocols) + SQLite backend.

The core depends only on these Protocols, never on SQLite. A different backend
can be swapped in by implementing the same interfaces. Large raw artifacts are
stored outside the database (content-addressed on disk) and referenced by
path/hash/metadata.
"""
from .protocols import (
    AgentRunRepository,
    ArtifactRepository,
    EvidenceRepository,
    FindingRepository,
    ProjectRepository,
    ScanRepository,
    TargetRepository,
    TaskRepository,
    ToolRunRepository,
)
from .store import BlobStore, SqliteStore

__all__ = [
    "AgentRunRepository",
    "ArtifactRepository",
    "BlobStore",
    "EvidenceRepository",
    "FindingRepository",
    "ProjectRepository",
    "ScanRepository",
    "SqliteStore",
    "TargetRepository",
    "TaskRepository",
    "ToolRunRepository",
]
