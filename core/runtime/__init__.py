"""Runtime layer: the Runtime Interface contract + Docker backend.

The platform never talks to Docker directly — agents and skills go through a
Runtime Interface. This makes the execution backend swappable (Podman later)
without touching skills or tools.
"""
from .base import Runtime, RunError, DockerRuntime

__all__ = ["Runtime", "RunError", "DockerRuntime"]
