"""Runtime layer: the Runtime Interface contract + Docker backend.

The platform never talks to Docker directly — agents and skills go through a
Runtime Interface. This makes the execution backend swappable (Podman later)
without touching skills or tools.
"""
from .base import DockerRuntime, RunError, Runtime

__all__ = ["DockerRuntime", "RunError", "Runtime"]
