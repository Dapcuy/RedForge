"""Multi-agent layer: agent interface + dispatcher.

RedForge is agent-agnostic. This layer defines the Agent contract and a
dispatcher that fans work out to domain agents and aggregates results through
the Finding engine. Core imports nothing from here.
"""
from .interface import Agent, AgentResult
from .dispatcher import Dispatcher, AgentSpec

__all__ = ["Agent", "AgentResult", "Dispatcher", "AgentSpec"]
