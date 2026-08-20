"""Integration adapters for external capability tools (Caido, Strix).

Each adapter turns an external tool into an evidence-producing capability.
Adapters are plug-ins: the core imports nothing from here.
"""
from .base import IntegrationAdapter, IntegrationConfig
from .caido import CaidoAdapter
from .strix import StrixAdapter

__all__ = ["CaidoAdapter", "IntegrationAdapter", "IntegrationConfig", "StrixAdapter"]
