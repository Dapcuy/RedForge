"""Evidence layer: capture, normalize, and store tool output as evidence."""
from .models import Evidence, EvidenceType
from .normalizer import normalize_evidence
from .store import EvidenceStore

__all__ = ["Evidence", "EvidenceStore", "EvidenceType", "normalize_evidence"]
