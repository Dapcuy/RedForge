"""Evidence layer: capture, normalize, and store tool output as evidence."""
from .models import Evidence, EvidenceType
from .store import EvidenceStore
from .normalizer import normalize_evidence

__all__ = ["Evidence", "EvidenceType", "EvidenceStore", "normalize_evidence"]
