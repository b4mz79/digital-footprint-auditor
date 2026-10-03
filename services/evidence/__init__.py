"""Evidence collection and enrichment primitives for Privacy Auditor.

This package is intentionally independent from the scan pipeline during the
foundation phase. It provides stable evidence records and optional enrichment
providers without changing existing discovery engines.
"""

from .models import EvidenceDirectness, EvidenceRecord, EvidenceRelation
from .security_publications import (
    DEFAULT_SECURITY_PUBLISHERS,
    FirecrawlSecurityPublicationProvider,
    SecurityPublicationError,
    normalize_domain,
)

__all__ = [
    "DEFAULT_SECURITY_PUBLISHERS",
    "EvidenceDirectness",
    "EvidenceRecord",
    "EvidenceRelation",
    "FirecrawlSecurityPublicationProvider",
    "SecurityPublicationError",
    "normalize_domain",
]
