"""Evidence collection and enrichment primitives for Privacy Auditor.

This package is intentionally independent from the scan pipeline during the
foundation phase. It provides stable evidence records and optional enrichment
providers without changing existing discovery engines.
"""

from .models import EvidenceDirectness, EvidenceRecord, EvidenceRelation
from .normalizer import evidence_to_dicts, service_findings_to_evidence
from .security_publications import (
    DEFAULT_SECURITY_PUBLISHERS,
    FirecrawlSecurityPublicationProvider,
    SecurityPublicationError,
    normalize_domain,
)
from .url_verifier import URLVerification, verify_public_url

__all__ = [
    "DEFAULT_SECURITY_PUBLISHERS",
    "evidence_to_dicts",
    "EvidenceDirectness",
    "EvidenceRecord",
    "EvidenceRelation",
    "FirecrawlSecurityPublicationProvider",
    "SecurityPublicationError",
    "service_findings_to_evidence",
    "URLVerification",
    "normalize_domain",
    "verify_public_url",
]
