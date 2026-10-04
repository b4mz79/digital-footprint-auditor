"""Evidence collection and enrichment primitives for Privacy Auditor.

The package keeps evidence normalization/enrichment separate from risk scoring
and AI interpretation. Existing discovery engines remain unchanged.
"""

from .enrichment import enrich_evidence
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
    "enrich_evidence",
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
