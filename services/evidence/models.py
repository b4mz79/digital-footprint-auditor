"""Stable evidence records used by enrichment and future risk lineage."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
from typing import Any


class EvidenceRelation(str, Enum):
    """How an evidence item relates to the audited subject."""

    DIRECT_TARGET = "direct_target"
    TARGET_RESOURCE = "target_resource"
    SECURITY_PUBLICATION = "security_publication"
    DOMAIN_CONTEXT = "domain_context"
    VERIFICATION = "verification"


class EvidenceDirectness(str, Enum):
    """Whether the evidence is directly about the target."""

    DIRECT = "direct"
    INDIRECT = "indirect"
    CONTEXTUAL = "contextual"
    UNKNOWN = "unknown"


VERIFICATION_SCOPES = ("url_accessibility",)
VERIFICATION_STATES = ("reachable", "unreachable", "unknown")


@dataclass(slots=True)
class EvidenceRecord:
    """A provenance-preserving, machine-readable evidence item.

    The record deliberately separates target relevance from source reliability.
    A trusted publication can still be only contextual evidence for a specific
    person's exposure.
    """

    evidence_id: str
    source: str
    source_type: str
    relation: EvidenceRelation
    directness: EvidenceDirectness
    confidence: float
    observed_at: str
    published_at: str | None
    domain: str
    url: str
    title: str
    summary: str
    provenance: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Explicit semantic contract for the assertion represented by this record.
    # This is not a risk score and must never be interpreted as one.
    assertion_scope: str = "unknown"
    # Verification is deliberately scoped. "url_accessibility" means only that
    # the stored URL was checked for HTTP reachability; it does not verify the
    # source, claim, or target exposure.
    verification_scope: str = "url_accessibility"
    verification_state: str = "unknown"
    verification_observed_at: str | None = None

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.assertion_scope = str(self.assertion_scope or "unknown").strip() or "unknown"
        self.verification_scope = (
            str(self.verification_scope or "url_accessibility").strip()
            or "url_accessibility"
        )
        self.verification_state = (
            str(self.verification_state or "unknown").strip().lower() or "unknown"
        )
        if self.verification_scope not in VERIFICATION_SCOPES:
            raise ValueError(f"Unsupported verification scope: {self.verification_scope}")
        if self.verification_state not in VERIFICATION_STATES:
            raise ValueError(f"Unsupported verification state: {self.verification_state}")
        if self.verification_state == "unknown":
            self.verification_observed_at = None

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable evidence without losing enum semantics."""
        data = asdict(self)
        data["relation"] = self.relation.value
        data["directness"] = self.directness.value
        return data


def make_evidence_id(
    *,
    source: str,
    source_type: str,
    domain: str,
    url: str,
    title: str = "",
) -> str:
    """Create a deterministic identifier from provenance, never from PII."""
    material = "".join(
        [
            source.strip().lower(),
            source_type.strip().lower(),
            domain.strip().lower(),
            url.strip(),
            title.strip(),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
