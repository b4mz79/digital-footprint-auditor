"""Normalize scanner findings into provenance-preserving evidence records.

This layer does not calculate risk. It converts findings already produced by the
existing scanners into a stable representation that can later be verified,
enriched, scored, and explained.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Iterable

from services.evidence.models import (
    EvidenceDirectness,
    EvidenceRecord,
    EvidenceRelation,
    make_evidence_id,
)
from utils.domains import root_domain

_MAX_TEXT = 512
_MAX_SUMMARY = 2_000
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9_.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b")
_LONG_PHONE_RE = re.compile(r"(?<!\w)\+?[0-9][0-9 .()\-]{7,}[0-9](?!\w)")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _redact_text(value: Any, limit: int) -> str:
    text = _text(value, limit)
    text = _EMAIL_RE.sub("[EMAIL_REDACTED]", text)
    text = _LONG_PHONE_RE.sub("[PHONE_REDACTED]", text)
    return text[:limit]


def _source_type(source: str) -> str:
    normalized = source.casefold()
    if "osint" in normalized or "holehe" in normalized:
        return "osint"
    if "imap" in normalized or "gmail" in normalized:
        return "imap"
    return "scanner"


def _normalize_observed_domain(value: Any) -> str:
    domain = _text(value, 253).lower().rstrip(".")
    if not domain or "@" in domain or any(ch.isspace() for ch in domain):
        return ""
    if not _DOMAIN_RE.fullmatch(domain):
        return ""
    return root_domain(domain)


def service_findings_to_evidence(
    findings: Iterable[dict[str, Any]],
    *,
    observed_at: str | None = None,
) -> list[EvidenceRecord]:
    """Convert existing service-discovery findings into target-linked evidence.

    Existing OSINT/IMAP findings describe an observed association between the
    audited target and a service/domain. They do not assert compromise.
    """
    observed = observed_at or _utc_now()
    evidence: list[EvidenceRecord] = []
    seen: set[str] = set()

    for item in findings:
        if not isinstance(item, dict):
            continue

        domain = _normalize_observed_domain(item.get("domain"))
        if not domain:
            continue

        name = _redact_text(item.get("name"), _MAX_TEXT) or domain
        source = _redact_text(item.get("source"), _MAX_TEXT) or "Unknown scanner"
        subject = _redact_text(item.get("subject"), _MAX_SUMMARY)
        source_type = _source_type(source)

        evidence_id = make_evidence_id(
            source=source,
            source_type=source_type,
            domain=domain,
            url="",
            title=name,
        )
        if evidence_id in seen:
            continue
        seen.add(evidence_id)

        evidence.append(
            EvidenceRecord(
                evidence_id=evidence_id,
                source=source,
                source_type=source_type,
                relation=EvidenceRelation.TARGET_RESOURCE,
                directness=EvidenceDirectness.DIRECT,
                confidence=0.80,
                observed_at=observed,
                published_at=None,
                domain=domain,
                url="",
                title=f"Target-associated service: {name}",
                summary=(
                    subject
                    or "Existing scanner reported an association between the target and this service."
                ),
                provenance={
                    "provider": source_type,
                    "normalizer": "service_findings_to_evidence",
                    # Backward-compatible provenance projection: the explicit
                    # EvidenceRecord field remains the semantic authority.
                    "assertion_scope": "service_association_only",
                },
                assertion_scope="service_association_only",
                metadata={
                    "finding_type": "service_discovery",
                    "service_name": name,
                    "scanner_source": source,
                },
            )
        )

    return evidence


def evidence_to_dicts(records: Iterable[EvidenceRecord]) -> list[dict[str, Any]]:
    """Serialize records for pipeline state / UI transport."""
    return [record.to_dict() for record in records]
