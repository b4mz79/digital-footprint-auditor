"""Verify reachability of URLs already present in evidence records.

This is an evidence-quality/provenance signal only. It does not verify source
trust, publication claims, target exposure, vulnerabilities, or website
security. Redirects are observed but never followed automatically.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Iterable

import httpx

from services.enrichment.evidence.models import EvidenceRecord
from services.enrichment.evidence.url_verifier import verify_public_url
from utils.envutil import env_non_negative_int, env_positive_float
from utils.logging_setup import get_logger

logger = get_logger("EvidenceVerification")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mark_verification_unknown(record: EvidenceRecord) -> None:
    """Clear stale verification state when the current URL cannot be verified."""
    record.verification_scope = "url_accessibility"
    record.verification_state = "unknown"
    record.verification_observed_at = None
    metadata = dict(record.metadata) if isinstance(record.metadata, dict) else {}
    metadata.pop("url_verification", None)
    record.metadata = metadata


async def verify_evidence_records(
    records: Iterable[EvidenceRecord],
    *,
    enabled: bool | None = None,
    timeout_seconds: float | None = None,
    concurrency: int | None = None,
) -> list[EvidenceRecord]:
    """Annotate existing evidence with scoped URL accessibility state."""
    items = list(records)
    if enabled is None:
        enabled = os.getenv("EVIDENCE_URL_VERIFICATION_ENABLED", "true").strip().lower() in {
            "1", "true", "yes", "on"
        }
    if not enabled:
        # A disabled verifier cannot vouch for a previous run's URL state.
        # Keep the evidence itself, but clear the current accessibility signal.
        for record in items:
            _mark_verification_unknown(record)
        return items

    timeout = (
        timeout_seconds
        if timeout_seconds is not None
        else env_positive_float("EVIDENCE_URL_VERIFICATION_TIMEOUT_SECONDS", 12.0, 120.0)
    )
    limit = (
        max(1, int(concurrency))
        if concurrency is not None
        else env_non_negative_int("EVIDENCE_URL_VERIFICATION_CONCURRENCY", 4, 16) or 1
    )

    targets: list[EvidenceRecord] = []
    for record in items:
        if record.url.strip():
            targets.append(record)
        else:
            # A previous URL result must not survive if this record no longer
            # has a URL that can be checked in the current verification pass.
            _mark_verification_unknown(record)
    if not targets:
        return items

    gate = asyncio.Semaphore(limit)
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": "PrivacyAuditor/EvidenceVerifier"},
        ) as client:

            async def verify_one(record: EvidenceRecord) -> None:
                async with gate:
                    try:
                        result = await verify_public_url(
                            record.url,
                            timeout_seconds=timeout,
                            client=client,
                        )
                    except Exception as exc:
                        # Verification is an optional quality signal. A failure for
                        # one URL must not cancel verification of unrelated records.
                        # Keep the record explicitly UNKNOWN rather than inferring
                        # reachability from the failure.
                        logger.warning(
                            "[Evidence Verification] URL verification failed: %s",
                            type(exc).__name__,
                        )
                        _mark_verification_unknown(record)
                        return

                    record.verification_scope = "url_accessibility"
                    record.verification_state = (
                        "reachable" if result.reachable else "unreachable"
                    )
                    record.verification_observed_at = _utc_now()
                    record.metadata = {
                        **record.metadata,
                        "url_verification": {
                            "status_code": result.status_code,
                            "redirected": result.redirected,
                            "location": result.location,
                            "content_type": result.content_type,
                        },
                    }

            await asyncio.gather(*(verify_one(record) for record in targets))
    except Exception as exc:
        # Client construction/setup failures can bypass the per-URL handler.
        # Do not leak old reachability metadata through the pipeline fallback.
        logger.warning(
            "[Evidence Verification] Verifier unavailable: %s",
            type(exc).__name__,
        )
        for record in targets:
            _mark_verification_unknown(record)

    return items
