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

    targets = [record for record in items if record.url.strip()]
    if not targets:
        return items

    gate = asyncio.Semaphore(limit)
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
                    record.verification_scope = "url_accessibility"
                    record.verification_state = "unknown"
                    record.verification_observed_at = None
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

    return items
