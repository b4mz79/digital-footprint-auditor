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


def mark_verification_unknown(record: EvidenceRecord) -> None:
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
    total_timeout_seconds: float | None = None,
) -> list[EvidenceRecord]:
    """Annotate existing evidence with scoped URL accessibility state.

    A batch-wide deadline bounds pipeline latency independently of per-URL
    timeouts. Records that do not finish within the budget remain UNKNOWN;
    this signal describes URL accessibility only, never account validity or
    target compromise.
    """
    items = list(records)
    if enabled is None:
        enabled = os.getenv("EVIDENCE_URL_VERIFICATION_ENABLED", "true").strip().lower() in {
            "1", "true", "yes", "on"
        }
    if not enabled:
        # A disabled verifier cannot vouch for a previous run's URL state.
        # Keep the evidence itself, but clear the current accessibility signal.
        for record in items:
            mark_verification_unknown(record)
        return items

    timeout = (
        timeout_seconds
        if timeout_seconds is not None
        else env_positive_float("EVIDENCE_URL_VERIFICATION_TIMEOUT_SECONDS", 12.0, 120.0)
    )
    total_timeout = (
        total_timeout_seconds
        if total_timeout_seconds is not None
        else env_positive_float(
            "EVIDENCE_URL_VERIFICATION_TOTAL_TIMEOUT_SECONDS", 120.0, 900.0
        )
    )
    if total_timeout <= 0:
        raise ValueError("total_timeout_seconds must be > 0")

    limit = (
        max(1, int(concurrency))
        if concurrency is not None
        else env_non_negative_int("EVIDENCE_URL_VERIFICATION_CONCURRENCY", 4, 16) or 1
    )

    targets: list[EvidenceRecord] = []
    for record in items:
        if isinstance(record.url, str) and record.url.strip():
            targets.append(record)
        else:
            # Malformed or absent URLs are record-local failures. They must not
            # abort the batch and invalidate verification for unrelated records.
            mark_verification_unknown(record)
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
                        mark_verification_unknown(record)
                        return

                    record.verification_scope = "url_accessibility"
                    record.verification_state = (
                        "reachable" if result.reachable else "unreachable"
                    )
                    record.verification_observed_at = _utc_now()
                    # Evidence records can be reconstructed from external or cached
                    # payloads. Treat malformed optional metadata as empty rather than
                    # allowing one record to abort gather() and downgrade every URL in
                    # this verification batch to UNKNOWN.
                    existing_metadata = (
                        record.metadata if isinstance(record.metadata, dict) else {}
                    )
                    record.metadata = {
                        **existing_metadata,
                        "url_verification": {
                            "status_code": result.status_code,
                            "redirected": result.redirected,
                            "location": result.location,
                            "content_type": result.content_type,
                        },
                    }

            tasks = {
                asyncio.create_task(verify_one(record)): record
                for record in targets
            }
            try:
                done, pending = await asyncio.wait(
                    tasks,
                    timeout=total_timeout,
                    return_when=asyncio.ALL_COMPLETED,
                )

                # Consume unexpected task exceptions individually. One malformed
                # record must not downgrade the other records in the same batch.
                for task in done:
                    record = tasks[task]
                    try:
                        task.result()
                    except asyncio.CancelledError:
                        mark_verification_unknown(record)
                    except Exception as exc:
                        logger.warning(
                            "[Evidence Verification] Unexpected task failure: %s",
                            type(exc).__name__,
                        )
                        mark_verification_unknown(record)

                if pending:
                    # Stop unfinished probes before mutating their records, so a
                    # cancelled coroutine cannot later overwrite UNKNOWN with stale
                    # reachability metadata.
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    for task in pending:
                        mark_verification_unknown(tasks[task])
                    logger.warning(
                        "[Evidence Verification] Total deadline reached; "
                        "completed=%d pending=%d total=%d timeout_seconds=%.2f",
                        len(done),
                        len(pending),
                        len(tasks),
                        total_timeout,
                    )
            finally:
                # Parent-task cancellation must propagate, but all child probes
                # must be cancelled and awaited before the shared HTTP client exits.
                unfinished = [task for task in tasks if not task.done()]
                for task in unfinished:
                    task.cancel()
                if unfinished:
                    await asyncio.gather(*unfinished, return_exceptions=True)
    except Exception as exc:
        # Client construction/setup failures can bypass the per-URL handler.
        # Do not leak old reachability metadata through the pipeline fallback.
        logger.warning(
            "[Evidence Verification] Verifier unavailable: %s",
            type(exc).__name__,
        )
        for record in targets:
            mark_verification_unknown(record)

    return items
