"""Evidence enrichment orchestration.

This layer augments already-normalized evidence with optional contextual
sources. It does not calculate risk and does not replace scanner findings.

External providers receive only the minimum non-PII lookup material required
for the enrichment operation (currently normalized domains).
"""

from __future__ import annotations

import asyncio
import os
from typing import Iterable

from utils.envutil import env_non_negative_int, env_positive_float
from utils.logging_setup import get_logger

from services.evidence.models import EvidenceRecord
from services.evidence.security_publications import (
    FirecrawlSecurityPublicationProvider,
)

logger = get_logger("EvidenceEnrichment")


async def enrich_evidence(
    records: Iterable[EvidenceRecord],
    *,
    firecrawl_api_key: str | None = None,
    firecrawl_max_results: int = 5,
) -> list[EvidenceRecord]:
    """Return base evidence plus optional contextual enrichment.

    Provider failures are isolated by the provider implementation. The base
    evidence remains intact even when enrichment is disabled or unavailable.
    """
    base = list(records)
    logger.info("[Evidence Enrichment] Starting; base_records=%d", len(base))
    api_key = (
        firecrawl_api_key
        if firecrawl_api_key is not None
        else os.getenv("FIRECRAWL_API_KEY", "")
    ).strip()

    if not api_key:
        logger.info("[Evidence Enrichment] Firecrawl disabled/not configured; skipping.")
        return base

    configured_max_results = env_non_negative_int(
        "FIRECRAWL_MAX_RESULTS",
        firecrawl_max_results,
        10,
    )
    max_results = configured_max_results or 1
    timeout_seconds = env_positive_float(
        "FIRECRAWL_TIMEOUT_SECONDS",
        20.0,
        120.0,
    )
    provider = FirecrawlSecurityPublicationProvider(
        api_key=api_key,
        max_results=max_results,
        timeout_seconds=timeout_seconds,
    )

    domains = sorted(
        {
            record.domain.strip().lower()
            for record in base
            if record.domain.strip()
        }
    )
    if not domains:
        logger.info("[Evidence Enrichment] No normalized domains available; skipping.")
        return base

    logger.info(
        "[Evidence Enrichment] Firecrawl enabled; domains=%d max_results=%d timeout=%.1fs",
        len(domains),
        max_results,
        timeout_seconds,
    )

    results = await asyncio.gather(
        *(provider.search_domain(domain) for domain in domains),
        return_exceptions=True,
    )

    merged: dict[str, EvidenceRecord] = {
        record.evidence_id: record for record in base
    }
    failed = 0
    contextual_added = 0
    for result in results:
        if isinstance(result, Exception):
            failed += 1
            logger.warning(
                "[Evidence Enrichment] Domain enrichment failed: %s",
                type(result).__name__,
            )
            continue
        for record in result:
            if record.evidence_id not in merged:
                contextual_added += 1
            merged[record.evidence_id] = record

    output = list(merged.values())
    logger.info(
        "[Evidence Enrichment] Completed; base=%d contextual_added=%d failed_domains=%d total=%d",
        len(base),
        contextual_added,
        failed,
        len(output),
    )
    return output
