"""Evidence enrichment orchestration.

This service is the main Evidence Enrichment capability. It augments
already-normalized evidence with optional contextual sources. It does not
calculate risk and does not replace scanner findings.

External providers receive only the minimum non-PII lookup material required
for the enrichment operation (currently normalized domains).
"""

from __future__ import annotations

import asyncio
import os
from typing import Iterable

import httpx

from services.evidence.models import EvidenceRecord
from services.evidence.security_publications import (
    FirecrawlSecurityPublicationProvider,
)
from utils.envutil import env_non_negative_int, env_positive_float
from utils.logging_setup import get_logger

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
    domain_concurrency = env_non_negative_int(
        "FIRECRAWL_DOMAIN_CONCURRENCY",
        4,
        16,
    ) or 1
    request_concurrency = env_non_negative_int(
        "FIRECRAWL_REQUEST_CONCURRENCY",
        2,
        16,
    ) or 1
    requests_per_minute = env_non_negative_int(
        "FIRECRAWL_REQUESTS_PER_MINUTE",
        10,
        10000,
    ) or 1
    cooldown_seconds = env_positive_float(
        "FIRECRAWL_COOLDOWN_SECONDS",
        60.0,
        3600.0,
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
        "[Evidence Enrichment] Firecrawl enabled; domains=%d max_results=%d timeout=%.1fs domain_concurrency=%d request_concurrency=%d requests_per_minute=%d cooldown=%.1fs",
        len(domains),
        max_results,
        timeout_seconds,
        domain_concurrency,
        request_concurrency,
        requests_per_minute,
        cooldown_seconds,
    )

    domain_gate = asyncio.Semaphore(domain_concurrency)

    async with httpx.AsyncClient(
        follow_redirects=False,
        headers={"User-Agent": "PrivacyAuditor/Evidence"},
    ) as client:
        provider = FirecrawlSecurityPublicationProvider(
            api_key=api_key,
            max_results=max_results,
            timeout_seconds=timeout_seconds,
            client=client,
            max_concurrency=request_concurrency,
            requests_per_minute=requests_per_minute,
            cooldown_seconds=cooldown_seconds,
        )

        async def enrich_domain(domain: str):
            async with domain_gate:
                return await provider.search_domain(domain)

        # Process only one bounded domain batch at a time. The previous
        # gather-all design created one coroutine per domain even after the
        # provider entered its global cooldown. That did not create a network
        # storm (the request gate prevented that), but it did create a large
        # task/log storm. Once a provider-wide rate limit is observed, do not
        # schedule another domain batch.
        results: list[object] = []
        for start in range(0, len(domains), domain_concurrency):
            batch = domains[start : start + domain_concurrency]
            batch_results = await asyncio.gather(
                *(enrich_domain(domain) for domain in batch),
                return_exceptions=True,
            )
            results.extend(batch_results)

            if provider.cooldown_active:
                logger.warning(
                    "[Evidence Enrichment] Firecrawl cooldown active; "
                    "stopping remaining domain batches after %d/%d domains.",
                    min(start + len(batch), len(domains)),
                    len(domains),
                )
                break

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
