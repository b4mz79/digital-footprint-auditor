"""Evidence enrichment orchestration.

This service is the main Evidence Enrichment capability. It augments
already-normalized evidence with optional contextual sources. It does not
calculate risk and does not replace scanner findings.

External providers receive only the minimum non-PII lookup material required
for the enrichment operation (currently normalized domains).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from typing import Iterable

import httpx

from services.enrichment.evidence.models import EvidenceRecord, EvidenceRelation
from services.enrichment_cache import (
    enrichment_cache_enabled,
    load_enrichment_cache,
    save_enrichment_cache,
)
from services.enrichment.evidence.security_publications import (
    FirecrawlSecurityPublicationProvider,
)
from utils.envutil import env_non_negative_int, env_positive_float
from utils.logging_setup import get_logger

logger = get_logger("EvidenceEnrichment")

DEFAULT_MAX_CONTEXTUAL_RECORDS = 20
DEFAULT_MAX_CONTEXTUAL_RECORDS_PER_DOMAIN = 1


def _fingerprint_domains(domains: list[str]) -> str:
    payload = "\n".join(domains).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


async def enrich_evidence(
    records: Iterable[EvidenceRecord],
    *,
    firecrawl_api_key: str | None = None,
    firecrawl_max_results: int = 5,
    force_refresh: bool = False,
    tenant_id: str = "default",
) -> list[EvidenceRecord]:
    """Return base evidence plus optional contextual enrichment.

    Provider failures are isolated by the provider implementation. The base
    evidence remains intact even when enrichment is disabled or unavailable.
    """
    base = list(records)
    logger.info("[Evidence Enrichment] Starting; base_records=%d", len(base))

    force_refresh = bool(force_refresh)

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
    max_contextual_records = env_non_negative_int(
        "FIRECRAWL_MAX_CONTEXTUAL_RECORDS",
        DEFAULT_MAX_CONTEXTUAL_RECORDS,
        200,
    )
    max_contextual_per_domain = env_non_negative_int(
        "FIRECRAWL_MAX_CONTEXTUAL_RECORDS_PER_DOMAIN",
        DEFAULT_MAX_CONTEXTUAL_RECORDS_PER_DOMAIN,
        10,
    )
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

    cache_material = {
        "schema": 1,
        "domains": domains,
        "base_records": [record.to_dict() for record in base],
        "provider": "firecrawl_security_publication",
        "max_results": max_results,
        "timeout_seconds": timeout_seconds,
        "domain_concurrency": domain_concurrency,
        "request_concurrency": request_concurrency,
        "requests_per_minute": requests_per_minute,
        "cooldown_seconds": cooldown_seconds,
        "max_contextual_records": max_contextual_records,
        "max_contextual_per_domain": max_contextual_per_domain,
    }
    cache_payload = hashlib.sha256(
        json.dumps(
            cache_material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


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

    if enrichment_cache_enabled() and not force_refresh:
        cached_records = load_enrichment_cache(cache_payload, tenant_id=tenant_id)
        if cached_records is not None:
            try:
                cached = [
                    EvidenceRecord(
                        evidence_id=item["evidence_id"],
                        source=item["source"],
                        source_type=item["source_type"],
                        relation=EvidenceRelation(item["relation"]),
                        directness=item["directness"],
                        confidence=item["confidence"],
                        observed_at=item["observed_at"],
                        published_at=item.get("published_at"),
                        domain=item["domain"],
                        url=item["url"],
                        title=item["title"],
                        summary=item["summary"],
                        provenance=item.get("provenance") or {},
                        metadata=item.get("metadata") or {},
                        assertion_scope=item.get("assertion_scope", "unknown"),
                        verification_scope=item.get("verification_scope", "url_accessibility"),
                        verification_state=item.get("verification_state", "unknown"),
                        verification_observed_at=item.get("verification_observed_at"),
                    )
                    for item in cached_records
                ]
            except (KeyError, TypeError, ValueError):
                logger.warning("[Evidence Enrichment] Cache payload invalid; treating as miss.")
            else:
                logger.info(
                    "[Evidence Enrichment] Cache HIT; records=%d domains=%d",
                    len(cached),
                    len(domains),
                )
                return cached

    logger.info(
        "[Evidence Enrichment] Input fingerprint; domains=%d domains_sha256=%s",
        len(domains),
        _fingerprint_domains(domains),
    )
    logger.info(
        "[Evidence Enrichment] Firecrawl enabled; domains=%d max_results=%d timeout=%.1fs domain_concurrency=%d request_concurrency=%d requests_per_minute=%d cooldown=%.1fs max_contextual=%d max_per_domain=%d",
        len(domains),
        max_results,
        timeout_seconds,
        domain_concurrency,
        request_concurrency,
        requests_per_minute,
        cooldown_seconds,
        max_contextual_records,
        max_contextual_per_domain,
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

        async def enrich_domain(domain: str) -> list[EvidenceRecord]:
            async with domain_gate:
                return await provider.search_domain(domain)

        # Process only one bounded domain batch at a time. The previous
        # gather-all design created one coroutine per domain even after the
        # provider entered its global cooldown. That did not create a network
        # storm (the request gate prevented that), but it did create a large
        # task/log storm. Once a provider-wide rate limit is observed, do not
        # schedule another domain batch.
        results: list[list[EvidenceRecord] | Exception] = []
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
    contextual_candidates: list[EvidenceRecord] = []
    for result in results:
        if isinstance(result, Exception):
            failed += 1
            logger.warning(
                "[Evidence Enrichment] Domain enrichment failed: %s",
                type(result).__name__,
            )
            continue
        for record in result:
            if record.relation is EvidenceRelation.SECURITY_PUBLICATION:
                contextual_candidates.append(record)
            else:
                merged[record.evidence_id] = record

    # Enrichment is an evidence producer, so it must enforce an explicit
    # output budget before evidence reaches verification and AI payload
    # construction. Prefer newer source-published evidence, then confidence,
    # then deterministic identity. This is a quality/budget guard, not a risk
    # decision and does not discard base scanner evidence.
    unique_contextual = {
        record.evidence_id: record for record in contextual_candidates
    }
    ordered_contextual = sorted(
        unique_contextual.values(),
        key=lambda record: (
            record.published_at is not None,
            record.published_at or "",
            record.confidence,
            record.evidence_id,
        ),
        reverse=True,
    )
    selected_contextual: list[EvidenceRecord] = []
    per_domain_counts: dict[str, int] = {}
    for record in ordered_contextual:
        domain = record.domain.strip().lower()
        if per_domain_counts.get(domain, 0) >= max_contextual_per_domain:
            continue
        if len(selected_contextual) >= max_contextual_records:
            break
        selected_contextual.append(record)
        per_domain_counts[domain] = per_domain_counts.get(domain, 0) + 1

    for record in selected_contextual:
        merged[record.evidence_id] = record

    contextual_added = len(selected_contextual)
    dropped_contextual = len(unique_contextual) - contextual_added
    if dropped_contextual:
        logger.info(
            "[Evidence Enrichment] Contextual evidence budget applied; "
            "candidates=%d selected=%d dropped=%d max_total=%d max_per_domain=%d",
            len(unique_contextual),
            contextual_added,
            dropped_contextual,
            max_contextual_records,
            max_contextual_per_domain,
        )

    output = list(merged.values())

    if (
        enrichment_cache_enabled()
        and failed == 0
        and len(results) == len(domains)
        and not provider.cooldown_active
    ):
        save_enrichment_cache(
            cache_payload,
            [record.to_dict() for record in output],
            tenant_id=tenant_id,
        )

    logger.info(
        "[Evidence Enrichment] Completed; base=%d contextual_added=%d failed_domains=%d total=%d",
        len(base),
        contextual_added,
        failed,
        len(output),
    )
    return output
