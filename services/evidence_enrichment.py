"""Evidence enrichment orchestration.

This module is the main Evidence Enrichment capability. It augments
already-normalized evidence with optional contextual sources. It does not
calculate risk and does not replace scanner findings.

External providers receive only the minimum non-PII lookup material required
for the enrichment operation (currently normalized domains).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from typing import Iterable

import httpx

from services.enrichment.evidence.models import EvidenceDirectness, EvidenceRecord, EvidenceRelation
from cache_security import load_encrypted_json, save_encrypted_json
from utils.cache_identity import hmac_identity, tenant_identity
from utils.envutil import env_bool
from utils.paths import resolve_data_path
from services.enrichment.evidence.security_publications import (
    CONTEXTUAL_FILTER_NAME,
    DEFAULT_SECURITY_PUBLISHERS,
    FirecrawlSecurityPublicationProvider,
)
from utils.envutil import env_non_negative_int, env_positive_float
from utils.logging_setup import get_logger

logger = get_logger("EvidenceEnrichment")

# Module-owned persistent cache.
ENRICHMENT_CACHE_ENABLED_ENV = "EVIDENCE_ENRICHMENT_CACHE_ENABLED"
ENRICHMENT_CACHE_SCHEMA_VERSION = 2
ENRICHMENT_CACHE_MAX_AGE_HOURS = 12.0
ENRICHMENT_CACHE_DIR = resolve_data_path(
    os.getenv("EVIDENCE_ENRICHMENT_CACHE_DIR"),
    "cache/enrichment",
)


def enrichment_cache_enabled() -> bool:
    return env_bool(ENRICHMENT_CACHE_ENABLED_ENV, False)


def _cache_path(input_fingerprint: str, tenant_id: str) -> Path:
    tenant_dir = ENRICHMENT_CACHE_DIR / tenant_identity(tenant_id)
    tenant_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        try:
            os.chmod(tenant_dir, 0o700)
        except OSError:
            pass
    identity = hmac_identity(input_fingerprint)
    return tenant_dir / f"enrichment_cache_{identity}.json"


def load_enrichment_cache(
    input_fingerprint: str,
    *,
    tenant_id: str = "default",
    max_age_hours: float = ENRICHMENT_CACHE_MAX_AGE_HOURS,
) -> list[dict[str, Any]] | None:
    if max_age_hours < 0:
        raise ValueError("max_age_hours must be >= 0")
    try:
        data = load_encrypted_json(
            _cache_path(input_fingerprint, tenant_id),
            tenant_id=tenant_id,
            max_age_seconds=int(max_age_hours * 3600),
        )
        if not isinstance(data, dict):
            return None
        if data.get("cache_schema_version") != ENRICHMENT_CACHE_SCHEMA_VERSION:
            return None
        if data.get("input_fingerprint") != input_fingerprint:
            return None
        records = data.get("records")
        if not isinstance(records, list) or not all(isinstance(x, dict) for x in records):
            return None
        return records
    except Exception:
        return None


def save_enrichment_cache(
    input_fingerprint: str,
    records: list[dict[str, Any]],
    *,
    tenant_id: str = "default",
) -> None:
    if not isinstance(records, list):
        raise TypeError("records must be a list")
    payload = {
        "cache_schema_version": ENRICHMENT_CACHE_SCHEMA_VERSION,
        "input_fingerprint": input_fingerprint,
        "records": [item for item in records if isinstance(item, dict)],
    }
    try:
        path = _cache_path(input_fingerprint, tenant_id)
        save_encrypted_json(path, payload, tenant_id=tenant_id)
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except Exception:
        return


def _cache_record_matches_publisher(record: EvidenceRecord) -> bool:
    """Validate cached URL provenance against the configured publisher contract."""
    expected_domain = dict(DEFAULT_SECURITY_PUBLISHERS).get(record.source)
    if not expected_domain or not isinstance(record.url, str) or len(record.url) > 4096:
        return False
    try:
        parsed = urlsplit(record.url)
        # Accessing .port rejects malformed and out-of-range port values.
        _ = parsed.port
        hostname = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    expected = expected_domain.lower().lstrip(".")
    return hostname == expected or hostname.endswith("." + expected)


def _publication_datetime_utc(value: str | None) -> datetime:
    """Return a comparable UTC timestamp for ordering publication dates.

    Date-only values are interpreted as midnight UTC for ordering only; the
    original source timestamp remains unchanged in the evidence record.
    """
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


DEFAULT_MAX_CONTEXTUAL_RECORDS = 20
DEFAULT_MAX_CONTEXTUAL_RECORDS_PER_DOMAIN = 1
DEFAULT_MAX_ENRICHMENT_DOMAINS = 100
DEFAULT_ENRICHMENT_TIMEOUT_SECONDS = 120.0


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
    max_domains = env_non_negative_int(
        "FIRECRAWL_MAX_DOMAINS",
        DEFAULT_MAX_ENRICHMENT_DOMAINS,
        1000,
    ) or 1
    total_timeout_seconds = env_positive_float(
        "FIRECRAWL_TOTAL_TIMEOUT_SECONDS",
        DEFAULT_ENRICHMENT_TIMEOUT_SECONDS,
        900.0,
    )

    # Records can be reconstructed or mutated at integration boundaries.
    # Keep malformed base evidence, but never let an invalid domain abort
    # enrichment for otherwise valid records in the same batch.
    discovered_domains = sorted(
        {
            record.domain.strip().lower()
            for record in base
            if isinstance(record.domain, str) and record.domain.strip()
        }
    )
    domains = discovered_domains[:max_domains]
    if len(discovered_domains) > len(domains):
        logger.warning(
            "[Evidence Enrichment] Domain budget applied; discovered=%d selected=%d cap=%d",
            len(discovered_domains),
            len(domains),
            max_domains,
        )
    cache_material = {
        "schema": 1,
        "cache_schema_version": ENRICHMENT_CACHE_SCHEMA_VERSION,
        "contextual_filter": CONTEXTUAL_FILTER_NAME,
        "publishers": list(DEFAULT_SECURITY_PUBLISHERS),
        "domains": domains,
        "provider": "firecrawl_security_publication",
        "max_results": max_results,
        "timeout_seconds": timeout_seconds,
        "domain_concurrency": domain_concurrency,
        "request_concurrency": request_concurrency,
        "requests_per_minute": requests_per_minute,
        "cooldown_seconds": cooldown_seconds,
        "max_domains": max_domains,
        "total_timeout_seconds": total_timeout_seconds,
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
                        directness=EvidenceDirectness(item["directness"]),
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
                # The cache contract is narrower than the EvidenceRecord schema:
                # only provider-owned contextual publications may be restored.
                # Reject the entire entry on semantic mismatch rather than
                # partially merging stale or scanner-like records into this scan.
                # Reject malformed serialized fields before records reach merge logic.
                if any(
                    not isinstance(record.evidence_id, str)
                    or not record.evidence_id.strip()
                    or not isinstance(record.source, str)
                    or not isinstance(record.source_type, str)
                    or not isinstance(record.domain, str)
                    or not isinstance(record.url, str)
                    or not isinstance(record.title, str)
                    or not isinstance(record.summary, str)
                    or not isinstance(record.provenance, dict)
                    or not isinstance(record.metadata, dict)
                    for record in cached
                ):
                    raise ValueError("Cache contains malformed evidence fields")

                if any(
                    record.source_type != "security_publication"
                    or record.relation is not EvidenceRelation.SECURITY_PUBLICATION
                    or record.directness is not EvidenceDirectness.CONTEXTUAL
                    or record.assertion_scope != "security_publication_context_only"
                    or not isinstance(record.domain, str)
                    or record.domain.strip().lower() not in domains
                    or not isinstance(record.provenance, dict)
                    or record.provenance.get("provider") != "firecrawl_search"
                    or record.provenance.get("query_scope") != "domain_only"
                    or record.provenance.get("relevance_filter") != CONTEXTUAL_FILTER_NAME
                    or record.provenance.get("assertion_scope")
                    != record.assertion_scope
                    or record.provenance.get("publisher_domain")
                    != dict(DEFAULT_SECURITY_PUBLISHERS).get(record.source)
                    or not _cache_record_matches_publisher(record)
                    for record in cached
                ):
                    raise ValueError("Cache contains records outside the contextual evidence contract")
            except (KeyError, TypeError, ValueError):
                logger.warning("[Evidence Enrichment] Cache payload invalid; treating as miss.")
            else:
                # The cache stores provider-owned enrichment records only.
                # Always retain the current scan's base evidence so cached
                # observations/verifications cannot overwrite fresher state.
                merged_cached: dict[str, EvidenceRecord] = {
                    record.evidence_id: record for record in base
                }
                for record in cached:
                    if record.evidence_id not in merged_cached:
                        merged_cached[record.evidence_id] = record
                output_cached = list(merged_cached.values())
                logger.info(
                    "[Evidence Enrichment] Cache HIT; enrichment_records=%d base_records=%d total=%d domains=%d",
                    len(cached),
                    len(base),
                    len(output_cached),
                    len(domains),
                )
                return output_cached

    logger.info(
        "[Evidence Enrichment] Input fingerprint; domains=%d domains_sha256=%s",
        len(domains),
        _fingerprint_domains(domains),
    )
    logger.info(
        "[Evidence Enrichment] Firecrawl enabled; domains=%d discovered_domains=%d domain_cap=%d total_timeout=%.1fs max_results=%d request_timeout=%.1fs domain_concurrency=%d request_concurrency=%d requests_per_minute=%d cooldown=%.1fs max_contextual=%d max_per_domain=%d",
        len(domains),
        len(discovered_domains),
        max_domains,
        total_timeout_seconds,
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
        loop = asyncio.get_running_loop()
        deadline = loop.time() + total_timeout_seconds
        for start in range(0, len(domains), domain_concurrency):
            remaining = deadline - loop.time()
            if remaining <= 0:
                logger.warning(
                    "[Evidence Enrichment] Total runtime budget exhausted between batches; completed_domains=%d/%d.",
                    len(results),
                    len(domains),
                )
                break

            batch = domains[start : start + domain_concurrency]
            tasks = [
                asyncio.create_task(enrich_domain(domain))
                for domain in batch
            ]
            done, pending = await asyncio.wait(tasks, timeout=remaining)

            # Retain completed results even when another task in the same batch
            # reaches the global deadline. Pending provider calls are cancelled;
            # base evidence is never discarded by an enrichment timeout.
            for task in done:
                try:
                    results.append(task.result())
                except asyncio.CancelledError:
                    results.append(RuntimeError("Domain enrichment task was cancelled"))
                except Exception as exc:
                    results.append(exc)

            if pending:
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                logger.warning(
                    "[Evidence Enrichment] Total runtime budget reached; completed_domains=%d/%d. Returning partial enrichment with base evidence intact.",
                    len(results),
                    len(domains),
                )
                break

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
            # Scanner/base evidence is authoritative for a colliding identity.
            # Keep provider output from replacing it or consuming contextual budget.
            if record.evidence_id in merged:
                continue
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
            _publication_datetime_utc(record.published_at),
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
        and not getattr(provider, "had_failures", False)
    ):
        save_enrichment_cache(
            cache_payload,
            [record.to_dict() for record in selected_contextual],
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
