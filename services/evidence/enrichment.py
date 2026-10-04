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

from services.evidence.models import EvidenceRecord
from services.evidence.security_publications import (
    FirecrawlSecurityPublicationProvider,
)


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
    api_key = (
        firecrawl_api_key
        if firecrawl_api_key is not None
        else os.getenv("FIRECRAWL_API_KEY", "")
    ).strip()

    if not api_key:
        return base

    provider = FirecrawlSecurityPublicationProvider(
        api_key=api_key,
        max_results=firecrawl_max_results,
    )

    domains = sorted(
        {
            record.domain.strip().lower()
            for record in base
            if record.domain.strip()
        }
    )
    if not domains:
        return base

    results = await asyncio.gather(
        *(provider.search_domain(domain) for domain in domains),
        return_exceptions=True,
    )

    merged: dict[str, EvidenceRecord] = {
        record.evidence_id: record for record in base
    }
    for result in results:
        if isinstance(result, Exception):
            continue
        for record in result:
            merged[record.evidence_id] = record

    return list(merged.values())
