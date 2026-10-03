from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx
import pytest

from services.evidence.models import (
    EvidenceDirectness,
    EvidenceRelation,
    EvidenceRecord,
    make_evidence_id,
)
from services.evidence.security_publications import (
    FirecrawlSecurityPublicationProvider,
    SecurityPublicationError,
    normalize_domain,
)


def test_evidence_record_preserves_directness_and_relation() -> None:
    record = EvidenceRecord(
        evidence_id="abc",
        source="Kaspersky Securelist",
        source_type="security_publication",
        relation=EvidenceRelation.SECURITY_PUBLICATION,
        directness=EvidenceDirectness.CONTEXTUAL,
        confidence=1.7,
        observed_at=datetime.now().isoformat(),
        published_at=None,
        domain="example.com",
        url="https://securelist.com/example",
        title="Example",
        summary="Context",
    )

    data = record.to_dict()

    assert data["relation"] == "security_publication"
    assert data["directness"] == "contextual"
    assert data["confidence"] == 1.0


def test_evidence_id_does_not_use_target_pii() -> None:
    first = make_evidence_id(
        source="ESET Research",
        source_type="security_publication",
        domain="example.com",
        url="https://welivesecurity.com/example",
        title="Example",
    )
    second = make_evidence_id(
        source="ESET Research",
        source_type="security_publication",
        domain="example.com",
        url="https://welivesecurity.com/example",
        title="Example",
    )

    assert first == second
    assert len(first) == 64


@pytest.mark.parametrize(
    "value, expected",
    [
        ("example.com", "example.com"),
        ("https://sub.example.com/path", "example.com"),
        ("Example.CO.ID", "example.co.id"),
    ],
)
def test_normalize_domain(value: str, expected: str) -> None:
    assert normalize_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "user@example.com",
        "+628123456789",
        "127.0.0.1",
        "https://example.com/path?email=user@example.com",
    ],
)
def test_normalize_domain_rejects_pii_or_unsafe_input(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_domain(value)


class MockTransport(httpx.AsyncBaseTransport):
    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self.payload = payload
        self.status_code = status_code

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/v2/search"
        assert request.headers["Authorization"] == "Bearer test-key"

        body = request.read()
        assert b"example.com" in body
        assert b"securelist.com" in body

        return httpx.Response(
            self.status_code,
            json=self.payload,
            request=request,
        )


@pytest.mark.asyncio
async def test_firecrawl_provider_returns_contextual_evidence() -> None:
    payload = {
        "success": True,
        "data": {
            "web": [
                {
                    "title": "Example domain in phishing research",
                    "description": "Research context for example.com.",
                    "url": "https://securelist.com/example-domain/",
                    "metadata": {"publishedTime": "2025-10-10"},
                },
                {
                    "title": "Wrong publisher",
                    "description": "Should be rejected.",
                    "url": "https://untrusted.example/example",
                },
            ]
        },
        "creditsUsed": 1,
    }

    transport = MockTransport(payload)
    client = httpx.AsyncClient(transport=transport)
    provider = FirecrawlSecurityPublicationProvider(
        api_key="test-key",
        client=client,
        publishers=(("Kaspersky Securelist", "securelist.com"),),
    )

    try:
        records = await provider.search_domain("example.com")
    finally:
        await client.aclose()

    assert len(records) == 1
    record = records[0]
    assert record.relation is EvidenceRelation.SECURITY_PUBLICATION
    assert record.directness is EvidenceDirectness.CONTEXTUAL
    assert record.domain == "example.com"
    assert record.published_at == "2025-10-10"
    assert record.provenance["query_scope"] == "domain_only"


@pytest.mark.asyncio
async def test_firecrawl_provider_is_optional_without_api_key() -> None:
    provider = FirecrawlSecurityPublicationProvider(
        api_key="",
        publishers=(("Kaspersky Securelist", "securelist.com"),),
    )

    assert provider.enabled is False
    assert await provider.search_domain("example.com") == []


@pytest.mark.asyncio
async def test_firecrawl_provider_swallows_provider_failure() -> None:
    class FailingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                503,
                json={"success": False, "error": "temporary"},
                request=request,
            )

    client = httpx.AsyncClient(transport=FailingTransport())
    provider = FirecrawlSecurityPublicationProvider(
        api_key="test-key",
        client=client,
        publishers=(("Kaspersky Securelist", "securelist.com"),),
    )

    try:
        records = await provider.search_domain("example.com")
    finally:
        await client.aclose()

    assert records == []
