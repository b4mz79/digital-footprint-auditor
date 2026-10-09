from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx
import pytest

from utils.privacy import clean_web_snippet, clean_web_title

from services.evidence_enrichment import enrich_evidence

from services.enrichment.evidence.models import (
    EvidenceDirectness,
    EvidenceRelation,
    EvidenceRecord,
    make_evidence_id,
)
from services.enrichment.evidence.security_publications import (
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
        observed_at=datetime.now().astimezone().isoformat(),
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
    assert data["assertion_scope"] == "unknown"
    assert data["verification_scope"] == "url_accessibility"
    assert data["verification_state"] == "unknown"
    assert data["verification_observed_at"] is None



@pytest.mark.parametrize("confidence", [float("nan"), float("inf"), float("-inf")])
def test_evidence_record_rejects_non_finite_confidence(confidence: float) -> None:
    with pytest.raises(ValueError, match="confidence must be finite"):
        EvidenceRecord(
            evidence_id="invalid-confidence",
            source="Example",
            source_type="test",
            relation=EvidenceRelation.TARGET_RESOURCE,
            directness=EvidenceDirectness.DIRECT,
            confidence=confidence,
            observed_at="2026-10-05T00:00:00+00:00",
            published_at=None,
            domain="example.com",
            url="",
            title="Example",
            summary="Example",
        )


def test_evidence_record_rejects_unscoped_verification_state() -> None:
    with pytest.raises(ValueError, match="Unsupported verification state"):
        EvidenceRecord(
            evidence_id="invalid",
            source="Example",
            source_type="test",
            relation=EvidenceRelation.TARGET_RESOURCE,
            directness=EvidenceDirectness.DIRECT,
            confidence=0.5,
            observed_at="2026-10-05T00:00:00+00:00",
            published_at=None,
            domain="example.com",
            url="https://example.com",
            title="Example",
            summary="Example",
            verification_state="verified",
        )


def test_service_finding_declares_narrow_assertion_scope() -> None:
    from services.enrichment.evidence.normalizer import service_findings_to_evidence

    records = service_findings_to_evidence([{
        "name": "Example Service",
        "domain": "example.com",
        "source": "OSINT",
        "subject": "Observed service association",
    }], observed_at="2026-10-05T00:00:00+00:00")

    assert len(records) == 1
    record = records[0]
    assert record.assertion_scope == "service_association_only"
    assert record.directness is EvidenceDirectness.DIRECT
    assert record.verification_state == "unknown"


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
        ("https://exämple.com/path", "xn--exmple-cua.com"),
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
        "8.8.8.8",
        "https://8.8.8.8/",
        "[2001:4860:4860::8888]",
        "https://[2001:4860:4860::8888]/",
        "2001:4860:4860::8888",
        "https://example.com/path?email=user@example.com",
        "ftp://example.com",
        "file://example.com",
        "javascript://example.com",
        "https://example.com:invalid/",
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


def test_clean_web_text_removes_markup_and_masks_sensitive_values() -> None:
    title = clean_web_title(
        "<b>Security &amp; incident</b> <img src='tracking.png'>",
    )
    snippet = clean_web_snippet(
        "<p>Research <strong>context</strong> for user@example.com.</p>"
        " Call +62 812-3456-7890. OTP 482913. "
        "Bearer abcdefghijklmnop. <script>alert('x')</script>",
    )

    assert title == "Security & incident"
    assert "<" not in snippet
    assert ">" not in snippet
    assert "user@example.com" not in snippet
    assert "+62 812-3456-7890" not in snippet
    assert "482913" not in snippet
    assert "abcdefghijklmnop" not in snippet
    assert "alert" not in snippet
    assert "Research context" in snippet
    assert "tracking.png" not in snippet

    markdown = clean_web_snippet(
        "![tracking image](https://example.com/pixel.png) "
        "[security report](https://example.com/report) "
        "## Incident",
    )
    assert "tracking image" in markdown
    assert "security report" in markdown
    assert "https://example.com" not in markdown
    assert "##" not in markdown


def test_clean_web_text_collapses_whitespace_and_bounds_length() -> None:
    value = clean_web_snippet("  one\n\n <b>two</b>\t three  ", max_length=10)
    assert value == "one two th"



def test_contextual_relevance_requires_target_and_security_signals() -> None:
    from services.enrichment.evidence.security_publications import _contextual_relevance

    accepted, signals = _contextual_relevance(
        "example.com", url="https://securelist.com/example-phishing/",
        title="Example.com in phishing research", summary="Security research context.",
    )
    assert accepted is True
    assert signals["reason"] == "target_subject_security_context"

    accepted, signals = _contextual_relevance(
        "example.com", url="https://securelist.com/example-update/",
        title="Example.com product update", summary="General company news.",
    )
    assert accepted is False
    assert signals["reason"] == "security_context_missing"

    accepted, signals = _contextual_relevance(
        "asus.com", url="https://securelist.com/asus-expert-site-manager/",
        title="ASUS Expert Site Manager",
        summary="Security management capability for ASUS devices.",
    )
    assert accepted is False
    assert signals["reason"] == "security_context_missing"

    accepted, signals = _contextual_relevance(
        "example.com", url="https://securelist.com/other-phishing/",
        title="Phishing campaign targets another company", summary="Security incident research.",
    )
    assert accepted is False
    assert signals["reason"] == "target_not_subject"

    accepted, signals = _contextual_relevance(
        "example.com", url="https://securelist.com/category/incidents/page/25/",
        title="Category: Incidents | Page 25 | Securelist", summary="example.com phishing security",
    )
    assert accepted is False
    assert signals["reason"] == "navigation_page"

    accepted, signals = _contextual_relevance(
        "example.com",
        url="https://securelist.com/incidents?offset=25",
        title="Security incidents",
        summary="example.com phishing incident",
    )
    assert accepted is False
    assert signals["reason"] == "navigation_page"

    accepted, signals = _contextual_relevance(
        "atlassian.com", url="https://welivesecurity.com/hipchat-hack/",
        title="HipChat hack leads to password reset",
        summary="Atlassian suffered a security breach after its HipChat service was compromised.",
    )
    assert accepted is True
    assert signals["target"] == "summary_alias"

    accepted, signals = _contextual_relevance(
        "blibli.com", url="https://microsoft.com/security/article",
        title="Microsoft Tingkatkan Upaya Perlindungan Konsumen",
        summary="Security news mentions Blanja.com, Blibli.com and other retailers.",
    )
    assert accepted is False
    assert signals["reason"] == "incidental_target_mention"

    accepted, signals = _contextual_relevance(
        "asus.com", url="https://securelist.com/operation-shadowhammer/",
        title="Operation ShadowHammer",
        summary="The attack compromised ASUS Live Update and was a major security incident.",
    )
    assert accepted is True
    assert signals["target"] == "summary_alias"

    accepted, signals = _contextual_relevance(
        "asus.com",
        url="https://unit42.paloaltonetworks.com/risks-in-iot-supply-chain/",
        title="Risks in IoT Supply Chain",
        summary=(
            "Operation ShadowHammer targeted ASUS through trojanized software. "
            "The campaign compromised infrastructure and abused security certificates."
        ),
    )
    assert accepted is True
    assert signals["reason"] == "target_subject_security_context"

    accepted, signals = _contextual_relevance(
        "asus.com", url="https://securelist.com/browsing-malicious-websites/36273/",
        title="Browsing malicious websites",
        summary="A general guide to browsing malicious websites; ASUS is mentioned as an example.",
    )
    assert accepted is False
    assert signals["reason"] == "reference_page"
    assert signals["page_type"] == "reference"

    accepted, signals = _contextual_relevance(
        "atlassian.com", url="https://learn.microsoft.com/en-us/microsoft-365-app-certification/teams/atlassiancom-jira-data-center",
        title="Jira Data Center - Microsoft 365 App Certification",
        summary="Security and compliance information for the application.",
    )
    assert accepted is False
    assert signals["reason"] == "product_metadata_page"
    assert signals["page_type"] == "product_metadata"
    assert signals["target"] == "none"
    assert signals["target_strength"] == "none"

    accepted, signals = _contextual_relevance(
        "atlassian.com",
        url="https://learn.microsoft.com/en-us/some-article",
        title="Application Information for Jira Cloud for Outlook (Official) by Atlassian.com",
        summary="Security and compliance information for the application.",
    )
    assert accepted is False
    assert signals["reason"] == "product_metadata_page"
    assert signals["page_type"] == "product_metadata"


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
                {
                    "title": "Example.com phishing incident",
                    "description": "A phishing incident affected example.com.",
                    "url": "https://securelist.com:99999/example-phishing/",
                },
                {
                    "title": "Example.com product update",
                    "description": "A general company announcement for example.com.",
                    "url": "https://securelist.com/example-product-update/",
                },
                {
                    "title": "Security incident affecting another company",
                    "description": "Phishing research with no target-domain mention.",
                    "url": "https://securelist.com/other-company-phishing/",
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
    assert record.provenance["relevance_filter"] == "security_publication_context_v2"
    assert record.assertion_scope == "security_publication_context_only"
    assert record.verification_scope == "url_accessibility"
    assert record.verification_state == "unknown"
    assert record.metadata["status"] == "contextual_accepted"
    assert len(record.summary) <= 600


@pytest.mark.asyncio
async def test_firecrawl_oversized_response_stops_streaming_and_closes(monkeypatch) -> None:
    import services.enrichment.evidence.security_publications as module

    consumed: list[bytes] = []
    stream_closed = False

    class ChunkedBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            nonlocal stream_closed
            for chunk in (b"12345", b"67890", b"X", b"should-not-be-read"):
                consumed.append(chunk)
                yield chunk

        async def aclose(self) -> None:
            nonlocal stream_closed
            stream_closed = True

    monkeypatch.setattr(module, "MAX_RESPONSE_BYTES", 10)
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=ChunkedBody(), request=request)
        )
    )
    provider = module.FirecrawlSecurityPublicationProvider(
        api_key="test-key",
        client=client,
        publishers=(("Kaspersky Securelist", "securelist.com"),),
        requests_per_minute=60000,
    )

    try:
        assert await provider.search_domain("example.com") == []
    finally:
        await client.aclose()

    assert len(consumed) == 3
    assert consumed[-1] == b"X"
    assert stream_closed is True


@pytest.mark.asyncio
async def test_firecrawl_provider_is_optional_without_api_key() -> None:
    provider = FirecrawlSecurityPublicationProvider(
        api_key="",
        publishers=(("Kaspersky Securelist", "securelist.com"),),
    )

    assert provider.enabled is False
    assert await provider.search_domain("example.com") == []


@pytest.mark.asyncio
async def test_firecrawl_malformed_success_response_marks_search_incomplete() -> None:
    client = httpx.AsyncClient(
        transport=MockTransport({"success": True}),
    )
    provider = FirecrawlSecurityPublicationProvider(
        api_key="test-key",
        client=client,
        publishers=(("Kaspersky Securelist", "securelist.com"),),
        requests_per_minute=60000,
    )

    try:
        assert await provider.search_domain("example.com") == []
    finally:
        await client.aclose()

    assert provider.had_failures is True


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
    assert provider.had_failures is True


@pytest.mark.asyncio
async def test_firecrawl_429_enters_cooldown_without_retry_storm() -> None:
    calls = 0

    class RateLimitTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(
                429,
                json={"success": False, "error": "rate limited"},
                request=request,
            )

    client = httpx.AsyncClient(transport=RateLimitTransport())
    provider = FirecrawlSecurityPublicationProvider(
        api_key="test-key",
        client=client,
        publishers=(("Kaspersky Securelist", "securelist.com"),),
        max_concurrency=1,
        cooldown_seconds=60,
    )

    try:
        assert await provider.search_domain("example.com") == []
        assert await provider.search_domain("example.org") == []
    finally:
        await client.aclose()

    assert calls == 1


@pytest.mark.asyncio
async def test_firecrawl_provider_applies_configured_request_spacing() -> None:
    calls: list[float] = []

    class SuccessTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            import time
            calls.append(time.monotonic())
            return httpx.Response(
                200,
                json={"success": True, "data": {"web": []}},
                request=request,
            )

    client = httpx.AsyncClient(transport=SuccessTransport())
    provider = FirecrawlSecurityPublicationProvider(
        api_key="test-key",
        client=client,
        publishers=(("Kaspersky Securelist", "securelist.com"),),
        max_concurrency=2,
        requests_per_minute=1200,
    )

    try:
        await provider.search_domain("example.com")
        await provider.search_domain("example.org")
    finally:
        await client.aclose()

    assert len(calls) == 2
    assert calls[1] - calls[0] >= 0.045


@pytest.mark.asyncio
async def test_enrich_evidence_passes_configured_request_rate(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeProvider:
        def __init__(self, **kwargs):
            captured["requests_per_minute"] = kwargs["requests_per_minute"]
            self.cooldown_active = False

        async def search_domain(self, domain):
            return []

    import services.evidence_enrichment as enrichment
    monkeypatch.setattr(enrichment, "FirecrawlSecurityPublicationProvider", FakeProvider)
    monkeypatch.setenv("FIRECRAWL_REQUESTS_PER_MINUTE", "7")

    base = EvidenceRecord(
        evidence_id="base-rpm",
        source="OSINT / Holehe",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.80,
        observed_at="2026-01-01T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Example",
        summary="Observed service association.",
    )

    result = await enrich_evidence([base], firecrawl_api_key="test-key")

    assert len(result) == 1
    assert captured["requests_per_minute"] == 7


@pytest.mark.asyncio
async def test_enrich_evidence_merges_contextual_records(monkeypatch) -> None:
    from services.enrichment.evidence.models import EvidenceDirectness, EvidenceRelation, EvidenceRecord

    base = EvidenceRecord(
        evidence_id="base-1",
        source="OSINT / Holehe",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.80,
        observed_at="2026-01-01T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Target-associated service: Example",
        summary="Observed service association.",
    )

    class FakeProvider:
        def __init__(self, **kwargs):
            assert kwargs["api_key"] == "test-key"
            assert kwargs["max_results"] == 5
            assert kwargs["client"] is not None
            assert kwargs["max_concurrency"] >= 1
            assert kwargs["requests_per_minute"] >= 1
            assert kwargs["cooldown_seconds"] >= 1
            self.cooldown_active = False

        async def search_domain(self, domain):
            assert domain == "example.com"
            return [
                EvidenceRecord(
                    evidence_id="context-1",
                    source="Kaspersky Securelist",
                    source_type="security_publication",
                    relation=EvidenceRelation.SECURITY_PUBLICATION,
                    directness=EvidenceDirectness.CONTEXTUAL,
                    confidence=0.65,
                    observed_at="2026-01-01T00:00:00+00:00",
                    published_at="2025-12-01",
                    domain=domain,
                    url="https://securelist.com/example",
                    title="Example security context",
                    summary="Context only.",
                )
            ]

    import services.evidence_enrichment as enrichment
    monkeypatch.setattr(enrichment, "FirecrawlSecurityPublicationProvider", FakeProvider)

    result = await enrich_evidence(
        [base],
        firecrawl_api_key="test-key",
    )

    assert len(result) == 2
    assert result[0].evidence_id == "base-1"
    assert result[1].relation is EvidenceRelation.SECURITY_PUBLICATION
    assert result[1].directness is EvidenceDirectness.CONTEXTUAL


@pytest.mark.asyncio
async def test_enrich_evidence_stops_scheduling_domains_after_rate_limit(monkeypatch) -> None:
    base_records = [
        EvidenceRecord(
            evidence_id=f"base-{domain}",
            source="OSINT / Holehe",
            source_type="osint",
            relation=EvidenceRelation.TARGET_RESOURCE,
            directness=EvidenceDirectness.DIRECT,
            confidence=0.80,
            observed_at="2026-01-01T00:00:00+00:00",
            published_at=None,
            domain=domain,
            url="",
            title=f"Target-associated service: {domain}",
            summary="Observed service association.",
        )
        for domain in ("one.example", "two.example", "three.example", "four.example")
    ]

    calls: list[str] = []

    class FakeProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False

        async def search_domain(self, domain):
            calls.append(domain)
            self.cooldown_active = True
            return []

    import services.evidence_enrichment as enrichment
    monkeypatch.setattr(enrichment, "FirecrawlSecurityPublicationProvider", FakeProvider)
    monkeypatch.setenv("FIRECRAWL_DOMAIN_CONCURRENCY", "2")

    result = await enrich_evidence(
        base_records,
        firecrawl_api_key="test-key",
    )

    assert len(result) == 4
    assert sorted(calls) == ["four.example", "one.example"]


@pytest.mark.asyncio
async def test_enrich_evidence_applies_contextual_output_budget(monkeypatch) -> None:
    base_records = [
        EvidenceRecord(
            evidence_id=f"base-{domain}",
            source="OSINT / Holehe",
            source_type="osint",
            relation=EvidenceRelation.TARGET_RESOURCE,
            directness=EvidenceDirectness.DIRECT,
            confidence=0.80,
            observed_at="2026-01-01T00:00:00+00:00",
            published_at=None,
            domain=domain,
            url="",
            title=f"Target-associated service: {domain}",
            summary="Observed service association.",
        )
        for domain in ("one.example", "two.example", "three.example")
    ]

    class FakeProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False

        async def search_domain(self, domain):
            return [
                EvidenceRecord(
                    evidence_id=f"context-{domain}-{idx}",
                    source="Kaspersky Securelist",
                    source_type="security_publication",
                    relation=EvidenceRelation.SECURITY_PUBLICATION,
                    directness=EvidenceDirectness.CONTEXTUAL,
                    confidence=0.65,
                    observed_at="2026-01-01T00:00:00+00:00",
                    published_at=f"2025-12-{idx:02d}",
                    domain=domain,
                    url=f"https://securelist.com/{domain}/{idx}",
                    title=f"{domain} security context {idx}",
                    summary="Security incident context.",
                )
                for idx in (1, 2, 3)
            ]

    import services.evidence_enrichment as enrichment
    monkeypatch.setattr(enrichment, "FirecrawlSecurityPublicationProvider", FakeProvider)
    monkeypatch.setenv("FIRECRAWL_MAX_CONTEXTUAL_RECORDS", "4")
    monkeypatch.setenv("FIRECRAWL_MAX_CONTEXTUAL_RECORDS_PER_DOMAIN", "1")
    monkeypatch.setenv("FIRECRAWL_DOMAIN_CONCURRENCY", "3")

    result = await enrich_evidence(base_records, firecrawl_api_key="test-key")

    contextual = [
        record
        for record in result
        if record.relation is EvidenceRelation.SECURITY_PUBLICATION
    ]
    assert len(contextual) == 3
    assert len(contextual) <= 4
    assert len({record.domain for record in contextual}) == 3


@pytest.mark.asyncio
async def test_contextual_budget_orders_publication_timestamps_by_utc(monkeypatch) -> None:
    import services.evidence_enrichment as module

    base = EvidenceRecord(
        evidence_id="base-time-order",
        source="OSINT",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-09T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Target-associated service: Example",
        summary="Observed service association.",
    )

    class FakeProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False
            self.had_failures = False

        async def search_domain(self, domain):
            assert domain == "example.com"
            return [
                EvidenceRecord(
                    evidence_id="publication-earlier-utc",
                    source="Kaspersky Securelist",
                    source_type="security_publication",
                    relation=EvidenceRelation.SECURITY_PUBLICATION,
                    directness=EvidenceDirectness.CONTEXTUAL,
                    confidence=0.65,
                    observed_at="2026-10-09T00:00:00+00:00",
                    published_at="2026-10-01T00:30:00+03:00",
                    domain=domain,
                    url="https://securelist.com/earlier",
                    title="Earlier publication",
                    summary="Security incident context.",
                ),
                EvidenceRecord(
                    evidence_id="publication-later-utc",
                    source="Kaspersky Securelist",
                    source_type="security_publication",
                    relation=EvidenceRelation.SECURITY_PUBLICATION,
                    directness=EvidenceDirectness.CONTEXTUAL,
                    confidence=0.65,
                    observed_at="2026-10-09T00:00:00+00:00",
                    published_at="2026-10-01T00:00:00Z",
                    domain=domain,
                    url="https://securelist.com/later",
                    title="Later publication",
                    summary="Security incident context.",
                ),
            ]

    monkeypatch.setattr(module, "FirecrawlSecurityPublicationProvider", FakeProvider)
    monkeypatch.setenv("FIRECRAWL_MAX_CONTEXTUAL_RECORDS_PER_DOMAIN", "1")
    monkeypatch.setenv("FIRECRAWL_MAX_CONTEXTUAL_RECORDS", "5")

    result = await module.enrich_evidence([base], firecrawl_api_key="test-key")
    contextual = [
        record
        for record in result
        if record.relation is EvidenceRelation.SECURITY_PUBLICATION
    ]

    assert len(contextual) == 1
    assert contextual[0].evidence_id == "publication-later-utc"


@pytest.mark.asyncio
async def test_enrichment_cache_hit_skips_firecrawl(monkeypatch) -> None:
    import services.evidence_enrichment as module

    base = EvidenceRecord(
        evidence_id="base-cache",
        source="OSINT",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-05T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Target-associated service: Example",
        summary="Observed service association.",
        assertion_scope="service_association_only",
    )
    cached = EvidenceRecord(
        evidence_id="cached-context-hit",
        source="Kaspersky Securelist",
        source_type="security_publication",
        relation=EvidenceRelation.SECURITY_PUBLICATION,
        directness=EvidenceDirectness.CONTEXTUAL,
        confidence=0.65,
        observed_at="2026-10-05T00:00:00+00:00",
        published_at="2026-10-01",
        domain="example.com",
        url="https://securelist.com/example",
        title="Example.com phishing research",
        summary="Security publication context.",
        provenance={
            "provider": "firecrawl_search",
            "publisher_domain": "securelist.com",
            "query_scope": "domain_only",
            "relevance_filter": module.CONTEXTUAL_FILTER_NAME,
            "assertion_scope": "security_publication_context_only",
        },
        assertion_scope="security_publication_context_only",
    )

    monkeypatch.setenv("FIRECRAWL_API_KEY", "test-key")
    monkeypatch.setenv("EVIDENCE_ENRICHMENT_CACHE_ENABLED", "true")
    monkeypatch.setattr(module, "load_enrichment_cache", lambda *args, **kwargs: [cached.to_dict()])
    monkeypatch.setattr(
        module,
        "FirecrawlSecurityPublicationProvider",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Firecrawl must be skipped on enrichment cache hit")
        ),
    )

    result = await module.enrich_evidence([base], tenant_id="tenant-a")

    assert {record.evidence_id for record in result} == {
        "base-cache",
        "cached-context-hit",
    }


@pytest.mark.asyncio
async def test_enrichment_cache_hit_preserves_current_base_state(monkeypatch) -> None:
    import services.evidence_enrichment as module

    contextual = EvidenceRecord(
        evidence_id="cached-context",
        source="Kaspersky Securelist",
        source_type="security_publication",
        relation=EvidenceRelation.SECURITY_PUBLICATION,
        directness=EvidenceDirectness.CONTEXTUAL,
        confidence=0.65,
        observed_at="2026-10-05T00:00:00+00:00",
        published_at="2026-10-01",
        domain="example.com",
        url="https://securelist.com/example-phishing/",
        title="Example.com phishing research",
        summary="Security publication context.",
        provenance={
            "provider": "firecrawl_search",
            "publisher_domain": "securelist.com",
            "query_scope": "domain_only",
            "relevance_filter": module.CONTEXTUAL_FILTER_NAME,
            "assertion_scope": "security_publication_context_only",
        },
        assertion_scope="security_publication_context_only",
    )
    current_base = EvidenceRecord(
        evidence_id="base-current-state",
        source="OSINT",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-09T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Target-associated service: Example",
        summary="Observed service association.",
        provenance={"fresh_scan": True},
        assertion_scope="service_association_only",
        verification_state="reachable",
        verification_observed_at="2026-10-09T00:00:00+00:00",
    )

    monkeypatch.setenv("FIRECRAWL_API_KEY", "test-key")
    monkeypatch.setenv("EVIDENCE_ENRICHMENT_CACHE_ENABLED", "true")
    monkeypatch.setattr(
        module,
        "load_enrichment_cache",
        lambda *args, **kwargs: [contextual.to_dict()],
    )
    monkeypatch.setattr(
        module,
        "FirecrawlSecurityPublicationProvider",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Firecrawl must be skipped on enrichment cache hit")
        ),
    )

    result = await module.enrich_evidence([current_base], tenant_id="tenant-current-state")
    by_id = {record.evidence_id: record for record in result}

    assert set(by_id) == {"base-current-state", "cached-context"}
    assert by_id["base-current-state"].observed_at == "2026-10-09T00:00:00+00:00"
    assert by_id["base-current-state"].verification_state == "reachable"
    assert by_id["base-current-state"].verification_observed_at == "2026-10-09T00:00:00+00:00"
    assert by_id["base-current-state"].provenance == {"fresh_scan": True}
    assert by_id["cached-context"].assertion_scope == "security_publication_context_only"


@pytest.mark.parametrize(
    "cache_enabled, provider_failed, expected_write",
    [
        (False, False, False),
        (True, True, False),
        (True, False, True),
    ],
)
@pytest.mark.asyncio
async def test_enrichment_cache_writes_only_when_enabled_and_complete(
    monkeypatch, cache_enabled, provider_failed, expected_write
) -> None:
    import services.evidence_enrichment as module

    writes: list[tuple[object, ...]] = []

    class FakeProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False
            self.had_failures = provider_failed

        async def search_domain(self, domain):
            return []

    base = EvidenceRecord(
        evidence_id="base-cache-policy",
        source="OSINT",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-09T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Target-associated service: Example",
        summary="Observed service association.",
        assertion_scope="service_association_only",
    )

    monkeypatch.setenv(
        "EVIDENCE_ENRICHMENT_CACHE_ENABLED",
        "true" if cache_enabled else "false",
    )
    monkeypatch.setattr(module, "load_enrichment_cache", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "save_enrichment_cache", lambda *args, **kwargs: writes.append(args))
    monkeypatch.setattr(module, "FirecrawlSecurityPublicationProvider", FakeProvider)

    result = await module.enrich_evidence([base], firecrawl_api_key="test-key")

    assert len(result) == 1
    assert bool(writes) is expected_write



def test_contextual_relevance_does_not_treat_public_suffix_as_target_alias() -> None:
    from services.enrichment.evidence.security_publications import _contextual_relevance

    accepted, signals = _contextual_relevance(
        "example.co.id",
        url="https://securelist.com/co-malware-campaign/",
        title="CO malware campaign",
        summary="A malware incident unrelated to the target.",
    )

    assert accepted is False
    assert signals["reason"] == "target_not_subject"


def test_contextual_relevance_does_not_treat_generic_domain_token_as_target() -> None:
    from services.enrichment.evidence.security_publications import _contextual_relevance

    accepted, signals = _contextual_relevance(
        "secure-company.com",
        url="https://securelist.com/company-phishing/",
        title="Company phishing campaign",
        summary="Company affected by a phishing incident.",
    )
    assert accepted is False
    assert signals["reason"] == "target_not_subject"

    accepted, signals = _contextual_relevance(
        "secure-company.com",
        url="https://securelist.com/secure-company-phishing/",
        title="Secure Company phishing campaign",
        summary="Secure Company suffered a phishing incident.",
    )
    assert accepted is True
    assert signals["reason"] == "target_subject_security_context"


@pytest.mark.asyncio
async def test_enrichment_cache_rejects_non_contextual_records(monkeypatch) -> None:
    import services.evidence_enrichment as module

    base = EvidenceRecord(
        evidence_id="base-cache-contract-validation",
        source="OSINT",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-09T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Target-associated service: Example",
        summary="Observed service association.",
        assertion_scope="service_association_only",
    )
    invalid_cached_record = EvidenceRecord(
        evidence_id="cached-scanner-like-record",
        source="OSINT",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-08T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Stale scanner record",
        summary="This record must not be restored from the enrichment cache.",
        assertion_scope="service_association_only",
    )
    provider_calls: list[str] = []

    class FakeProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False
            self.had_failures = False

        async def search_domain(self, domain):
            provider_calls.append(domain)
            return []

    monkeypatch.setenv("EVIDENCE_ENRICHMENT_CACHE_ENABLED", "true")
    monkeypatch.setattr(
        module,
        "load_enrichment_cache",
        lambda *args, **kwargs: [invalid_cached_record.to_dict()],
    )
    monkeypatch.setattr(module, "save_enrichment_cache", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "FirecrawlSecurityPublicationProvider", FakeProvider)

    result = await module.enrich_evidence([base], firecrawl_api_key="test-key")

    assert provider_calls == ["example.com"]
    assert [record.evidence_id for record in result] == [
        "base-cache-contract-validation"
    ]



@pytest.mark.asyncio
async def test_enrichment_cache_rejects_mismatched_publisher_provenance(monkeypatch) -> None:
    import services.evidence_enrichment as module

    base = EvidenceRecord(
        evidence_id="base-publisher-provenance",
        source="OSINT",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-09T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Target-associated service: Example",
        summary="Observed service association.",
        assertion_scope="service_association_only",
    )
    common = {
        "evidence_id": "cached-mismatched-publisher",
        "source": "Kaspersky Securelist",
        "source_type": "security_publication",
        "relation": EvidenceRelation.SECURITY_PUBLICATION,
        "directness": EvidenceDirectness.CONTEXTUAL,
        "confidence": 0.65,
        "observed_at": "2026-10-08T00:00:00+00:00",
        "published_at": "2026-10-01",
        "domain": "example.com",
        "title": "Security publication context",
        "summary": "Contextual publication evidence.",
        "provenance": {
            "provider": "firecrawl_search",
            "publisher_domain": "securelist.com",
            "query_scope": "domain_only",
            "relevance_filter": module.CONTEXTUAL_FILTER_NAME,
            "assertion_scope": "security_publication_context_only",
        },
        "assertion_scope": "security_publication_context_only",
    }
    invalid_url = EvidenceRecord(
        **common,
        url="https://attacker.example/report",
    )
    mismatched_scope_data = dict(common)
    mismatched_scope_data["evidence_id"] = "cached-mismatched-scope"
    mismatched_scope_data["url"] = "https://securelist.com/report"
    mismatched_scope_data["provenance"] = {
        **common["provenance"],
        "assertion_scope": "target_compromise_confirmed",
    }
    invalid_scope = EvidenceRecord(**mismatched_scope_data)
    cached_entries = [
        [invalid_url.to_dict()],
        [invalid_scope.to_dict()],
    ]
    provider_calls: list[str] = []

    class FakeProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False
            self.had_failures = False

        async def search_domain(self, domain):
            provider_calls.append(domain)
            return []

    monkeypatch.setenv("EVIDENCE_ENRICHMENT_CACHE_ENABLED", "true")
    monkeypatch.setattr(
        module,
        "load_enrichment_cache",
        lambda *args, **kwargs: cached_entries.pop(0),
    )
    monkeypatch.setattr(module, "save_enrichment_cache", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "FirecrawlSecurityPublicationProvider", FakeProvider)

    first = await module.enrich_evidence(
        [base],
        firecrawl_api_key="test-key",
        tenant_id="tenant-bad-publisher-url",
    )
    second = await module.enrich_evidence(
        [base],
        firecrawl_api_key="test-key",
        tenant_id="tenant-bad-assertion-scope",
    )

    assert provider_calls == ["example.com", "example.com"]
    assert [record.evidence_id for record in first] == ["base-publisher-provenance"]
    assert [record.evidence_id for record in second] == ["base-publisher-provenance"]


@pytest.mark.asyncio
async def test_enrichment_cache_fingerprint_tracks_provider_inputs_not_base_state(monkeypatch) -> None:
    import services.evidence_enrichment as module

    base = EvidenceRecord(
        evidence_id="base-cache-contract",
        source="OSINT",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-09T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Target-associated service: Example",
        summary="Observed service association.",
        assertion_scope="service_association_only",
    )
    fingerprints: list[str] = []
    searched_domains: list[str] = []

    class FakeProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False
            self.had_failures = False

        async def search_domain(self, domain):
            searched_domains.append(domain)
            return []

    def cache_miss(fingerprint, **kwargs):
        fingerprints.append(fingerprint)
        return None

    monkeypatch.setenv("EVIDENCE_ENRICHMENT_CACHE_ENABLED", "true")
    monkeypatch.setattr(module, "load_enrichment_cache", cache_miss)
    monkeypatch.setattr(module, "save_enrichment_cache", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "FirecrawlSecurityPublicationProvider", FakeProvider)

    await module.enrich_evidence([base], firecrawl_api_key="test-key")

    # A fresh scan can change evidence timestamps and metadata without changing
    # the provider input: Firecrawl still receives only the normalized domain.
    base.observed_at = "2026-10-10T12:30:00+00:00"
    base.metadata = {"fresh_scan": True}
    base.summary = "Updated scanner-side description."
    await module.enrich_evidence([base], firecrawl_api_key="test-key")

    # The normalized domain is a real provider input and must invalidate cache.
    base.domain = "different.example"
    await module.enrich_evidence([base], firecrawl_api_key="test-key")

    # Changes to the contextual filter contract must also invalidate cache.
    monkeypatch.setattr(module, "CONTEXTUAL_FILTER_NAME", "test-filter-contract-change")
    await module.enrich_evidence([base], firecrawl_api_key="test-key")

    assert len(fingerprints) == 4
    assert fingerprints[0] == fingerprints[1]
    assert fingerprints[1] != fingerprints[2]
    assert fingerprints[2] != fingerprints[3]
    assert searched_domains == [
        "example.com",
        "example.com",
        "different.example",
        "different.example",
    ]


@pytest.mark.asyncio
async def test_enrichment_does_not_replace_base_record_on_evidence_id_collision(monkeypatch) -> None:
    import services.evidence_enrichment as module

    base = EvidenceRecord(
        evidence_id="shared-evidence-id",
        source="OSINT",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-09T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Original scanner evidence",
        summary="Observed service association.",
        assertion_scope="service_association_only",
    )

    class FakeProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False
            self.had_failures = False

        async def search_domain(self, domain):
            return [
                EvidenceRecord(
                    evidence_id="shared-evidence-id",
                    source="Kaspersky Securelist",
                    source_type="security_publication",
                    relation=EvidenceRelation.SECURITY_PUBLICATION,
                    directness=EvidenceDirectness.CONTEXTUAL,
                    confidence=0.99,
                    observed_at="2026-10-09T00:00:00+00:00",
                    published_at="2026-10-08",
                    domain=domain,
                    url="https://securelist.com/example",
                    title="Conflicting contextual evidence",
                    summary="Security incident context.",
                    assertion_scope="security_publication_context_only",
                )
            ]

    monkeypatch.setattr(module, "FirecrawlSecurityPublicationProvider", FakeProvider)

    result = await module.enrich_evidence([base], firecrawl_api_key="test-key")

    assert len(result) == 1
    assert result[0] is base
    assert result[0].relation is EvidenceRelation.TARGET_RESOURCE
    assert result[0].title == "Original scanner evidence"

@pytest.mark.asyncio
async def test_malformed_base_domain_does_not_abort_valid_domain_enrichment(monkeypatch) -> None:
    import services.evidence_enrichment as module

    def make_record(evidence_id: str, domain: str) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_id=evidence_id,
            source="OSINT",
            source_type="osint",
            relation=EvidenceRelation.TARGET_RESOURCE,
            directness=EvidenceDirectness.DIRECT,
            confidence=0.8,
            observed_at="2026-10-09T00:00:00+00:00",
            published_at=None,
            domain=domain,
            url="",
            title="Observed service",
            summary="Observed service association.",
            assertion_scope="service_association_only",
        )

    malformed = make_record("base-malformed-domain", "invalid.example")
    malformed.domain = None
    valid = make_record("base-valid-domain", "example.com")
    provider_calls: list[str] = []

    class FakeProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False
            self.had_failures = False

        async def search_domain(self, domain):
            provider_calls.append(domain)
            return []

    monkeypatch.setenv("EVIDENCE_ENRICHMENT_CACHE_ENABLED", "false")
    monkeypatch.setattr(module, "FirecrawlSecurityPublicationProvider", FakeProvider)

    result = await module.enrich_evidence(
        [malformed, valid],
        firecrawl_api_key="test-key",
    )

    assert provider_calls == ["example.com"]
    assert {record.evidence_id for record in result} == {
        "base-malformed-domain",
        "base-valid-domain",
    }



@pytest.mark.asyncio
async def test_enrichment_cache_rejects_unhashable_evidence_id(monkeypatch) -> None:
    import services.evidence_enrichment as module

    base = EvidenceRecord(
        evidence_id="base-malformed-cache-id",
        source="OSINT",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-09T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Target-associated service: Example",
        summary="Observed service association.",
        assertion_scope="service_association_only",
    )
    cached = {
        "evidence_id": [],
        "source": "Kaspersky Securelist",
        "source_type": "security_publication",
        "relation": "security_publication",
        "directness": "contextual",
        "confidence": 0.65,
        "observed_at": "2026-10-08T00:00:00+00:00",
        "published_at": "2026-10-01",
        "domain": "example.com",
        "url": "https://securelist.com/example-report",
        "title": "Example.com security report",
        "summary": "Security publication context.",
        "provenance": {
            "provider": "firecrawl_search",
            "publisher_domain": "securelist.com",
            "query_scope": "domain_only",
            "relevance_filter": module.CONTEXTUAL_FILTER_NAME,
            "assertion_scope": "security_publication_context_only",
        },
        "metadata": {},
        "assertion_scope": "security_publication_context_only",
    }
    provider_calls = []

    class FakeProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False
            self.had_failures = False

        async def search_domain(self, domain):
            provider_calls.append(domain)
            return []

    monkeypatch.setenv("EVIDENCE_ENRICHMENT_CACHE_ENABLED", "true")
    monkeypatch.setattr(module, "load_enrichment_cache", lambda *args, **kwargs: [cached])
    monkeypatch.setattr(module, "save_enrichment_cache", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "FirecrawlSecurityPublicationProvider", FakeProvider)

    result = await module.enrich_evidence(
        [base], firecrawl_api_key="test-key", tenant_id="tenant-malformed-cache-id"
    )
    assert provider_calls == ["example.com"]
    assert [record.evidence_id for record in result] == ["base-malformed-cache-id"]


@pytest.mark.asyncio
async def test_enrichment_domain_cap_limits_provider_lookups(monkeypatch: pytest.MonkeyPatch) -> None:
    import services.evidence_enrichment as enrichment

    monkeypatch.setenv("FIRECRAWL_MAX_DOMAINS", "3")
    monkeypatch.setenv("FIRECRAWL_TOTAL_TIMEOUT_SECONDS", "5")
    monkeypatch.setenv("FIRECRAWL_DOMAIN_CONCURRENCY", "2")
    monkeypatch.setenv("EVIDENCE_ENRICHMENT_CACHE_ENABLED", "false")
    looked_up: list[str] = []

    class FastProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False
            self.had_failures = False

        async def search_domain(self, domain: str):
            looked_up.append(domain)
            return []

    monkeypatch.setattr(enrichment, "FirecrawlSecurityPublicationProvider", FastProvider)
    base = [
        EvidenceRecord(
            evidence_id=f"cap-{index}",
            source="OSINT / Holehe",
            source_type="osint",
            relation=EvidenceRelation.TARGET_RESOURCE,
            directness=EvidenceDirectness.DIRECT,
            confidence=0.8,
            observed_at="2026-01-01T00:00:00+00:00",
            published_at=None,
            domain=f"domain-{index}.example",
            url="",
            title=f"Domain {index}",
            summary="Observed service association.",
        )
        for index in range(8)
    ]

    result = await enrich_evidence(base, firecrawl_api_key="test-key")

    assert len(looked_up) == 3
    assert len(result) == len(base)


@pytest.mark.asyncio
async def test_enrichment_global_deadline_preserves_base_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio
    import services.evidence_enrichment as enrichment

    monkeypatch.setenv("FIRECRAWL_MAX_DOMAINS", "10")
    monkeypatch.setenv("FIRECRAWL_TOTAL_TIMEOUT_SECONDS", "0.03")
    monkeypatch.setenv("FIRECRAWL_DOMAIN_CONCURRENCY", "2")
    monkeypatch.setenv("EVIDENCE_ENRICHMENT_CACHE_ENABLED", "false")
    started: list[str] = []

    class SlowProvider:
        def __init__(self, **kwargs):
            self.cooldown_active = False
            self.had_failures = False

        async def search_domain(self, domain: str):
            started.append(domain)
            await asyncio.sleep(0.2)
            return []

    monkeypatch.setattr(enrichment, "FirecrawlSecurityPublicationProvider", SlowProvider)
    base = [
        EvidenceRecord(
            evidence_id=f"deadline-{index}",
            source="OSINT / Holehe",
            source_type="osint",
            relation=EvidenceRelation.TARGET_RESOURCE,
            directness=EvidenceDirectness.DIRECT,
            confidence=0.8,
            observed_at="2026-01-01T00:00:00+00:00",
            published_at=None,
            domain=f"deadline-{index}.example",
            url="",
            title=f"Deadline {index}",
            summary="Observed service association.",
        )
        for index in range(6)
    ]

    result = await enrich_evidence(base, firecrawl_api_key="test-key")

    assert len(started) == 2
    assert {record.evidence_id for record in result} == {
        record.evidence_id for record in base
    }


@pytest.mark.asyncio
async def test_evidence_verification_total_deadline_marks_pending_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio
    import services.enrichment.verification as verification
    from services.enrichment.evidence.models import EvidenceRecord, EvidenceRelation, EvidenceDirectness

    def make_record(evidence_id: str, url: str) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_id=evidence_id,
            source="test",
            source_type="test",
            relation=EvidenceRelation.TARGET_RESOURCE,
            directness=EvidenceDirectness.DIRECT,
            confidence=0.5,
            observed_at="2026-10-09T00:00:00+00:00",
            published_at=None,
            domain="example.com",
            url=url,
            title=evidence_id,
            summary="URL accessibility is an evidence-quality signal only.",
            verification_state="reachable",
            verification_observed_at="2026-10-08T00:00:00+00:00",
            metadata={"url_verification": {"status_code": 200}},
        )

    async def slow_verify(url, **kwargs):
        if url.endswith("/slow"):
            await asyncio.sleep(1)
        return type(
            "Result",
            (),
            {"reachable": True, "status_code": 200, "redirected": False,
             "location": None, "content_type": "text/html"},
        )()

    monkeypatch.setattr(verification, "verify_public_url", slow_verify)
    fast = make_record("fast", "https://example.com/fast")
    slow = make_record("slow", "https://example.com/slow")

    result = await verification.verify_evidence_records(
        [fast, slow],
        timeout_seconds=2,
        concurrency=2,
        total_timeout_seconds=0.05,
    )

    assert result[0].verification_state == "reachable"
    assert result[0].metadata["url_verification"]["status_code"] == 200
    assert result[1].verification_state == "unknown"
    assert result[1].verification_observed_at is None
    assert "url_verification" not in result[1].metadata


@pytest.mark.asyncio
async def test_evidence_verification_parent_cancellation_propagates_and_cleans_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio
    import services.enrichment.verification as verification
    from services.enrichment.evidence.models import EvidenceRecord, EvidenceRelation, EvidenceDirectness

    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def slow_verify(url, **kwargs):
        started.set()
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    record = EvidenceRecord(
        evidence_id="cancelled-verification",
        source="test",
        source_type="test",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.5,
        observed_at="2026-10-09T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="https://example.com/slow",
        title="Slow verification",
        summary="Test cancellation cleanup.",
    )
    monkeypatch.setattr(verification, "verify_public_url", slow_verify)

    task = asyncio.create_task(
        verification.verify_evidence_records(
            [record], timeout_seconds=20, total_timeout_seconds=20
        )
    )
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set()
