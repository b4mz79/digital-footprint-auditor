from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx
import pytest

from utils.privacy import clean_web_snippet, clean_web_title

from services.enrichment.orchestration import enrich_evidence

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
async def test_contextual_filter_dump_is_single_markdown_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("EVIDENCE_CONTEXTUAL_FILTER_DUMP_DIR", str(tmp_path))
    payload = {"success": True, "data": {"web": [{
        "title": "Example.com phishing incident",
        "description": "Security incident involving example.com.",
        "url": "https://securelist.com/example-incident/",
    }]}}
    client = httpx.AsyncClient(transport=MockTransport(payload))
    provider = FirecrawlSecurityPublicationProvider(
        api_key="test-key", client=client,
        publishers=(("Kaspersky Securelist", "securelist.com"),),
    )
    try:
        await provider.search_domain("example.com")
    finally:
        await client.aclose()
    await provider.finalize_filter_dump()
    dump = (tmp_path / "contextual_filter_dump.md").read_text(encoding="utf-8")
    assert dump.startswith("BEFORE\n```json\n")
    assert "\n---\nAFTER\n```json\n" in dump
    assert dump.endswith("\n```\n")
    assert not (tmp_path / "contextual_filter_before.json").exists()
    assert not (tmp_path / "contextual_filter_after.json").exists()


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
    captured: dict[str, int] = {}

    class FakeProvider:
        def __init__(self, **kwargs):
            captured["requests_per_minute"] = kwargs["requests_per_minute"]
            self.cooldown_active = False

        async def finalize_filter_dump(self):
            return None

        async def search_domain(self, domain):
            return []

    import services.enrichment.orchestration as enrichment
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

        async def finalize_filter_dump(self):
            return None

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

    import services.enrichment.orchestration as enrichment
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

        async def finalize_filter_dump(self):
            return None

        async def search_domain(self, domain):
            calls.append(domain)
            self.cooldown_active = True
            return []

    import services.enrichment.orchestration as enrichment
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

        async def finalize_filter_dump(self):
            return None

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

    import services.enrichment.orchestration as enrichment
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
async def test_enrichment_cache_hit_skips_firecrawl(monkeypatch) -> None:
    from services.enrichment import orchestration as module

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
    cached = base.to_dict()

    monkeypatch.setenv("FIRECRAWL_API_KEY", "test-key")
    monkeypatch.setenv("EVIDENCE_ENRICHMENT_CACHE_ENABLED", "true")
    monkeypatch.setattr(module, "load_enrichment_cache", lambda *args, **kwargs: [cached])
    monkeypatch.setattr(
        module,
        "FirecrawlSecurityPublicationProvider",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Firecrawl must be skipped on enrichment cache hit")
        ),
    )

    result = await module.enrich_evidence([base], tenant_id="tenant-a")

    assert len(result) == 1
    assert result[0].evidence_id == "base-cache"
