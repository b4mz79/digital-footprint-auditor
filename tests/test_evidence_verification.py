from __future__ import annotations

import pytest

from services.enrichment.evidence.models import EvidenceDirectness, EvidenceRecord, EvidenceRelation
from services.enrichment.verification import verify_evidence_records
import services.enrichment.verification as verification_module


@pytest.mark.asyncio
async def test_verify_evidence_records_annotates_url_accessibility(monkeypatch) -> None:
    async def fake_verify(url, *, timeout_seconds, client):
        class Result:
            reachable = True
            status_code = 200
            redirected = False
            location = None
            content_type = "text/html"

        assert url == "https://example.com/report"
        return Result()

    monkeypatch.setattr("services.enrichment.verification.verify_public_url", fake_verify)

    record = EvidenceRecord(
        evidence_id="e1",
        source="Example Security",
        source_type="security_publication",
        relation=EvidenceRelation.SECURITY_PUBLICATION,
        directness=EvidenceDirectness.CONTEXTUAL,
        confidence=0.65,
        observed_at="2026-10-05T00:00:00+00:00",
        published_at="2026-10-01T00:00:00+00:00",
        domain="example.com",
        url="https://example.com/report",
        title="Security report",
        summary="Security context.",
        assertion_scope="security_publication_context_only",
    )

    result = await verify_evidence_records([record], concurrency=1)

    assert result[0].verification_scope == "url_accessibility"
    assert result[0].verification_state == "reachable"
    assert result[0].verification_observed_at
    assert result[0].metadata["url_verification"]["status_code"] == 200


@pytest.mark.asyncio
async def test_verify_evidence_records_keeps_urlless_evidence_unknown() -> None:
    record = EvidenceRecord(
        evidence_id="e2",
        source="OSINT",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-05T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url="",
        title="Target-associated service",
        summary="Association only.",
        assertion_scope="service_association_only",
        verification_state="reachable",
        verification_observed_at="2026-10-05T00:00:00+00:00",
        metadata={
            "keep": "this metadata",
            "url_verification": {"status_code": 200, "reachable": True},
        },
    )

    result = await verify_evidence_records([record])

    assert result[0].verification_state == "unknown"
    assert result[0].verification_observed_at is None
    assert "url_verification" not in result[0].metadata
    assert result[0].metadata["keep"] == "this metadata"


@pytest.mark.asyncio
async def test_verify_evidence_records_isolates_per_record_failure(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_verify(url, *, timeout_seconds, client):
        calls.append(url)
        if url.endswith("/bad"):
            raise RuntimeError("synthetic verifier failure")

        class Result:
            reachable = True
            status_code = 200
            redirected = False
            location = None
            content_type = "text/html"

        return Result()

    monkeypatch.setattr("services.enrichment.verification.verify_public_url", fake_verify)

    def make_record(evidence_id: str, url: str) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_id=evidence_id,
            source="Example Security",
            source_type="security_publication",
            relation=EvidenceRelation.SECURITY_PUBLICATION,
            directness=EvidenceDirectness.CONTEXTUAL,
            confidence=0.65,
            observed_at="2026-10-05T00:00:00+00:00",
            published_at="2026-10-01T00:00:00+00:00",
            domain="example.com",
            url=url,
            title="Security report",
            summary="Security context.",
            assertion_scope="security_publication_context_only",
        )

    good, bad = make_record("good", "https://example.com/good"), make_record(
        "bad", "https://example.com/bad"
    )
    bad.verification_state = "reachable"
    bad.verification_observed_at = "2026-10-05T00:00:00+00:00"
    bad.metadata = {
        "keep": "other metadata",
        "url_verification": {"status_code": 200, "reachable": True},
    }

    result = await verify_evidence_records([good, bad], concurrency=2)

    assert calls == ["https://example.com/good", "https://example.com/bad"]
    assert result[0].verification_state == "reachable"
    assert result[0].verification_observed_at
    assert result[1].verification_state == "unknown"
    assert result[1].verification_observed_at is None
    assert "url_verification" not in result[1].metadata
    assert result[1].metadata["keep"] == "other metadata"


@pytest.mark.asyncio
async def test_verify_evidence_records_can_be_disabled() -> None:
    record = EvidenceRecord(
        evidence_id="disabled",
        source="Example Security",
        source_type="security_publication",
        relation=EvidenceRelation.SECURITY_PUBLICATION,
        directness=EvidenceDirectness.CONTEXTUAL,
        confidence=0.65,
        observed_at="2026-10-05T00:00:00+00:00",
        published_at="2026-10-01T00:00:00+00:00",
        domain="example.com",
        url="https://example.com/report",
        title="Security report",
        summary="Security context.",
        assertion_scope="security_publication_context_only",
        verification_state="reachable",
        verification_observed_at="2026-10-05T00:00:00+00:00",
        metadata={
            "keep": "unrelated metadata",
            "url_verification": {"status_code": 200, "reachable": True},
        },
    )

    result = await verify_evidence_records([record], enabled=False)

    assert result[0] is record
    assert result[0].verification_state == "unknown"
    assert result[0].verification_observed_at is None
    assert "url_verification" not in result[0].metadata
    assert result[0].metadata["keep"] == "unrelated metadata"


@pytest.mark.asyncio
async def test_verification_client_setup_failure_clears_stale_state(monkeypatch) -> None:
    def broken_client(**kwargs):
        raise RuntimeError("synthetic client setup failure")

    monkeypatch.setattr(verification_module.httpx, "AsyncClient", broken_client)

    record = EvidenceRecord(
        evidence_id="client-setup-failure",
        source="Example Security",
        source_type="security_publication",
        relation=EvidenceRelation.SECURITY_PUBLICATION,
        directness=EvidenceDirectness.CONTEXTUAL,
        confidence=0.65,
        observed_at="2026-10-05T00:00:00+00:00",
        published_at="2026-10-01T00:00:00+00:00",
        domain="example.com",
        url="https://example.com/report",
        title="Security report",
        summary="Security context.",
        assertion_scope="security_publication_context_only",
        verification_state="reachable",
        verification_observed_at="2026-10-05T00:00:00+00:00",
        metadata={
            "keep": "unrelated metadata",
            "url_verification": {"status_code": 200, "reachable": True},
        },
    )

    result = await verify_evidence_records([record], concurrency=1)

    assert result[0] is record
    assert result[0].verification_state == "unknown"
    assert result[0].verification_observed_at is None
    assert "url_verification" not in result[0].metadata
    assert result[0].metadata["keep"] == "unrelated metadata"


@pytest.mark.asyncio
async def test_verification_disables_implicit_environment_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_options: dict[str, object] = {}

    class StubAsyncClient:
        def __init__(self, **kwargs) -> None:
            client_options.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> bool:
            return False

    class Result:
        reachable = True
        status_code = 200
        redirected = False
        location = None
        content_type = "text/html"

    async def fake_verify(url, *, timeout_seconds, client):
        return Result()

    monkeypatch.setattr(verification_module.httpx, "AsyncClient", StubAsyncClient)
    monkeypatch.setattr(verification_module, "verify_public_url", fake_verify)

    record = EvidenceRecord(
        evidence_id="proxy-policy",
        source="Example Security",
        source_type="security_publication",
        relation=EvidenceRelation.SECURITY_PUBLICATION,
        directness=EvidenceDirectness.CONTEXTUAL,
        confidence=0.65,
        observed_at="2026-10-05T00:00:00+00:00",
        published_at="2026-10-01T00:00:00+00:00",
        domain="example.com",
        url="https://example.com/report",
        title="Security report",
        summary="Security context.",
        assertion_scope="security_publication_context_only",
    )

    await verify_evidence_records([record], concurrency=1)

    assert client_options["trust_env"] is False
    assert client_options["follow_redirects"] is False


@pytest.mark.asyncio
async def test_malformed_metadata_does_not_downgrade_other_url_verification(monkeypatch):
    async def fake_verify(url, *, timeout_seconds, client):
        class Result:
            reachable = True
            status_code = 200
            redirected = False
            location = None
            content_type = "text/html"

        return Result()

    monkeypatch.setattr(verification_module, "verify_public_url", fake_verify)

    def make_record(evidence_id: str, url: str, metadata):
        return EvidenceRecord(
            evidence_id=evidence_id,
            source="Example Security",
            source_type="security_publication",
            relation=EvidenceRelation.SECURITY_PUBLICATION,
            directness=EvidenceDirectness.CONTEXTUAL,
            confidence=0.65,
            observed_at="2026-10-09T00:00:00+00:00",
            published_at="2026-10-01",
            domain="example.com",
            url=url,
            title="Security report",
            summary="Security context.",
            metadata=metadata,
            assertion_scope="security_publication_context_only",
        )

    malformed = make_record("malformed-metadata", "https://example.com/a", None)
    # Simulate a record reconstructed from a malformed payload: the model
    # normalizes metadata while verification is UNKNOWN, so install the
    # inconsistent legacy state the verifier must still handle defensively.
    malformed.metadata = None
    malformed.verification_state = "reachable"
    malformed.verification_observed_at = "2026-10-09T00:00:00+00:00"
    valid = make_record(
        "valid-metadata",
        "https://example.com/b",
        {"existing": "preserve"},
    )

    result = await verify_evidence_records([malformed, valid], concurrency=2)

    assert result[0].verification_state == "reachable"
    assert result[0].metadata["url_verification"]["status_code"] == 200
    assert result[1].verification_state == "reachable"
    assert result[1].metadata["existing"] == "preserve"
    assert result[1].metadata["url_verification"]["status_code"] == 200
