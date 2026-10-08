from __future__ import annotations

import pytest

from services.enrichment.evidence.models import EvidenceDirectness, EvidenceRecord, EvidenceRelation
from services.enrichment.verification import verify_evidence_records


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
    )

    result = await verify_evidence_records([record])

    assert result[0].verification_state == "unknown"
    assert result[0].verification_observed_at is None


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

    result = await verify_evidence_records([good, bad], concurrency=2)

    assert calls == ["https://example.com/good", "https://example.com/bad"]
    assert result[0].verification_state == "reachable"
    assert result[0].verification_observed_at
    assert result[1].verification_state == "unknown"
    assert result[1].verification_observed_at is None


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
    )

    result = await verify_evidence_records([record], enabled=False)

    assert result[0] is record
    assert result[0].verification_state == "unknown"
    assert result[0].verification_observed_at is None
