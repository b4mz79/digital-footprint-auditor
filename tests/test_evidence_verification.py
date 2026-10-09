from __future__ import annotations

from services.enrichment.evidence.models import (
    EvidenceDirectness,
    EvidenceRecord,
    EvidenceRelation,
)
from services.enrichment.evidence.url_verifier import URLVerification
from services.enrichment import verification


def _record(evidence_id: str, *, metadata, url: str) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id,
        source="Example",
        source_type="osint",
        relation=EvidenceRelation.TARGET_RESOURCE,
        directness=EvidenceDirectness.DIRECT,
        confidence=0.8,
        observed_at="2026-10-09T00:00:00+00:00",
        published_at=None,
        domain="example.com",
        url=url,
        title=evidence_id,
        summary="Test evidence",
        metadata=metadata,
        verification_state="unknown",
    )


async def test_malformed_metadata_does_not_downgrade_other_url_verification(monkeypatch):
    async def fake_verify_public_url(url, **kwargs):
        return URLVerification(
            url=url,
            reachable=True,
            status_code=200,
            final_url=url,
            content_type="text/html",
            redirected=False,
            location=None,
            title="",
        )

    monkeypatch.setattr(verification, "verify_public_url", fake_verify_public_url)
    malformed = _record("malformed", metadata=None, url="https://example.com/a")
    valid = _record(
        "valid",
        metadata={"existing": "preserve"},
        url="https://example.com/b",
    )

    result = await verification.verify_evidence_records([malformed, valid])

    assert result[0].verification_state == "reachable"
    assert result[0].metadata["url_verification"]["status_code"] == 200
    assert result[1].verification_state == "reachable"
    assert result[1].metadata["existing"] == "preserve"
    assert result[1].metadata["url_verification"]["status_code"] == 200
