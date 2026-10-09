from __future__ import annotations

import pytest

from services.enrichment.evidence.models import (
    EvidenceDirectness,
    EvidenceRecord,
    EvidenceRelation,
)
from services.enrichment.evidence.security_publications import _normalize_source_timestamp


def _record(**overrides) -> EvidenceRecord:
    values = {
        "evidence_id": "temporal-test",
        "source": "Example Security",
        "source_type": "security_publication",
        "relation": EvidenceRelation.SECURITY_PUBLICATION,
        "directness": EvidenceDirectness.CONTEXTUAL,
        "confidence": 0.65,
        "observed_at": "2026-10-05T00:00:00+00:00",
        "published_at": "2026-10-01T00:00:00+00:00",
        "domain": "example.com",
        "url": "https://example.com/report",
        "title": "Security report",
        "summary": "Security context.",
        "assertion_scope": "security_publication_context_only",
    }
    values.update(overrides)
    return EvidenceRecord(**values)


def test_evidence_record_accepts_timezone_aware_temporal_fields() -> None:
    record = _record(
        observed_at="2026-10-05T03:00:00+03:00",
        published_at="2026-10-01T00:00:00Z",
        verification_observed_at="2026-10-05T03:05:00+03:00",
        verification_state="reachable",
    )

    assert record.observed_at == "2026-10-05T03:00:00+03:00"
    assert record.published_at == "2026-10-01T00:00:00Z"
    assert record.verification_observed_at == "2026-10-05T03:05:00+03:00"


@pytest.mark.parametrize(
    "field,value",
    [
        ("observed_at", "not-a-timestamp"),
        ("observed_at", "2026-10-05T03:00:00"),
        ("published_at", "not-a-timestamp"),
        ("verification_observed_at", "2026-10-05T03:05:00"),
    ],
)
def test_evidence_record_rejects_invalid_or_timezone_naive_timestamps(
    field: str,
    value: str,
) -> None:
    with pytest.raises(ValueError):
        _record(**{field: value, "verification_state": "reachable"})


def test_evidence_record_allows_missing_published_and_verification_timestamps() -> None:
    record = _record(
        published_at=None,
        verification_observed_at=None,
        verification_state="unknown",
    )

    assert record.published_at is None
    assert record.verification_observed_at is None


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z"),
        ("2026-10-01T00:00:00+00:00", "2026-10-01T00:00:00+00:00"),
        ("2026-10-01T03:00:00+03:00", "2026-10-01T03:00:00+03:00"),
    ],
)
def test_source_publication_timestamp_preserves_valid_timezone_aware_value(
    value: str,
    expected: str,
) -> None:
    assert _normalize_source_timestamp(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "2026-10-01T00:00:00",
        "January 2026",
        "not-a-timestamp",
    ],
)
def test_source_publication_timestamp_invalid_or_ambiguous_becomes_unknown(
    value: str | None,
) -> None:
    assert _normalize_source_timestamp(value) is None


def test_temporal_contract_does_not_infer_event_time() -> None:
    record = _record(
        title="Incident reported in January 2026",
        summary="The publication describes a historical incident.",
        published_at=None,
    )

    serialized = record.to_dict()

    assert serialized["published_at"] is None
    assert "event_at" not in serialized

def test_reachability_state_without_timestamp_is_downgraded_to_unknown() -> None:
    record = _record(
        verification_state="reachable",
        verification_observed_at=None,
        metadata={
            "keep": "unrelated metadata",
            "url_verification": {"status_code": 200, "reachable": True},
        },
    )

    assert record.verification_state == "unknown"
    assert record.verification_observed_at is None
    assert "url_verification" not in record.metadata
    assert record.metadata["keep"] == "unrelated metadata"


def test_unknown_verification_state_clears_stale_reachability_metadata() -> None:
    record = _record(
        verification_state="unknown",
        verification_observed_at="2026-10-05T03:05:00+03:00",
        metadata={
            "keep": "unrelated metadata",
            "url_verification": {"status_code": 200, "reachable": True},
        },
    )

    assert record.verification_state == "unknown"
    assert record.verification_observed_at is None
    assert "url_verification" not in record.metadata
    assert record.metadata["keep"] == "unrelated metadata"

