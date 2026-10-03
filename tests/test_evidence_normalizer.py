from __future__ import annotations

from services.evidence.normalizer import service_findings_to_evidence


def test_service_finding_from_osint_becomes_target_resource_evidence() -> None:
    records = service_findings_to_evidence(
        [
            {
                "name": "Example",
                "domain": "sub.example.com",
                "source": "OSINT / Holehe",
                "subject": "Active account detected",
            }
        ],
        observed_at="2026-10-03T00:00:00+00:00",
    )

    assert len(records) == 1
    record = records[0]

    assert record.source_type == "osint"
    assert record.relation.value == "target_resource"
    assert record.directness.value == "direct"
    assert record.domain == "example.com"
    assert record.observed_at == "2026-10-03T00:00:00+00:00"
    assert record.provenance["assertion_scope"] == "service_association_only"
    assert record.metadata["finding_type"] == "service_discovery"


def test_service_finding_normalization_deduplicates_identical_findings() -> None:
    finding = {
        "name": "Example",
        "domain": "example.com",
        "source": "OSINT / Holehe",
        "subject": "Active account detected",
    }

    records = service_findings_to_evidence([finding, dict(finding)])

    assert len(records) == 1


def test_invalid_service_domains_are_not_promoted_to_evidence() -> None:
    records = service_findings_to_evidence(
        [
            {
                "name": "Bad",
                "domain": "user@example.com",
                "source": "OSINT / Holehe",
                "subject": "Active account detected",
            },
            {
                "name": "Private",
                "domain": "127.0.0.1",
                "source": "OSINT / Holehe",
                "subject": "Active account detected",
            },
        ]
    )

    assert records == []
