from __future__ import annotations

from pathlib import Path

from tests.scorecard.fixture_loader import (
    accepted_contextual_records,
    contextual_security_evidence_measurement,
    load_contextual_filter_dump,
)

FIXTURE = Path(__file__).parent / "fixtures" / "contextual_filter_dump.sample.md"

def test_contextual_dump_parser_reads_before_and_after() -> None:
    dump = load_contextual_filter_dump(FIXTURE)
    assert dump["before"]["schema_version"] == "contextual-filter-dump-v2"
    assert len(dump["before"]["candidates"]) == 2
    assert len(accepted_contextual_records(dump)) == 1

def test_contextual_dump_derives_only_supported_security_evidence_measurement() -> None:
    measurement = contextual_security_evidence_measurement(load_contextual_filter_dump(FIXTURE))
    assert measurement == {
        "kpi_id": "relevant_security_evidence",
        "unit": "count",
        "value": 1,
        "state": "observed",
        "source": "contextual_filter_dump",
        "evidence_ids": ["evidence-security-1"],
    }
