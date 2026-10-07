from __future__ import annotations

from pathlib import Path

from tests.scorecard.fixture_loader import (
    accepted_contextual_records,
    contextual_security_evidence_measurement,
    load_contextual_filter_dump,
)

FIXTURE = Path(__file__).parent / "fixtures" / "contextual_filter_dump.md"


def test_contextual_dump_parser_reads_before_and_after() -> None:
    dump = load_contextual_filter_dump(FIXTURE)

    for section in ("before", "after"):
        assert dump[section]["schema_version"] == "contextual-filter-dump-v2"
        assert isinstance(dump[section].get("records"), list)

    before_records = dump["before"]["records"]
    after_records = accepted_contextual_records(dump)

    # The fixture may be populated from a real application run, so record
    # counts are intentionally not hard-coded. The importer contract is what
    # this test owns: both sections are parsed and accepted records are
    # extractable from AFTER.
    assert all(isinstance(item, dict) for item in before_records)
    assert all(isinstance(item, dict) for item in after_records)
    assert len(after_records) <= len(before_records)


def test_contextual_dump_derives_only_supported_security_evidence_measurement() -> None:
    dump = load_contextual_filter_dump(FIXTURE)
    records = accepted_contextual_records(dump)

    measurement = contextual_security_evidence_measurement(dump)

    assert measurement["kpi_id"] == "relevant_security_evidence"
    assert measurement["unit"] == "count"
    assert measurement["value"] == len(records)
    assert measurement["state"] == "observed"
    assert measurement["source"] == "contextual_filter_dump"
    # The contextual filter dump is a filter-decision artifact, not a
    # serialized EvidenceRecord. It therefore does not provide evidence IDs
    # or EvidenceRecord assertion_scope.
    assert measurement["evidence_ids"] == []
    assert all(item.get("decision") == "accept" for item in records)
    assert all(item.get("signals", {}).get("security") is True for item in records)
