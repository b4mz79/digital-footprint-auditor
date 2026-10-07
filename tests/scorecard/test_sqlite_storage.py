from __future__ import annotations

import sqlite3

import pytest

from addons.scorecard.models import (
    AssessmentRecord,
    RiskPolicyRecord,
    ScorecardDefinitionRecord,
    ScorecardResultRecord,
)
from addons.scorecard.sqlite_store import SQLiteScorecardStore


def make_store(tmp_path):
    store = SQLiteScorecardStore(tmp_path / "scorecard.db")
    store.initialize()
    return store


def test_store_auto_initializes_without_explicit_setup(tmp_path):
    store = SQLiteScorecardStore(tmp_path / "nested" / "scorecard.db")
    assert (tmp_path / "nested" / "scorecard.db").exists()


def test_sqlite_initializes_only_minimal_persistence_tables(tmp_path):
    store = make_store(tmp_path)

    with sqlite3.connect(tmp_path / "scorecard.db") as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert tables == {
        "scorecard_definitions",
        "risk_policies",
        "assessments",
        "results",
    }


def test_definition_round_trip_preserves_json_snapshot(tmp_path):
    store = make_store(tmp_path)
    payload = {"schema_version": "scorecard-definition-v1", "weights": {"a": 0.6}}
    record = ScorecardDefinitionRecord("privacy-assessment", "v1", payload)
    payload["weights"]["a"] = 0.1

    store.save_definition(record)

    assert store.get_definition("privacy-assessment", "v1") == record
    assert store.get_definition("privacy-assessment", "missing") is None


def test_snapshot_models_deep_copy_nested_payloads():
    payload = {"nested": {"value": 1}}
    record = ScorecardDefinitionRecord("privacy-assessment", "v1", payload)

    payload["nested"]["value"] = 99

    assert record.definition["nested"]["value"] == 1


def test_policy_round_trip(tmp_path):
    store = make_store(tmp_path)
    record = RiskPolicyRecord(
        "privacy-risk",
        "v1",
        {"schema_version": "risk-policy-v1", "mapping": {"rules": []}},
    )

    store.save_policy(record)

    assert store.get_policy("privacy-risk", "v1") == record


def test_assessment_is_immutable_snapshot(tmp_path):
    store = make_store(tmp_path)
    record = AssessmentRecord(
        "assessment-001",
        "2026-10-07T10:00:00+07:00",
        {"schema_version": "scorecard-eval-v1", "kpis": [{"id": "a", "value": 1}]},
    )

    store.save_assessment(record)

    with pytest.raises(ValueError, match="immutable"):
        store.save_assessment(record)

    assert store.get_assessment("assessment-001") == record


def test_result_is_append_only_and_can_have_multiple_results_per_assessment(tmp_path):
    store = make_store(tmp_path)
    first = ScorecardResultRecord(
        "result-001",
        "assessment-001",
        "2026-10-07T10:01:00+07:00",
        {"score": 0.7, "state": "observed"},
    )
    second = ScorecardResultRecord(
        "result-002",
        "assessment-001",
        "2026-10-07T10:02:00+07:00",
        {"score": 0.8, "state": "observed"},
    )

    store.save_result(first)
    store.save_result(second)

    with pytest.raises(ValueError, match="immutable"):
        store.save_result(first)

    assert store.get_result("result-001") == first
    assert store.list_results_for_assessment("assessment-001") == (first, second)


def test_result_storage_does_not_require_assessment_row(tmp_path):
    store = make_store(tmp_path)
    result = ScorecardResultRecord(
        "result-standalone",
        "assessment-not-persisted",
        "2026-10-07T10:03:00+07:00",
        {"score": None, "state": "unknown"},
    )

    store.save_result(result)

    assert store.get_result("result-standalone") == result


def test_json_payload_rejects_non_finite_numbers(tmp_path):
    store = make_store(tmp_path)
    record = ScorecardDefinitionRecord(
        "privacy-assessment",
        "v1",
        {"weight": float("nan")},
    )

    with pytest.raises(ValueError, match="Out of range float"):
        store.save_definition(record)


def test_model_contract_rejects_empty_identity():
    with pytest.raises(ValueError, match="scorecard_id"):
        ScorecardDefinitionRecord("", "v1", {})

    with pytest.raises(ValueError, match="policy_id"):
        RiskPolicyRecord("", "v1", {})

    with pytest.raises(ValueError, match="assessment_id"):
        AssessmentRecord("", "now", {})

    with pytest.raises(ValueError, match="result_id"):
        ScorecardResultRecord("", "assessment", "now", {})
