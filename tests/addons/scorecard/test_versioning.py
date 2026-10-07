from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _assert_result_version_matches_assessment(
    assessment: dict, result: dict
) -> None:
    assert result["assessment_id"] == assessment["assessment_id"]
    assert result["scorecard_version"] == assessment["scorecard_definition_version"]


def test_scorecard_definition_version_is_explicit() -> None:
    assert _load("assessment_basic.json")["scorecard_definition_version"] == "synthetic-v1"


def test_same_measurements_can_be_replayed_against_different_definition_versions() -> None:
    first = _load("assessment_basic.json")
    second = json.loads(json.dumps(first))
    second["scorecard_definition_version"] = "synthetic-v2"

    assert first["assessment_id"] == second["assessment_id"]
    assert first["kpis"] == second["kpis"]
    assert first["scorecard_definition_version"] != second["scorecard_definition_version"]


def test_result_binds_to_the_assessment_definition_version() -> None:
    assessment = _load("assessment_basic.json")
    result = _load("scorecard_result_contract.json")

    _assert_result_version_matches_assessment(assessment, result)


def test_result_version_drift_is_rejected_for_the_same_assessment() -> None:
    assessment = _load("assessment_basic.json")
    result = _load("scorecard_result_contract.json")
    result["scorecard_version"] = "synthetic-v2"

    with pytest.raises(AssertionError):
        _assert_result_version_matches_assessment(assessment, result)
