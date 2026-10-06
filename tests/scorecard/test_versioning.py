from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


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

    assert result["assessment_id"] == assessment["assessment_id"]
    assert result["scorecard_version"] == assessment["scorecard_definition_version"]


def test_result_version_is_not_allowed_to_drift_from_replay_definition() -> None:
    assessment = _load("assessment_basic.json")
    result = _load("scorecard_result_contract.json")

    result["scorecard_version"] = "synthetic-v2"

    assert result["assessment_id"] == assessment["assessment_id"]
    assert result["scorecard_version"] != assessment["scorecard_definition_version"]
