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
