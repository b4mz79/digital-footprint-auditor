from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"

def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

def test_measurement_contract_is_engine_neutral() -> None:
    data = _load("assessment_basic.json")
    assert data["schema_version"] == "scorecard-eval-v1"
    for item in data["kpis"]:
        assert {"id", "unit", "value", "state", "source"} <= item.keys()
        assert isinstance(item["id"], str)
        assert isinstance(item["unit"], str)
        assert item["state"] in {"observed", "unknown"}

def test_unit_and_value_are_measurement_data_not_formula_metadata() -> None:
    kpi = _load("assessment_basic.json")["kpis"][0]
    assert kpi["unit"] == "count"
    assert kpi["value"] == 10
    assert "formula" not in kpi
    assert "weight" not in kpi
