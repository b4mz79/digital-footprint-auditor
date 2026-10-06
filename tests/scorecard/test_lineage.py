from __future__ import annotations

import json
from pathlib import Path

from tests.scorecard.reference_engine import evaluate_weighted_sum

FIXTURES = Path(__file__).parent / "fixtures"

def test_measurement_keeps_evidence_lineage() -> None:
    data = json.loads((FIXTURES / "assessment_basic.json").read_text(encoding="utf-8"))
    evidence_kpi = next(item for item in data["kpis"] if item["id"] == "relevant_security_evidence")
    assert evidence_kpi["source"] == "contextual_filter_dump"
    assert evidence_kpi["evidence_ids"] == ["evidence-security-1"]

def test_reference_result_lineage_is_explicit() -> None:
    measurements = {
        "a": {"unit": "count", "value": 10, "state": "observed", "evidence_ids": ["evidence-a"]},
        "b": {"unit": "count", "value": 4, "state": "observed", "evidence_ids": ["evidence-b"]},
    }
    result = evaluate_weighted_sum(measurements, {"a": 0.6, "b": 0.4})
    assert result.lineage == ("a", "b")
