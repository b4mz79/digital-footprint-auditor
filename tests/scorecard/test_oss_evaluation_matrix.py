from __future__ import annotations

import json
from pathlib import Path


MATRIX = Path(__file__).parent / "oss_evaluation_matrix.json"


def test_oss_evaluation_matrix_is_complete_and_not_prejudged() -> None:
    data = json.loads(MATRIX.read_text(encoding="utf-8"))

    assert data["schema_version"] == "scorecard-oss-evaluation-v1"
    assert data["status"] == "evaluation_ready"

    required_dimensions = {
        "calculation_semantics",
        "unknown_partial_semantics",
        "determinism",
        "lineage",
        "contribution",
        "version_isolation",
        "adapter_complexity",
        "dependency_cost",
        "operational_cost",
    }
    assert set(data["comparison_scope"]) == required_dimensions

    candidates = {item["id"]: item for item in data["candidates"]}
    assert candidates["native-reference"]["status"] == "baseline"

    oss_candidates = {
        candidate_id: item
        for candidate_id, item in candidates.items()
        if item["kind"] == "oss-candidate"
    }
    assert oss_candidates
    assert all(item["status"] == "not_evaluated" for item in oss_candidates.values())

    for candidate_id in oss_candidates:
        assert data["verdicts"][candidate_id] == "not_evaluated"

    assert data["decision_rule"]["reference_engine_is_not_an_adoption_candidate"] is True
