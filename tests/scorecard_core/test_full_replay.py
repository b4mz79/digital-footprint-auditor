from __future__ import annotations

from services.scorecard.engine import ScorecardEngine
from services.scorecard.sqlite_store import SQLiteScorecardStore
from services.scorecard.policy import CONDITION_MATCH, CONDITION_NO_MATCH, CONDITION_UNKNOWN


def _predicate(condition, context):
    score = context["score"]
    if condition["type"] == "score_at_least":
        return CONDITION_MATCH if score is not None and score >= condition["parameters"]["value"] else CONDITION_NO_MATCH
    raise ValueError("unsupported synthetic predicate")


def _policy():
    return {
        "risk_policy_id": "policy-v1",
        "version": "1",
        "output": {"risk_bands": ["high", "medium", "low", "unknown"]},
        "mapping": {
            "rules": [
                {"rule_id": "high", "priority": 10, "condition": {"type": "score_at_least", "parameters": {"value": 0.8}}, "then": "high"},
                {"rule_id": "medium", "priority": 20, "condition": {"type": "score_at_least", "parameters": {"value": 0.5}}, "then": "medium"},
                {"rule_id": "low", "priority": 30, "condition": {"type": "score_at_least", "parameters": {"value": 0.0}}, "then": "low"},
            ],
        },
    }


def _evaluate(score_a, score_b):
    return ScorecardEngine().evaluate(
        assessment_id="assessment-1",
        scorecard_id="scorecard-1",
        scorecard_version="v1",
        result_id="result-1",
        measurements={
            "a": {"value": score_a, "state": "observed"},
            "b": {"value": score_b, "state": "observed"},
        },
        scorecard_definition={
            "schema_version": "scorecard-definition-v1",
            "scorecard_id": "scorecard-1",
            "version": "v1",
            "score": {
                "canonical_range": {"min": 0.0, "max": 10.0},
                "precision": 2,
                "rounding": "half_even",
            },
            "aggregation": {
                "operation": "weighted_sum",
                "weights": {"a": 0.6, "b": 0.4},
            },
        },
        risk_policy=_policy(),
        condition_evaluator=_predicate,
        measurement_refs=("measurement-a", "measurement-b"),
        calculated_at="2026-10-07T00:01:00+07:00",
    )


def test_full_replay_produces_score_and_policy_result():
    result = _evaluate(10, 4)
    assert result.score == 0.76
    assert result.state == "observed"
    assert result.risk_band == "medium"
    assert result.contributions[0].kpi_id == "a"
    assert result.contributions[0].contribution == 6.0
    assert result.policy_refs == {
        "risk_policy": "policy-v1",
        "risk_policy_version": "1",
        "score_policy": "v1",
    }
    assert result.calculation_lineage["output"] == "score"


def test_full_replay_is_deterministic():
    first = _evaluate(10, 4)
    second = _evaluate(10, 4)
    assert first == second


def test_full_replay_unknown_score_stays_unknown():
    result = ScorecardEngine().evaluate(
        assessment_id="assessment-unknown",
        scorecard_id="scorecard-1",
        scorecard_version="v1",
        result_id="result-unknown",
        measurements={
            "a": {"value": 10, "state": "observed"},
            "b": {"value": None, "state": "unknown"},
        },
        scorecard_definition={
            "schema_version": "scorecard-definition-v1",
            "scorecard_id": "scorecard-1",
            "version": "v1",
            "score": {
                "canonical_range": {"min": 0.0, "max": 10.0},
                "precision": 2,
                "rounding": "half_even",
            },
            "aggregation": {
                "operation": "weighted_sum",
                "weights": {"a": 0.6, "b": 0.4},
            },
        },
        risk_policy=_policy(),
        condition_evaluator=_predicate,
        measurement_refs=("measurement-a", "measurement-b"),
        calculated_at="2026-10-07T00:01:00+07:00",
    )
    assert result.state == "unknown"
    assert result.score is None
    assert result.risk_band == "unknown"


def test_replay_identity_does_not_depend_on_current_clock():
    result = _evaluate(10, 4)
    assert result.calculated_at == "2026-10-07T00:01:00+07:00"


def test_full_replay_result_round_trips_through_sqlite(tmp_path):
    result = _evaluate(10, 4)
    store = SQLiteScorecardStore(tmp_path / "scorecard.db")
    store.save_result(result.to_record())

    restored = store.get_result(result.result_id)
    assert restored is not None
    assert restored.result == result.to_dict()
    assert restored.assessment_id == result.assessment_id
    assert restored.calculated_at == result.calculated_at
