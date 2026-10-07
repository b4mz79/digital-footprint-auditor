from __future__ import annotations

from services.scorecard.integration import (
    PipelineAssessmentAdapter,
    evaluate_pipeline_scorecard,
    threshold_condition_evaluator,
)
from services.scorecard.policy import CONDITION_MATCH, CONDITION_UNKNOWN


def _state(*, breach_complete: bool = True) -> dict:
    return {
        "services": [
            {"name": "Example", "domain": "example.com"},
            {"name": "Other", "domain": "other.example"},
        ],
        "evidence": [
            {
                "evidence_id": "service-1",
                "source": "OSINT",
                "source_type": "scanner",
                "relation": "target_resource",
                "directness": "direct",
                "observed_at": "2026-10-07T01:00:00+00:00",
                "domain": "example.com",
                "provenance": {
                    "service_name": "Example",
                    "scanner_source": "OSINT",
                },
                "metadata": {"finding_type": "service_discovery"},
                "verification_state": "reachable",
            },
            {
                "evidence_id": "security-1",
                "source": "Securelist",
                "source_type": "security_publication",
                "relation": "security_publication",
                "directness": "contextual",
                "observed_at": "2026-10-07T01:00:00+00:00",
                "domain": "example.com",
                "provenance": {"service_name": "Example"},
                "metadata": {"finding_type": "security_context"},
                "verification_state": "unknown",
            },
        ],
        "breach": {
            "complete": breach_complete,
            "findings": [{"kind": "breach_db", "dataset": "example"}],
        },
    }


def _definition() -> dict:
    return {
        "schema_version": "scorecard-definition-v1",
        "scorecard_id": "integration-scorecard",
        "version": "v1",
        "score": {
            "canonical_range": {"min": 0.0, "max": 10.0},
            "precision": 2,
            "rounding": "half_even",
        },
        "aggregation": {
            "operation": "weighted_sum",
            "weights": {"service_discovery_count": 1.0},
        },
    }


def _policy() -> dict:
    return {
        "schema_version": "risk-policy-v1",
        "risk_policy_id": "integration-policy",
        "version": "v1",
        "output": {"risk_bands": ["high", "medium", "low", "unknown"]},
        "mapping": {
            "rules": [
                {
                    "rule_id": "high",
                    "priority": 10,
                    "condition": {
                        "type": "score_threshold",
                        "parameters": {"operator": ">=", "value": 0.8},
                    },
                    "then": "high",
                },
                {
                    "rule_id": "low",
                    "priority": 20,
                    "condition": {
                        "type": "score_threshold",
                        "parameters": {"operator": ">=", "value": 0.0},
                    },
                    "then": "low",
                },
            ]
        },
    }


def test_pipeline_adapter_derives_real_chain_measurements() -> None:
    result = PipelineAssessmentAdapter.to_input(
        _state(),
        assessment_id="assessment-integration",
        created_at="2026-10-07T01:00:00+00:00",
    )

    assert result.measurements["service_discovery_count"]["value"] == 2
    assert result.measurements["evidence_backed_service_count"]["value"] == 1
    assert result.measurements["relevant_security_evidence"]["value"] == 1
    assert result.measurements["evidence_record_coverage"]["value"] == 0.5
    assert result.measurements["verification_coverage"]["value"] == 0.5
    assert result.measurements["breach_finding_count"]["value"] == 1
    assert result.measurements["url_accessibility_state"]["value"] == {
        "reachable": 1,
        "unreachable": 0,
        "unknown": 1,
    }


def test_incomplete_breach_is_unknown_not_zero() -> None:
    result = PipelineAssessmentAdapter.to_input(
        _state(breach_complete=False),
        assessment_id="assessment-incomplete",
        created_at="2026-10-07T01:00:00+00:00",
    )

    measurement = result.measurements["breach_finding_count"]
    assert measurement["value"] is None
    assert measurement["state"] == "unknown"


def test_threshold_condition_preserves_unknown() -> None:
    assert threshold_condition_evaluator(
        {"type": "score_threshold", "parameters": {"operator": ">=", "value": 0.8}},
        {"score": None},
    ) == CONDITION_UNKNOWN
    assert threshold_condition_evaluator(
        {"type": "score_threshold", "parameters": {"operator": ">=", "value": 0.8}},
        {"score": 0.9},
    ) == CONDITION_MATCH


def test_pipeline_result_enters_scorecard_add_on() -> None:
    scorecard_input, result = evaluate_pipeline_scorecard(
        _state(),
        scorecard_definition=_definition(),
        risk_policy=_policy(),
        assessment_id="assessment-real-chain",
        result_id="result-real-chain",
        calculated_at="2026-10-07T01:00:00+00:00",
    )

    assert scorecard_input.assessment_id == "assessment-real-chain"
    assert result.assessment_id == "assessment-real-chain"
    assert result.score == 0.2
    assert result.risk_band == "low"
    assert result.measurement_refs == tuple(scorecard_input.measurements.keys())
