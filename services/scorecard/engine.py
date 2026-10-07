from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from .calculation import CalculationResult, ScorecardCalculationEngine
from .policy import ConditionEvaluator, PolicyDecision, RiskPolicyEngine
from .result import ScorecardResult, build_scorecard_result


class ScorecardEngine:
    """Self-contained calculation-to-result orchestration for one assessment."""

    def __init__(
        self,
        *,
        calculation_engine: ScorecardCalculationEngine | None = None,
        risk_policy_engine: RiskPolicyEngine | None = None,
    ) -> None:
        self.calculation = calculation_engine or ScorecardCalculationEngine()
        self.policy = risk_policy_engine or RiskPolicyEngine()

    def evaluate(
        self,
        *,
        assessment_id: str,
        scorecard_id: str,
        scorecard_version: str,
        result_id: str,
        measurements: Mapping[str, Mapping[str, Any]],
        weights: Mapping[str, float],
        normalization: Mapping[str, Any],
        risk_policy: Mapping[str, Any],
        condition_evaluator: ConditionEvaluator,
        measurement_refs: tuple[str, ...],
        calculated_at: str | None = None,
    ) -> ScorecardResult:
        aggregation = scorecard_definition.get("aggregation")
        score_config = scorecard_definition.get("score")
        if not isinstance(aggregation, Mapping) or not isinstance(score_config, Mapping):
            raise ValueError("scorecard definition requires aggregation and score")
        if aggregation.get("operation") != "weighted_sum":
            raise ValueError("current production engine requires weighted_sum aggregation")
        weights = aggregation.get("weights")
        canonical_range = score_config.get("canonical_range")
        if not isinstance(weights, Mapping) or not isinstance(canonical_range, Mapping):
            raise ValueError("scorecard definition requires weights and canonical_range")
        raw = self.calculation.weighted_sum(measurements, weights)
        normalized = self.calculation.normalization(
            raw,
            source_min=canonical_range["min"],
            source_max=canonical_range["max"],
            clamp=False,
            precision=int(score_config.get("precision", 2)),
        )

        policy_context = {
            "score": normalized.value,
            "score_state": normalized.state,
            "coverage": normalized.coverage,
            "measurements": dict(measurements),
        }
        if normalized.state == "unknown":
            decision = PolicyDecision(
                "condition_unknown",
                None,
                None,
                (),
                (),
            )
        else:
            decision = self.policy.evaluate(
                risk_policy,
                policy_context,
                condition_evaluator=condition_evaluator,
            )

        lineage = {
            "schema_version": "scorecard-lineage-v1",
            "inputs": list(measurement_refs),
            "steps": [
                {
                    "id": "weighted_sum-1",
                    "operation": "weighted_sum",
                    "inputs": list(measurement_refs),
                    "parameters": {"weights": dict(weights)},
                    "output": "weighted_sum-1",
                },
                {
                    "id": "normalization-1",
                    "operation": "normalization",
                    "inputs": ["weighted_sum-1"],
                    "parameters": {
                        "source_min": float(normalization["source_min"]),
                        "source_max": float(normalization["source_max"]),
                        "clamp": bool(normalization.get("clamp", False)),
                        "rounding": normalization.get("rounding", "half_even"),
                        "precision": int(normalization.get("precision", 2)),
                    },
                    "output": "score",
                },
            ],
            "output": "score",
        }
        policy_refs = {
            "risk_policy": str(risk_policy["risk_policy_id"]),
            "risk_policy_version": str(risk_policy["version"]),
            "score_policy": scorecard_version,
        }

        return build_scorecard_result(
            result_id=result_id,
            assessment_id=assessment_id,
            scorecard_id=scorecard_id,
            scorecard_version=scorecard_version,
            calculated_at=calculated_at or datetime.now(timezone.utc).isoformat(),
            calculation=normalized,
            contribution_details=raw.contribution_details,
            measurement_refs=measurement_refs,
            lineage=lineage,
            policy_refs=policy_refs,
            policy_decision=decision,
            contribution_stage="pre_normalization",
        )

    @staticmethod
    def replay(
        *,
        stored_assessment: Mapping[str, Any],
        scorecard_id: str,
        scorecard_version: str,
        result_id: str,
        measurements: Mapping[str, Mapping[str, Any]],
        weights: Mapping[str, float],
        normalization: Mapping[str, Any],
        risk_policy: Mapping[str, Any],
        condition_evaluator: ConditionEvaluator,
        measurement_refs: tuple[str, ...],
        calculated_at: str,
    ) -> ScorecardResult:
        return ScorecardEngine().evaluate(
            assessment_id=str(stored_assessment["assessment_id"]),
            scorecard_id=scorecard_id,
            scorecard_version=scorecard_version,
            result_id=result_id,
            measurements=measurements,
            scorecard_definition=scorecard_definition,
            risk_policy=risk_policy,
            condition_evaluator=condition_evaluator,
            measurement_refs=measurement_refs,
            calculated_at=calculated_at,
        )
