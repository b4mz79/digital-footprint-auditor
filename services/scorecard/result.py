from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import math
from typing import Any, Mapping

from .calculation import CalculationResult, ContributionDetail
from .policy import PolicyDecision


@dataclass(frozen=True, slots=True)
class ScorecardResult:
    """Self-contained final result snapshot emitted by the Scorecard add-on."""

    result_id: str
    assessment_id: str
    scorecard_id: str
    scorecard_version: str
    calculated_at: str
    state: str
    score: float | None
    risk_band: str
    dimension_results: tuple[Mapping[str, Any], ...]
    contributions: tuple[ContributionDetail, ...]
    measurement_refs: tuple[str, ...]
    calculation_lineage: Mapping[str, Any]
    policy_refs: Mapping[str, str]
    contribution_stage: str | None = None

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value
            for value in (
                self.result_id,
                self.assessment_id,
                self.scorecard_id,
                self.scorecard_version,
                self.calculated_at,
            )
        ):
            raise ValueError("result identity fields must be non-empty strings")
        if self.state not in {"observed", "partial", "unknown"}:
            raise ValueError("unsupported result state")
        if self.risk_band not in {"high", "medium", "low", "unknown"}:
            raise ValueError("unsupported risk band")

        parsed = datetime.fromisoformat(self.calculated_at)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("calculated_at must be timezone-aware")

        if self.state == "unknown":
            if self.score is not None:
                raise ValueError("unknown result must not have a score")
        else:
            if self.score is None or isinstance(self.score, bool):
                raise ValueError("known result requires a numeric score")
            if not math.isfinite(float(self.score)) or not 0.0 <= float(self.score) <= 1.0:
                raise ValueError("score must be finite and within [0, 1]")

        if not self.measurement_refs or len(self.measurement_refs) != len(set(self.measurement_refs)):
            raise ValueError("measurement_refs must be non-empty and unique")
        if self.contribution_stage is not None and self.contribution_stage not in {
            "pre_normalization", "aggregation", "dimension", "final_score"
        }:
            raise ValueError("unsupported contribution stage")


def build_scorecard_result(
    *,
    result_id: str,
    assessment_id: str,
    scorecard_id: str,
    scorecard_version: str,
    calculated_at: str,
    calculation: CalculationResult,
    measurement_refs: tuple[str, ...],
    lineage: Mapping[str, Any],
    policy_refs: Mapping[str, str],
    policy_decision: PolicyDecision,
    dimension_results: tuple[Mapping[str, Any], ...] = (),
    contribution_stage: str | None = None,
) -> ScorecardResult:
    if policy_decision.status == "matched":
        risk_band = policy_decision.risk_band
    else:
        risk_band = "unknown"

    return ScorecardResult(
        result_id=result_id,
        assessment_id=assessment_id,
        scorecard_id=scorecard_id,
        scorecard_version=scorecard_version,
        calculated_at=calculated_at,
        state=calculation.state,
        score=calculation.value,
        risk_band=risk_band or "unknown",
        dimension_results=tuple(dict(item) for item in dimension_results),
        contributions=calculation.contribution_details,
        measurement_refs=measurement_refs,
        calculation_lineage=dict(lineage),
        policy_refs=dict(policy_refs),
        contribution_stage=contribution_stage,
    )
