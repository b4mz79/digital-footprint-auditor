from __future__ import annotations

from typing import Any

from tests.scorecard.reference_engine import (
    EvalResult,
    evaluate_aggregation,
    evaluate_conditional,
    evaluate_dependency,
    evaluate_formula,
    evaluate_normalization,
    evaluate_weighted_sum,
)


class NativeReferenceAdapter:
    """Baseline adapter backed by our neutral semantic reference engine."""

    name = "native-reference"

    def weighted_sum(self, measurements: dict[str, dict[str, Any]], weights: dict[str, float]) -> EvalResult:
        return evaluate_weighted_sum(measurements, weights)

    def formula(self, left: EvalResult, right: EvalResult, *, operation: str) -> EvalResult:
        return evaluate_formula(left, right, operation=operation)

    def aggregation(self, results: list[EvalResult], *, operation: str, weights: list[float] | None = None) -> EvalResult:
        return evaluate_aggregation(results, operation=operation, weights=weights)

    def conditional(self, condition: bool | None, when_true: EvalResult, when_false: EvalResult) -> EvalResult:
        return evaluate_conditional(condition, when_true, when_false)

    def normalization(self, result: EvalResult, *, source_min: float, source_max: float, clamp: bool = False) -> EvalResult:
        return evaluate_normalization(result, source_min=source_min, source_max=source_max, clamp=clamp)

    def dependency(self, left: EvalResult, right: EvalResult, *, relation: str) -> EvalResult:
        return evaluate_dependency(left, right, relation=relation)
