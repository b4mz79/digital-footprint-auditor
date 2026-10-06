from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class EvalResult:
    value: float | None
    state: str
    lineage: tuple[str, ...]
    contributions: tuple[tuple[str, float], ...] = ()


def _numeric(value: Any, *, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{label} must be finite")
    return result


def _weight(weight: Any, *, kpi_id: str) -> float:
    return _numeric(weight, label=f"weight[{kpi_id}]")


def _unknown_result(results: Iterable[EvalResult]) -> EvalResult:
    items = tuple(results)
    return EvalResult(
        value=None,
        state="unknown",
        lineage=tuple(sorted({item for result in items for item in result.lineage})),
        contributions=tuple(
            contribution
            for result in items
            for contribution in result.contributions
        ),
    )



def evaluate_weighted_sum(
    measurements: dict[str, dict[str, Any]],
    weights: dict[str, float],
) -> EvalResult:
    """Neutral reference semantics for engine compatibility tests only.

    Weight semantics are deliberately primitive: each weight is an explicit
    coefficient applied to its KPI value. The reference engine does not
    normalize weights or impose risk-direction semantics. Those are scorecard
    policy concerns and must remain configurable above this calculation layer.
    """
    contributions: list[tuple[str, float]] = []
    lineage: list[str] = []

    for kpi_id, weight in weights.items():
        item = measurements.get(kpi_id)
        if not item or item.get("state") == "unknown" or item.get("value") is None:
            return EvalResult(
                value=None,
                state="unknown",
                lineage=tuple(sorted({*lineage, kpi_id})),
                contributions=tuple(contributions),
            )

        value = _numeric(item["value"], label=kpi_id)
        weighted = value * _weight(weight, kpi_id=kpi_id)
        contributions.append((kpi_id, weighted))
        lineage.append(kpi_id)

    return EvalResult(
        value=sum(value for _, value in contributions),
        state="observed",
        lineage=tuple(lineage),
        contributions=tuple(contributions),
    )


def evaluate_formula(
    left: EvalResult,
    right: EvalResult,
    *,
    operation: str,
) -> EvalResult:
    """Neutral binary formula primitives for compatibility tests only."""
    lineage = tuple(sorted(set(left.lineage) | set(right.lineage)))
    contributions = left.contributions + right.contributions

    if left.state == "unknown" or right.state == "unknown":
        return EvalResult(
            value=None,
            state="unknown",
            lineage=lineage,
            contributions=contributions,
        )

    if left.value is None or right.value is None:
        raise ValueError("observed formula requires numeric values")

    if operation == "sum":
        value = left.value + right.value
    elif operation == "difference":
        value = left.value - right.value
    elif operation == "ratio":
        if right.value == 0:
            return EvalResult(
                value=None,
                state="unknown",
                lineage=lineage,
                contributions=contributions,
            )
        value = left.value / right.value
    else:
        raise ValueError(f"Unsupported synthetic formula: {operation}")

    return EvalResult(
        value=_numeric(value, label=f"formula[{operation}]"),
        state="observed",
        lineage=lineage,
        contributions=contributions,
    )


def evaluate_aggregation(
    results: list[EvalResult],
    *,
    operation: str,
    weights: list[float] | None = None,
) -> EvalResult:
    """Neutral aggregation primitives for compatibility tests only."""
    if not results:
        raise ValueError("aggregation requires at least one result")

    if any(result.state == "unknown" or result.value is None for result in results):
        return _unknown_result(results)

    values = [_numeric(result.value, label="aggregation input") for result in results]
    lineage = tuple(sorted({item for result in results for item in result.lineage}))
    contributions = tuple(
        contribution
        for result in results
        for contribution in result.contributions
    )

    if operation == "sum":
        value = sum(values)
    elif operation == "mean":
        value = sum(values) / len(values)
    elif operation == "min":
        value = min(values)
    elif operation == "max":
        value = max(values)
    elif operation == "weighted_sum":
        if weights is None:
            raise ValueError("weighted_sum aggregation requires weights")
        if len(weights) != len(results):
            raise ValueError("weighted_sum weights must match result count")
        weighted_values: list[float] = []
        for index, result in enumerate(results):
            weight = _numeric(weights[index], label=f"weight[{index}]")
            weighted_values.append(result.value * weight)  # type: ignore[operator]
        value = sum(weighted_values)
    else:
        raise ValueError(f"Unsupported synthetic aggregation: {operation}")

    return EvalResult(
        value=_numeric(value, label=f"aggregation[{operation}]"),
        state="observed",
        lineage=lineage,
        contributions=contributions,
    )


def evaluate_normalization(
    result: EvalResult,
    *,
    source_min: float,
    source_max: float,
    clamp: bool = False,
) -> EvalResult:
    """Normalize an observed result to the canonical [0.0, 1.0] range.

    This is a neutral calculation primitive for compatibility tests only.
    Source bounds and out-of-range behavior are explicit configuration; the
    primitive does not infer score direction or risk thresholds.
    """
    lineage = result.lineage
    contributions = result.contributions

    if result.state == "unknown" or result.value is None:
        return EvalResult(None, "unknown", lineage, contributions)

    value = _numeric(result.value, label="normalization input")
    lower = _numeric(source_min, label="source_min")
    upper = _numeric(source_max, label="source_max")

    if lower >= upper:
        raise ValueError("source_min must be less than source_max")

    if value < lower or value > upper:
        if not clamp:
            raise ValueError("normalization input is outside source range")
        value = min(max(value, lower), upper)

    normalized = round((value - lower) / (upper - lower), 2)
    return EvalResult(
        value=_numeric(normalized, label="normalized score"),
        state="observed",
        lineage=lineage,
        contributions=contributions,
    )


def evaluate_dependency(
    left: EvalResult,
    right: EvalResult,
    *,
    relation: str,
) -> EvalResult:
    """Small dependency primitive for testing UNKNOWN and lineage propagation."""
    lineage = tuple(sorted(set(left.lineage) | set(right.lineage)))
    contributions = left.contributions + right.contributions
    if left.state == "unknown" or right.state == "unknown":
        return EvalResult(None, "unknown", lineage, contributions)
    if left.value is None or right.value is None:
        raise ValueError("observed dependency requires numeric values")
    if relation == "sum":
        value = left.value + right.value
    elif relation == "max":
        value = max(left.value, right.value)
    else:
        raise ValueError(f"Unsupported synthetic relation: {relation}")
    return EvalResult(
        value=_numeric(value, label=f"dependency[{relation}]"),
        state="observed",
        lineage=lineage,
        contributions=contributions,
    )
