from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any


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


def evaluate_weighted_sum(
    measurements: dict[str, dict[str, Any]],
    weights: dict[str, float],
) -> EvalResult:
    """Neutral reference semantics for engine compatibility tests only."""
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


def evaluate_dependency(
    left: EvalResult,
    right: EvalResult,
    *,
    relation: str,
) -> EvalResult:
    """Small dependency primitive for testing UNKNOWN and lineage propagation."""
    lineage = tuple(sorted(set(left.lineage) | set(right.lineage)))
    if left.state == "unknown" or right.state == "unknown":
        return EvalResult(
            value=None,
            state="unknown",
            lineage=lineage,
            contributions=left.contributions + right.contributions,
        )

    if left.value is None or right.value is None:
        raise ValueError("observed dependency requires numeric values")

    if relation == "sum":
        value = left.value + right.value
    elif relation == "max":
        value = max(left.value, right.value)
    else:
        raise ValueError(f"Unsupported synthetic relation: {relation}")

    return EvalResult(
        value=value,
        state="observed",
        lineage=lineage,
        contributions=left.contributions + right.contributions,
    )
