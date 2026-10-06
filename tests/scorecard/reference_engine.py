from __future__ import annotations

from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True, slots=True)
class EvalResult:
    value: float | None
    state: str
    lineage: tuple[str, ...]

def evaluate_weighted_sum(
    measurements: dict[str, dict[str, Any]],
    weights: dict[str, float],
) -> EvalResult:
    """Neutral reference semantics for engine compatibility tests only."""
    contributions: list[float] = []
    lineage: list[str] = []
    for kpi_id, weight in weights.items():
        item = measurements.get(kpi_id)
        if not item or item.get("state") == "unknown" or item.get("value") is None:
            return EvalResult(
                value=None,
                state="unknown",
                lineage=tuple(sorted({*lineage, kpi_id})),
            )
        value = item["value"]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise TypeError(f"{kpi_id} must contain a numeric value")
        contributions.append(float(value) * float(weight))
        lineage.append(kpi_id)
    return EvalResult(sum(contributions), "observed", tuple(lineage))

def evaluate_dependency(
    left: EvalResult,
    right: EvalResult,
    *,
    relation: str,
) -> EvalResult:
    """Small dependency primitive for testing UNKNOWN and lineage propagation."""
    lineage = tuple(sorted(set(left.lineage) | set(right.lineage)))
    if left.state == "unknown" or right.state == "unknown":
        return EvalResult(value=None, state="unknown", lineage=lineage)
    if relation == "sum":
        assert left.value is not None and right.value is not None
        return EvalResult(left.value + right.value, "observed", lineage)
    if relation == "max":
        assert left.value is not None and right.value is not None
        return EvalResult(max(left.value, right.value), "observed", lineage)
    raise ValueError(f"Unsupported synthetic relation: {relation}")
