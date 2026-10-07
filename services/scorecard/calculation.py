from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Iterable, Mapping


VALID_STATES = {"observed", "partial", "unknown"}


@dataclass(frozen=True, slots=True)
class ContributionDetail:
    """Additive contribution detail for a calculation stage."""

    kpi_id: str
    value: float
    weight: float
    contribution: float


@dataclass(frozen=True, slots=True)
class CalculationResult:
    """Deterministic calculation result with explicit state and lineage."""

    value: float | None
    state: str
    lineage: tuple[str, ...]
    contributions: tuple[tuple[str, float], ...] = ()
    contribution_details: tuple[ContributionDetail, ...] = ()
    coverage: float | None = None
    known_weight: float | None = None
    unknown_weight: float | None = None

    def __post_init__(self) -> None:
        if self.state not in VALID_STATES:
            raise ValueError(f"unsupported calculation state: {self.state}")
        if self.state == "unknown":
            if self.value is not None:
                raise ValueError("unknown calculation result must not have a value")
        elif self.value is None:
            raise ValueError("known calculation result requires a value")

        for item in self.lineage:
            if not isinstance(item, str) or not item:
                raise ValueError("calculation lineage entries must be non-empty strings")
        if len(self.lineage) != len(set(self.lineage)):
            raise ValueError("calculation lineage must not contain duplicates")

        if self.coverage is not None:
            coverage = _numeric(self.coverage, label="coverage")
            if not 0.0 <= coverage <= 1.0:
                raise ValueError("coverage must be within [0, 1]")
            if self.state == "observed" and coverage != 1.0:
                raise ValueError("observed result must have full coverage")
            if self.state == "partial" and not 0.0 < coverage < 1.0:
                raise ValueError("partial result must have partial coverage")

        for label, value in (
            ("known_weight", self.known_weight),
            ("unknown_weight", self.unknown_weight),
        ):
            if value is not None and _numeric(value, label=label) < 0.0:
                raise ValueError(f"{label} must not be negative")


def _numeric(value: Any, *, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{label} must be finite")
    return result


def _coverage(result: CalculationResult, *, label: str) -> float:
    value = 1.0 if result.state == "observed" else result.coverage
    if value is None:
        raise ValueError(f"{label} requires coverage for partial input")
    value = _numeric(value, label=label)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{label} must be within [0, 1]")
    return value


def _scale_details(
    details: Iterable[ContributionDetail],
    factor: float,
) -> tuple[ContributionDetail, ...]:
    return tuple(
        ContributionDetail(
            detail.kpi_id,
            detail.value,
            detail.weight * factor,
            detail.contribution * factor,
        )
        for detail in details
    )


def _details_to_contributions(
    details: Iterable[ContributionDetail],
) -> tuple[tuple[str, float], ...]:
    return tuple((detail.kpi_id, detail.contribution) for detail in details)


def _unknown_result(results: Iterable[CalculationResult]) -> CalculationResult:
    items = tuple(results)
    return CalculationResult(
        value=None,
        state="unknown",
        lineage=tuple(sorted({item for result in items for item in result.lineage})),
        contributions=tuple(
            contribution
            for result in items
            for contribution in result.contributions
        ),
        contribution_details=tuple(
            detail
            for result in items
            for detail in result.contribution_details
        ),
    )


class ScorecardCalculationEngine:
    """Native deterministic calculation primitives for the Scorecard add-on.

    This is the production semantic layer. It deliberately owns calculation
    mechanics only; score direction, risk thresholds, evidence semantics, and
    product-specific KPI meaning remain outside this engine.
    """

    name = "native"

    @staticmethod
    def weighted_sum(
        measurements: Mapping[str, Mapping[str, Any]],
        weights: Mapping[str, float],
    ) -> CalculationResult:
        contributions: list[tuple[str, float]] = []
        details: list[ContributionDetail] = []
        lineage: list[str] = []
        has_unknown = False

        for kpi_id, weight in weights.items():
            if not isinstance(kpi_id, str) or not kpi_id:
                raise ValueError("KPI identifiers must be non-empty strings")
            lineage.append(kpi_id)
            numeric_weight = _numeric(weight, label=f"weight[{kpi_id}]")
            item = measurements.get(kpi_id)
            available = (
                isinstance(item, Mapping)
                and item.get("state") != "unknown"
                and item.get("value") is not None
            )
            if not available:
                has_unknown = True
                continue

            value = _numeric(item["value"], label=kpi_id)
            contribution = value * numeric_weight
            contributions.append((kpi_id, contribution))
            details.append(
                ContributionDetail(kpi_id, value, numeric_weight, contribution)
            )

        if has_unknown:
            return CalculationResult(
                value=None,
                state="unknown",
                lineage=tuple(lineage),
                contributions=tuple(contributions),
                contribution_details=tuple(details),
            )

        return CalculationResult(
            value=sum(value for _, value in contributions),
            state="observed",
            lineage=tuple(lineage),
            contributions=tuple(contributions),
            contribution_details=tuple(details),
            coverage=1.0,
        )

    @staticmethod
    def formula(
        left: CalculationResult,
        right: CalculationResult,
        *,
        operation: str,
    ) -> CalculationResult:
        lineage = tuple(sorted(set(left.lineage) | set(right.lineage)))
        contributions = left.contributions + right.contributions
        details = left.contribution_details + right.contribution_details

        if left.state == "unknown" or right.state == "unknown":
            return CalculationResult(
                None, "unknown", lineage, contributions, details, coverage=0.0
            )

        if left.value is None or right.value is None:
            raise ValueError("formula requires numeric values")

        coverage = min(
            _coverage(left, label="formula input coverage"),
            _coverage(right, label="formula input coverage"),
        )

        if operation == "sum":
            value = left.value + right.value
            derived = details
        elif operation == "difference":
            value = left.value - right.value
            derived = left.contribution_details + _scale_details(
                right.contribution_details, -1.0
            )
        elif operation == "ratio":
            if right.value == 0:
                return CalculationResult(
                    None, "unknown", lineage, (), (), coverage=0.0
                )
            value = left.value / right.value
            derived = ()
        else:
            raise ValueError(f"unsupported formula operation: {operation}")

        state = "observed" if coverage == 1.0 else "partial"
        return CalculationResult(
            value=_numeric(value, label=f"formula[{operation}]"),
            state=state,
            lineage=lineage,
            contributions=_details_to_contributions(derived),
            contribution_details=derived,
            coverage=coverage,
        )

    @staticmethod
    def aggregation(
        results: list[CalculationResult],
        *,
        operation: str,
        weights: list[float] | None = None,
    ) -> CalculationResult:
        if not results:
            raise ValueError("aggregation requires at least one result")

        lineage = tuple(sorted({item for result in results for item in result.lineage}))

        if operation == "weighted_sum":
            if weights is None:
                raise ValueError("weighted_sum aggregation requires weights")
            if len(weights) != len(results):
                raise ValueError("weighted_sum weights must match result count")

            numeric_weights = [
                _numeric(weight, label=f"weight[{index}]")
                for index, weight in enumerate(weights)
            ]
            if any(weight < 0.0 for weight in numeric_weights):
                raise ValueError("weighted_sum aggregation weights must be non-negative")

            total_weight = sum(numeric_weights)
            if total_weight <= 0.0:
                raise ValueError("weighted_sum aggregation requires positive total weight")

            known_weight = 0.0
            unknown_weight = 0.0
            weighted_values: list[float] = []

            for index, result in enumerate(results):
                weight = numeric_weights[index]
                if result.value is None or result.state == "unknown":
                    unknown_weight += weight
                    continue

                value = _numeric(result.value, label="aggregation input")
                if result.state == "partial":
                    coverage = _coverage(result, label="partial aggregation coverage")
                    known_weight += weight * coverage
                    unknown_weight += weight * (1.0 - coverage)
                else:
                    known_weight += weight
                weighted_values.append(value * weight)

            if known_weight == 0.0:
                return CalculationResult(
                    None,
                    "unknown",
                    lineage,
                    tuple(
                        contribution
                        for result in results
                        for contribution in result.contributions
                    ),
                    tuple(
                        detail
                        for result in results
                        for detail in result.contribution_details
                    ),
                    coverage=0.0,
                    known_weight=0.0,
                    unknown_weight=unknown_weight,
                )

            derived = tuple(
                detail
                for index, result in enumerate(results)
                for detail in _scale_details(
                    result.contribution_details, numeric_weights[index]
                )
                if result.value is not None and result.state != "unknown"
            )
            coverage = known_weight / total_weight
            return CalculationResult(
                value=_numeric(
                    sum(weighted_values), label=f"aggregation[{operation}]"
                ),
                state="observed" if unknown_weight == 0.0 else "partial",
                lineage=lineage,
                contributions=_details_to_contributions(derived),
                contribution_details=derived,
                coverage=coverage,
                known_weight=known_weight,
                unknown_weight=unknown_weight,
            )

        if any(result.state == "unknown" or result.value is None for result in results):
            return _unknown_result(results)

        coverage = min(
            _coverage(result, label="aggregation input coverage")
            for result in results
        )
        values = [
            _numeric(result.value, label="aggregation input")
            for result in results
        ]

        if operation == "sum":
            value = sum(values)
            derived = tuple(
                detail
                for result in results
                for detail in result.contribution_details
            )
        elif operation == "mean":
            value = sum(values) / len(values)
            derived = _scale_details(
                (
                    detail
                    for result in results
                    for detail in result.contribution_details
                ),
                1.0 / len(values),
            )
        elif operation == "min":
            value = min(values)
            derived = ()
        elif operation == "max":
            value = max(values)
            derived = ()
        else:
            raise ValueError(f"unsupported aggregation operation: {operation}")

        return CalculationResult(
            value=_numeric(value, label=f"aggregation[{operation}]"),
            state="observed" if coverage == 1.0 else "partial",
            lineage=lineage,
            contributions=_details_to_contributions(derived),
            contribution_details=derived,
            coverage=coverage,
        )

    @staticmethod
    def conditional(
        condition: bool | None,
        when_true: CalculationResult,
        when_false: CalculationResult,
    ) -> CalculationResult:
        lineage = tuple(sorted(set(when_true.lineage) | set(when_false.lineage)))
        if condition is None:
            return CalculationResult(None, "unknown", lineage, coverage=0.0)

        chosen = when_true if condition else when_false
        if chosen.state == "unknown" or chosen.value is None:
            return CalculationResult(
                None,
                "unknown",
                lineage,
                chosen.contributions,
                chosen.contribution_details,
                coverage=0.0,
            )

        coverage = _coverage(chosen, label="conditional coverage")
        return CalculationResult(
            value=_numeric(chosen.value, label="conditional"),
            state="observed" if coverage == 1.0 else "partial",
            lineage=lineage,
            contributions=chosen.contributions,
            contribution_details=chosen.contribution_details,
            coverage=coverage,
            known_weight=chosen.known_weight,
            unknown_weight=chosen.unknown_weight,
        )

    @staticmethod
    def normalization(
        result: CalculationResult,
        *,
        source_min: float,
        source_max: float,
        clamp: bool = False,
        precision: int = 2,
    ) -> CalculationResult:
        if not isinstance(precision, int) or isinstance(precision, bool) or precision < 0:
            raise ValueError("precision must be a non-negative integer")

        if result.state == "unknown" or result.value is None:
            return CalculationResult(
                None,
                "unknown",
                result.lineage,
                result.contributions,
                result.contribution_details,
                coverage=0.0,
            )

        coverage = _coverage(result, label="normalization input coverage")
        value = _numeric(result.value, label="normalization input")
        lower = _numeric(source_min, label="source_min")
        upper = _numeric(source_max, label="source_max")

        if lower >= upper:
            raise ValueError("source_min must be less than source_max")

        if value < lower or value > upper:
            if not clamp:
                raise ValueError("normalization input is outside source range")
            value = min(max(value, lower), upper)

        normalized = round((value - lower) / (upper - lower), precision)
        return CalculationResult(
            value=_numeric(normalized, label="normalized score"),
            state="observed" if coverage == 1.0 else "partial",
            lineage=result.lineage,
            contributions=(),
            contribution_details=(),
            coverage=coverage,
        )

    @staticmethod
    def dependency(
        left: CalculationResult,
        right: CalculationResult,
        *,
        relation: str,
    ) -> CalculationResult:
        lineage = tuple(sorted(set(left.lineage) | set(right.lineage)))
        contributions = left.contributions + right.contributions
        details = left.contribution_details + right.contribution_details

        if left.state == "unknown" or right.state == "unknown":
            return CalculationResult(
                None, "unknown", lineage, contributions, details, coverage=0.0
            )

        if left.value is None or right.value is None:
            raise ValueError("dependency requires numeric values")

        coverage = min(
            _coverage(left, label="dependency input coverage"),
            _coverage(right, label="dependency input coverage"),
        )

        if relation == "sum":
            value = left.value + right.value
            derived = details
        elif relation == "max":
            value = max(left.value, right.value)
            derived = ()
        else:
            raise ValueError(f"unsupported dependency relation: {relation}")

        return CalculationResult(
            value=_numeric(value, label=f"dependency[{relation}]"),
            state="observed" if coverage == 1.0 else "partial",
            lineage=lineage,
            contributions=_details_to_contributions(derived),
            contribution_details=derived,
            coverage=coverage,
        )
