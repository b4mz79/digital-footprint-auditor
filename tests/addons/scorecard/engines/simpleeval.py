from __future__ import annotations

import math
from typing import Any

from tests.addons.scorecard.reference_engine import ContributionDetail, EvalResult


def _numeric(value: Any, *, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{label} must be finite")
    return result


def _weight(value: Any, *, kpi_id: str) -> float:
    return _numeric(value, label=f"weight[{kpi_id}]")


class SimpleEvalReferenceAdapter:
    """Candidate adapter; Scorecard semantics remain domain-owned."""

    name = "simpleeval"

    def __init__(self) -> None:
        try:
            from simpleeval import simple_eval
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("simpleeval is required for this candidate evaluation") from exc
        self._simple_eval = simple_eval

    @staticmethod
    def _lineage(*results: EvalResult) -> tuple[str, ...]:
        return tuple(sorted({item for result in results for item in result.lineage}))

    @staticmethod
    def _coverage(result: EvalResult) -> float:
        if result.state == "observed":
            return 1.0
        if result.state == "partial" and result.coverage is not None:
            value = _numeric(result.coverage, label="input coverage")
            if not 0.0 <= value <= 1.0:
                raise ValueError("input coverage must be within [0, 1]")
            return value
        raise ValueError("partial input requires coverage")

    @staticmethod
    def _minmax_expression(names: list[str], *, operation: str) -> str:
        if not names:
            raise ValueError("min/max requires at least one value")
        if operation not in {"min", "max"}:
            raise ValueError(f"Unsupported min/max operation: {operation}")
        comparator = "<" if operation == "min" else ">"
        expression = names[0]
        for candidate in names[1:]:
            expression = f"({expression} if {expression} {comparator} {candidate} else {candidate})"
        return expression

    def _evaluate_numeric_expression(
        self,
        expression: str,
        names: dict[str, Any],
        *,
        label: str,
    ) -> float:
        return _numeric(self._simple_eval(expression, names=names), label=label)

    def weighted_sum(
        self,
        measurements: dict[str, dict[str, Any]],
        weights: dict[str, float],
    ) -> EvalResult:
        lineage = tuple(weights)
        details: list[ContributionDetail] = []
        terms: list[str] = []
        names: dict[str, float] = {}
        has_unknown = False

        for kpi_id, weight in weights.items():
            numeric_weight = _weight(weight, kpi_id=kpi_id)
            if numeric_weight < 0:
                raise ValueError("simpleeval adapter requires non-negative weights")
            item = measurements.get(kpi_id)
            if (
                not isinstance(item, dict)
                or item.get("state") == "unknown"
                or item.get("value") is None
            ):
                has_unknown = True
                continue

            value = _numeric(item["value"], label=kpi_id)
            if not kpi_id.isidentifier():
                raise ValueError(
                    "simpleeval candidate adapter requires KPI ids to be "
                    f"valid Python identifiers: {kpi_id!r}"
                )

            names[kpi_id] = value
            terms.append(f"({kpi_id} * {numeric_weight!r})")
            details.append(
                ContributionDetail(
                    kpi_id=kpi_id,
                    value=value,
                    weight=numeric_weight,
                    contribution=value * numeric_weight,
                )
            )

        if has_unknown:
            return EvalResult(
                value=None,
                state="unknown",
                lineage=lineage,
                contributions=tuple(
                    (item.kpi_id, item.contribution) for item in details
                ),
                contribution_details=tuple(details),
            )

        if not terms:
            raise ValueError("weighted_sum requires at least one observed measurement")

        value = self._evaluate_numeric_expression(
            " + ".join(terms),
            names,
            label="simpleeval weighted_sum",
        )
        return EvalResult(
            value=value,
            state="observed",
            lineage=lineage,
            contributions=tuple(
                (item.kpi_id, item.contribution) for item in details
            ),
            contribution_details=tuple(details),
        )

    def formula(
        self,
        left: EvalResult,
        right: EvalResult,
        *,
        operation: str,
    ) -> EvalResult:
        lineage = self._lineage(left, right)
        contributions = left.contributions + right.contributions
        details = left.contribution_details + right.contribution_details

        if left.state == "unknown" or right.state == "unknown":
            return EvalResult(
                None, "unknown", lineage, contributions, details, coverage=0.0
            )

        left_value = _numeric(left.value, label="formula left")
        right_value = _numeric(right.value, label="formula right")
        coverage = min(self._coverage(left), self._coverage(right))

        expressions = {
            "sum": "left + right",
            "difference": "left - right",
            "ratio": "left / right",
        }
        if operation not in expressions:
            raise ValueError(f"Unsupported synthetic formula: {operation}")
        if operation == "ratio" and right_value == 0:
            return EvalResult(None, "unknown", lineage, coverage=0.0)

        value = self._evaluate_numeric_expression(
            expressions[operation],
            {"left": left_value, "right": right_value},
            label=f"formula[{operation}]",
        )

        if operation == "sum":
            derived = details
        elif operation == "difference":
            derived = left.contribution_details + tuple(
                ContributionDetail(
                    d.kpi_id, d.value, -d.weight, -d.contribution
                )
                for d in right.contribution_details
            )
        else:
            derived = ()

        return EvalResult(
            value=value,
            state="observed" if coverage == 1.0 else "partial",
            lineage=lineage,
            contributions=tuple((d.kpi_id, d.contribution) for d in derived),
            contribution_details=derived,
            coverage=coverage,
        )

    def aggregation(
        self,
        results: list[EvalResult],
        *,
        operation: str,
        weights: list[float] | None = None,
    ) -> EvalResult:
        if not results:
            raise ValueError("aggregation requires at least one result")

        lineage = self._lineage(*results)

        if operation == "weighted_sum":
            if weights is None or len(weights) != len(results):
                raise ValueError("weighted_sum aggregation weights must match results")

            numeric_weights = [
                _numeric(weight, label=f"weight[{i}]")
                for i, weight in enumerate(weights)
            ]
            if any(weight < 0 for weight in numeric_weights):
                raise ValueError(
                    "weighted_sum aggregation requires non-negative weights"
                )
            total_weight = sum(numeric_weights)
            if total_weight <= 0:
                raise ValueError(
                    "weighted_sum aggregation requires positive total weight"
                )

            known_weight = 0.0
            unknown_weight = 0.0
            terms: list[str] = []
            names: dict[str, float] = {}

            for i, (result, weight) in enumerate(zip(results, numeric_weights)):
                if result.value is None or result.state == "unknown":
                    unknown_weight += weight
                    continue

                coverage = self._coverage(result)
                known_weight += weight * coverage
                unknown_weight += weight * (1.0 - coverage)
                variable = f"v{i}"
                names[variable] = _numeric(result.value, label="aggregation input")
                terms.append(f"({variable} * {weight!r})")

            if known_weight == 0.0:
                return EvalResult(
                    None,
                    "unknown",
                    lineage,
                    coverage=0.0,
                    known_weight=0.0,
                    unknown_weight=unknown_weight,
                )

            value = self._evaluate_numeric_expression(
                " + ".join(terms),
                names,
                label="aggregation[weighted_sum]",
            )
            derived = tuple(
                ContributionDetail(
                    d.kpi_id,
                    d.value,
                    d.weight * numeric_weights[i],
                    d.contribution * numeric_weights[i],
                )
                for i, result in enumerate(results)
                if result.value is not None and result.state != "unknown"
                for d in result.contribution_details
            )
            return EvalResult(
                value,
                "observed" if unknown_weight == 0.0 else "partial",
                lineage,
                tuple((d.kpi_id, d.contribution) for d in derived),
                derived,
                coverage=known_weight / total_weight,
                known_weight=known_weight,
                unknown_weight=unknown_weight,
            )

        if any(result.state == "unknown" or result.value is None for result in results):
            return EvalResult(
                None,
                "unknown",
                lineage,
                tuple(c for result in results for c in result.contributions),
                tuple(d for result in results for d in result.contribution_details),
            )

        coverage = min(self._coverage(result) for result in results)
        values = [
            _numeric(result.value, label="aggregation input")
            for result in results
        ]
        names = {f"v{i}": value for i, value in enumerate(values)}

        if operation == "sum":
            expression = " + ".join(names)
        elif operation == "mean":
            expression = f"({' + '.join(names)}) / {len(values)}"
        elif operation in {"min", "max"}:
            expression = self._minmax_expression(
                list(names),
                operation=operation,
            )
        else:
            raise ValueError(f"Unsupported synthetic aggregation: {operation}")

        value = self._evaluate_numeric_expression(
            expression,
            names,
            label=f"aggregation[{operation}]",
        )
        details = tuple(
            d for result in results for d in result.contribution_details
        )
        if operation == "mean":
            details = tuple(
                ContributionDetail(
                    d.kpi_id,
                    d.value,
                    d.weight / len(values),
                    d.contribution / len(values),
                )
                for d in details
            )
        elif operation in {"min", "max"}:
            details = ()

        return EvalResult(
            value,
            "observed" if coverage == 1.0 else "partial",
            lineage,
            tuple((d.kpi_id, d.contribution) for d in details),
            details,
            coverage=coverage,
        )

    def conditional(
        self,
        condition: bool | None,
        when_true: EvalResult,
        when_false: EvalResult,
    ) -> EvalResult:
        lineage = self._lineage(when_true, when_false)
        if condition is None:
            return EvalResult(None, "unknown", lineage, coverage=0.0)

        chosen = when_true if condition else when_false
        if chosen.state == "unknown" or chosen.value is None:
            return EvalResult(
                None,
                "unknown",
                lineage,
                chosen.contributions,
                chosen.contribution_details,
                coverage=0.0,
            )

        coverage = self._coverage(chosen)
        value = self._evaluate_numeric_expression(
            "selected if condition else 0",
            {
                "condition": bool(condition),
                "selected": _numeric(chosen.value, label="conditional branch"),
            },
            label="conditional",
        )
        return EvalResult(
            value,
            "observed" if coverage == 1.0 else "partial",
            lineage,
            chosen.contributions,
            chosen.contribution_details,
            coverage=coverage,
            known_weight=chosen.known_weight,
            unknown_weight=chosen.unknown_weight,
        )

    def normalization(
        self,
        result: EvalResult,
        *,
        source_min: float,
        source_max: float,
        clamp: bool = False,
    ) -> EvalResult:
        if result.state == "unknown" or result.value is None:
            return EvalResult(
                None,
                "unknown",
                result.lineage,
                result.contributions,
                result.contribution_details,
                coverage=0.0,
            )

        coverage = self._coverage(result)
        value = _numeric(result.value, label="normalization input")
        lower = _numeric(source_min, label="source_min")
        upper = _numeric(source_max, label="source_max")
        if lower >= upper:
            raise ValueError("source_min must be less than source_max")

        if value < lower or value > upper:
            if not clamp:
                raise ValueError("normalization input is outside source range")
            value = min(max(value, lower), upper)

        normalized = self._evaluate_numeric_expression(
            "(value - lower) / (upper - lower)",
            {"value": value, "lower": lower, "upper": upper},
            label="normalized score",
        )
        normalized = round(normalized, 2)
        return EvalResult(
            normalized,
            "observed" if coverage == 1.0 else "partial",
            result.lineage,
            (),
            (),
            coverage=coverage,
        )

    def dependency(
        self,
        left: EvalResult,
        right: EvalResult,
        *,
        relation: str,
    ) -> EvalResult:
        lineage = self._lineage(left, right)
        contributions = left.contributions + right.contributions
        details = left.contribution_details + right.contribution_details

        if left.state == "unknown" or right.state == "unknown":
            return EvalResult(
                None,
                "unknown",
                lineage,
                contributions,
                details,
                coverage=0.0,
            )

        left_value = _numeric(left.value, label="dependency left")
        right_value = _numeric(right.value, label="dependency right")
        coverage = min(self._coverage(left), self._coverage(right))

        if relation == "sum":
            expression = "left + right"
            derived = details
        elif relation == "max":
            expression = "left if left > right else right"
            derived = ()
        else:
            raise ValueError(f"Unsupported synthetic relation: {relation}")

        value = self._evaluate_numeric_expression(
            expression,
            {"left": left_value, "right": right_value},
            label=f"dependency[{relation}]",
        )
        return EvalResult(
            value,
            "observed" if coverage == 1.0 else "partial",
            lineage,
            tuple((d.kpi_id, d.contribution) for d in derived),
            derived,
            coverage=coverage,
        )
