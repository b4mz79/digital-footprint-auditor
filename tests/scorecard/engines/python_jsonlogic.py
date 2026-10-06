from __future__ import annotations

from typing import Any

from tests.scorecard.reference_engine import ContributionDetail, EvalResult


class PythonJsonLogicReferenceAdapter:
    """Candidate-only adapter for python-jsonlogic evaluation.

    The Scorecard domain remains authoritative for UNKNOWN, lineage,
    contribution semantics, and version binding. python-jsonlogic is used only
    for the arithmetic expression evaluation in this candidate test path.
    """

    name = "python-jsonlogic"

    def __init__(self) -> None:
        try:
            from jsonlogic import JSONLogicExpression
            from jsonlogic.evaluation import evaluate
            from jsonlogic.operators import operator_registry
        except ImportError as exc:  # pragma: no cover - exercised by environment
            raise RuntimeError(
                "python-jsonlogic is required for this candidate evaluation"
            ) from exc

        self._JSONLogicExpression = JSONLogicExpression
        self._evaluate = evaluate
        self._operator_registry = operator_registry

    def weighted_sum(
        self,
        measurements: dict[str, dict[str, Any]],
        weights: dict[str, float],
    ) -> EvalResult:
        lineage = tuple(weights)
        contribution_details: list[ContributionDetail] = []
        has_unknown = False

        expression_terms: list[dict[str, Any]] = []

        for kpi_id, weight in weights.items():
            item = measurements.get(kpi_id)
            if (
                not isinstance(item, dict)
                or item.get("state") == "unknown"
                or item.get("value") is None
            ):
                has_unknown = True
                continue

            value = item["value"]
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise TypeError(f"{kpi_id} must be numeric")

            if not isinstance(weight, (int, float)) or isinstance(weight, bool):
                raise TypeError(f"weight[{kpi_id}] must be numeric")

            # python-jsonlogic 0.2.x resolves variable references using JSON
            # Pointer semantics when the reference starts with "/". Using the
            # bare JsonLogic reference here is parsed as a dot-like path and
            # makes a single-segment KPI id resolve incorrectly (e.g. "a").
            pointer_key = kpi_id.replace("~", "~0").replace("/", "~1")
            expression_terms.append(
                {"*": [{"var": f"/{pointer_key}"}, float(weight)]}
            )

            contribution_details.append(
                ContributionDetail(
                    kpi_id=kpi_id,
                    value=float(value),
                    weight=float(weight),
                    contribution=float(value) * float(weight),
                )
            )

        if has_unknown:
            return EvalResult(
                value=None,
                state="unknown",
                lineage=lineage,
                contributions=tuple(
                    (detail.kpi_id, detail.contribution)
                    for detail in contribution_details
                ),
                contribution_details=tuple(contribution_details),
            )

        if not expression_terms:
            raise ValueError("weighted_sum requires at least one observed measurement")

        expression: dict[str, Any]
        if len(expression_terms) == 1:
            expression = expression_terms[0]
        else:
            expression = {"+": expression_terms}

        parsed = self._JSONLogicExpression.from_json(expression)
        root_op = parsed.as_operator_tree(self._operator_registry)
        data = {
            kpi_id: measurements[kpi_id]["value"]
            for kpi_id in weights
        }
        value = self._evaluate(
            root_op,
            data=data,
            data_schema=None,
        )

        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise TypeError("python-jsonlogic weighted_sum result must be numeric")

        return EvalResult(
            value=float(value),
            state="observed",
            lineage=lineage,
            contributions=tuple(
                (detail.kpi_id, detail.contribution)
                for detail in contribution_details
            ),
            contribution_details=tuple(contribution_details),
        )
