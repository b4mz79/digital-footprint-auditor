from __future__ import annotations

from typing import Any

from tests.scorecard.reference_engine import ContributionDetail, EvalResult


class SimpleEvalReferenceAdapter:
    """Candidate-only adapter for simpleeval evaluation."""

    name = "simpleeval"

    def __init__(self) -> None:
        try:
            from simpleeval import simple_eval
        except ImportError as exc:
            raise RuntimeError(
                "simpleeval is required for this candidate evaluation"
            ) from exc
        self._simple_eval = simple_eval

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
            if not kpi_id.isidentifier():
                raise ValueError(
                    "simpleeval candidate adapter requires KPI ids to be "
                    f"valid Python identifiers: {kpi_id!r}"
                )

            names[kpi_id] = float(value)
            terms.append(f"({kpi_id} * {float(weight)!r})")
            details.append(
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
                    (item.kpi_id, item.contribution) for item in details
                ),
                contribution_details=tuple(details),
            )

        if not terms:
            raise ValueError("weighted_sum requires at least one observed measurement")

        value = self._simple_eval(" + ".join(terms), names=names)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise TypeError("simpleeval weighted_sum result must be numeric")

        return EvalResult(
            value=float(value),
            state="observed",
            lineage=lineage,
            contributions=tuple(
                (item.kpi_id, item.contribution) for item in details
            ),
            contribution_details=tuple(details),
        )
