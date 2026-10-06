from __future__ import annotations

import math
from typing import Any

from tests.scorecard.reference_engine import ContributionDetail, EvalResult


def _numeric(value: Any, *, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{label} must be finite")
    return result


def _weight(value: Any, *, kpi_id: str) -> float:
    return _numeric(value, label=f"weight[{kpi_id}]")


class ZenReferenceAdapter:
    """GoRules ZEN adapter for candidate-engine evaluation only.

    Domain semantics remain outside ZEN. The adapter translates a weighted
    calculation into a ZEN Expression node, then reconstructs the common
    EvalResult contract from the canonical inputs.
    """

    name = "gorules-zen"

    def __init__(self) -> None:
        try:
            import zen
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "GoRules ZEN Engine is not installed; install the pinned "
                "scorecard OSS evaluation dependency first."
            ) from exc
        self._zen = zen.ZenEngine()

    @staticmethod
    def _graph(expression: str) -> dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": "scorecard-input",
                    "type": "inputNode",
                    "position": {"x": 180, "y": 240},
                    "name": "Request",
                },
                {
                    "id": "scorecard-expression",
                    "type": "expressionNode",
                    "position": {"x": 470, "y": 240},
                    "name": "weighted_sum",
                    "content": {
                        "expressions": [
                            {
                                "id": "scorecard-expression-value",
                                "key": "score",
                                "value": expression,
                            }
                        ]
                    },
                },
                {
                    "id": "scorecard-output",
                    "type": "outputNode",
                    "position": {"x": 780, "y": 240},
                    "name": "Response",
                },
            ],
            "edges": [
                {
                    "id": "scorecard-edge-input",
                    "sourceId": "scorecard-input",
                    "type": "edge",
                    "targetId": "scorecard-expression",
                },
                {
                    "id": "scorecard-edge-output",
                    "sourceId": "scorecard-expression",
                    "type": "edge",
                    "targetId": "scorecard-output",
                },
            ],
        }

    def weighted_sum(
        self,
        measurements: dict[str, dict[str, Any]],
        weights: dict[str, float],
    ) -> EvalResult:
        lineage = tuple(weights)
        known: list[tuple[str, float, float]] = []
        unknown = False

        for kpi_id, weight in weights.items():
            numeric_weight = _weight(weight, kpi_id=kpi_id)
            if numeric_weight < 0:
                raise ValueError("ZEN adapter requires non-negative weights")
            item = measurements.get(kpi_id)
            if not item or item.get("state") == "unknown" or item.get("value") is None:
                unknown = True
                continue
            value = _numeric(item["value"], label=kpi_id)
            known.append((kpi_id, value, numeric_weight))

        # UNKNOWN semantics belong to our domain contract, not to ZEN arithmetic.
        # Do not coerce missing values into zero.
        if unknown:
            details = tuple(
                ContributionDetail(kpi_id, value, weight, value * weight)
                for kpi_id, value, weight in known
            )
            return EvalResult(
                value=None,
                state="unknown",
                lineage=lineage,
                contributions=tuple(
                    (detail.kpi_id, detail.contribution) for detail in details
                ),
                contribution_details=details,
            )

        expression = " + ".join(
            f"{kpi_id} * {weight!r}" for kpi_id, _value, weight in known
        )
        if not expression:
            raise ValueError("weighted_sum requires at least one known input")

        decision = self._zen.create_decision(self._graph(expression))
        response = decision.evaluate(
            {kpi_id: value for kpi_id, value, _weight in known}
        )

        raw_result = response.get("result") if isinstance(response, dict) else None
        if not isinstance(raw_result, dict) or "score" not in raw_result:
            raise ValueError(f"unexpected ZEN response: {response!r}")

        value = _numeric(raw_result["score"], label="ZEN weighted_sum")
        details = tuple(
            ContributionDetail(kpi_id, measured, weight, measured * weight)
            for kpi_id, measured, weight in known
        )
        return EvalResult(
            value=value,
            state="observed",
            lineage=lineage,
            contributions=tuple(
                (detail.kpi_id, detail.contribution) for detail in details
            ),
            contribution_details=details,
            coverage=1.0,
            known_weight=sum(weight for _kpi, _value, weight in known),
            unknown_weight=0.0,
        )
