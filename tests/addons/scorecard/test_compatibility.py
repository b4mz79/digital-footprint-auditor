from __future__ import annotations

import json
from pathlib import Path

from tests.scorecard.compatibility import (
    compare_eval_results,
    compare_policy_decisions,
    validate_policy_decision,
)
from tests.scorecard.engines.native import NativeReferenceAdapter
from tests.scorecard.policy_engine_contract import (
    CONDITION_MATCH,
    CONDITION_NO_MATCH,
    CONDITION_UNKNOWN,
    PolicyDecision,
)
from tests.scorecard.reference_policy_engine import evaluate_policy


FIXTURES = Path(__file__).parent / "fixtures"


def _observed(value: float, unit: str = "count") -> dict:
    return {"unit": unit, "value": value, "state": "observed"}


def _unknown(unit: str = "count") -> dict:
    return {"unit": unit, "value": None, "state": "unknown"}


def _policy() -> dict:
    return json.loads(
        (FIXTURES / "risk_policy_active.json").read_text(encoding="utf-8")
    )


def _condition_evaluator(condition: dict, _context: dict) -> str:
    return condition["parameters"]["result"]


class EquivalentCandidate(NativeReferenceAdapter):
    """Synthetic candidate used only to prove the differential harness."""

    name = "equivalent-candidate"


class DivergentCandidate(NativeReferenceAdapter):
    """Synthetic incompatible candidate for negative compatibility tests."""

    name = "divergent-candidate"

    def weighted_sum(self, measurements, weights):
        result = super().weighted_sum(measurements, weights)
        if result.state == "unknown":
            return type(result)(
                value=0.0,
                state="observed",
                lineage=result.lineage,
                contributions=result.contributions,
                contribution_details=result.contribution_details,
                coverage=1.0,
                known_weight=result.known_weight,
                unknown_weight=result.unknown_weight,
            )
        return result


def test_differential_harness_accepts_semantically_equivalent_candidate() -> None:
    reference = NativeReferenceAdapter()
    candidate = EquivalentCandidate()

    measurements = {
        "a": _observed(10),
        "b": _observed(4),
    }
    weights = {"a": 0.6, "b": 0.4}

    report = compare_eval_results(
        reference.weighted_sum(measurements, weights),
        candidate.weighted_sum(measurements, weights),
    )

    assert report.compatible is True
    assert report.diffs == ()


def test_differential_harness_rejects_semantic_divergence() -> None:
    reference = NativeReferenceAdapter()
    candidate = DivergentCandidate()

    measurements = {
        "a": _observed(10),
        "b": _unknown(),
    }
    weights = {"a": 0.6, "b": 0.4}

    report = compare_eval_results(
        reference.weighted_sum(measurements, weights),
        candidate.weighted_sum(measurements, weights),
    )

    assert report.compatible is False
    assert {diff.field for diff in report.diffs} >= {"value", "state"}


def test_differential_harness_compares_policy_resolution_semantics() -> None:
    policy = _policy()
    reference = evaluate_policy(
        policy,
        {},
        condition_evaluator=_condition_evaluator,
    )
    candidate = evaluate_policy(
        policy,
        {},
        condition_evaluator=_condition_evaluator,
    )

    validate_policy_decision(
        reference,
        risk_bands={"high", "medium", "low", "unknown"},
    )
    validate_policy_decision(
        candidate,
        risk_bands={"high", "medium", "low", "unknown"},
    )

    report = compare_policy_decisions(reference, candidate)

    assert report.compatible is True
    assert report.diffs == ()


def test_policy_differential_harness_rejects_risk_band_divergence() -> None:
    reference = PolicyDecision(
        status="matched",
        risk_band="medium",
        applied_rule_id="rule-medium",
        evaluated_rule_ids=("rule-low", "rule-medium"),
        condition_outcomes=(
            ("rule-low", CONDITION_NO_MATCH),
            ("rule-medium", CONDITION_MATCH),
        ),
    )
    candidate = PolicyDecision(
        status="matched",
        risk_band="high",
        applied_rule_id="rule-medium",
        evaluated_rule_ids=("rule-low", "rule-medium"),
        condition_outcomes=(
            ("rule-low", CONDITION_NO_MATCH),
            ("rule-medium", CONDITION_MATCH),
        ),
    )

    report = compare_policy_decisions(reference, candidate)

    assert report.compatible is False
    assert report.diffs == (
        type(report.diffs[0])("risk_band", "medium", "high"),
    )


def test_differential_harness_preserves_unknown_policy_outcome() -> None:
    decision = PolicyDecision(
        status="condition_unknown",
        risk_band=None,
        applied_rule_id=None,
        evaluated_rule_ids=("rule-low",),
        condition_outcomes=(("rule-low", CONDITION_UNKNOWN),),
    )

    validated = validate_policy_decision(
        decision,
        risk_bands={"high", "medium", "low", "unknown"},
    )

    assert validated.status == "condition_unknown"
    assert validated.risk_band is None
