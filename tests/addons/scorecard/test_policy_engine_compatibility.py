from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.addons.scorecard.policy_engine_contract import (
    CONDITION_MATCH,
    CONDITION_NO_MATCH,
    CONDITION_UNKNOWN,
    DECISION_CONDITION_UNKNOWN,
    DECISION_MATCHED,
    DECISION_NO_MATCH,
    assert_policy_decision_semantics,
)
from tests.addons.scorecard.reference_policy_engine import evaluate_policy

FIXTURES = Path(__file__).parent / "fixtures"


def _load() -> dict:
    return json.loads(
        (FIXTURES / "risk_policy_active.json").read_text(encoding="utf-8")
    )


def _evaluator(condition: dict, _context: dict) -> str:
    return condition["parameters"]["result"]


def _active_policy() -> dict:
    return _load()


def test_reference_policy_engine_is_deterministic_and_engine_neutral() -> None:
    result = evaluate_policy(
        _active_policy(),
        {},
        condition_evaluator=_evaluator,
    )

    assert_policy_decision_semantics(
        result,
        risk_bands={"high", "medium", "low", "unknown"},
    )
    assert result.status == DECISION_MATCHED
    assert result.applied_rule_id == "rule-medium"
    assert result.risk_band == "medium"
    assert result.evaluated_rule_ids == ("rule-low", "rule-medium")


def test_policy_resolution_uses_priority_not_fixture_order() -> None:
    policy = _active_policy()
    policy["mapping"]["rules"] = list(reversed(policy["mapping"]["rules"]))

    result = evaluate_policy(
        policy,
        {},
        condition_evaluator=_evaluator,
    )

    assert result.status == DECISION_MATCHED
    assert result.applied_rule_id == "rule-medium"
    assert result.evaluated_rule_ids == ("rule-low", "rule-medium")


def test_policy_preserves_no_match_as_distinct_from_unknown() -> None:
    policy = _active_policy()
    for rule in policy["mapping"]["rules"]:
        rule["condition"]["parameters"]["result"] = CONDITION_NO_MATCH

    result = evaluate_policy(
        policy,
        {},
        condition_evaluator=_evaluator,
    )

    assert_policy_decision_semantics(
        result,
        risk_bands={"high", "medium", "low", "unknown"},
    )
    assert result.status == DECISION_NO_MATCH
    assert result.risk_band is None
    assert result.applied_rule_id is None


def test_policy_preserves_condition_unknown_as_distinct_from_no_match() -> None:
    policy = _active_policy()
    policy["mapping"]["rules"][0]["condition"]["parameters"]["result"] = (
        CONDITION_UNKNOWN
    )

    result = evaluate_policy(
        policy,
        {},
        condition_evaluator=_evaluator,
    )

    assert_policy_decision_semantics(
        result,
        risk_bands={"high", "medium", "low", "unknown"},
    )
    assert result.status == DECISION_CONDITION_UNKNOWN
    assert result.risk_band is None
    assert result.applied_rule_id is None


def test_policy_records_applied_rule_identity_for_replay() -> None:
    result = evaluate_policy(
        _active_policy(),
        {},
        condition_evaluator=_evaluator,
    )

    assert result.applied_rule_id == "rule-medium"
    assert result.condition_outcomes == (
        ("rule-low", CONDITION_NO_MATCH),
        ("rule-medium", CONDITION_MATCH),
    )


def test_policy_rejects_unsupported_condition_outcome() -> None:
    def invalid_evaluator(_condition: dict, _context: dict) -> str:
        return "false"

    with pytest.raises(ValueError):
        evaluate_policy(
            _active_policy(),
            {},
            condition_evaluator=invalid_evaluator,
        )
