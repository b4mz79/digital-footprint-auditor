
from __future__ import annotations

import json
import math
from pathlib import Path

import pytest


FIXTURES = Path(__file__).parent / "fixtures"


def _load() -> dict:
    return json.loads(
        (FIXTURES / "risk_policy_contract.json").read_text(
            encoding="utf-8"
        )
    )


def _assert_risk_policy_contract(data: dict) -> None:
    assert data["schema_version"] == "risk-policy-v1"

    for field in ("risk_policy_id", "version"):
        assert isinstance(data.get(field), str)
        assert data[field]

    scope = data.get("scope")
    assert isinstance(scope, dict)
    assert isinstance(scope.get("scorecard_id"), str)
    assert scope["scorecard_id"]
    assert isinstance(scope.get("scorecard_version"), str)
    assert scope["scorecard_version"]

    input_contract = data.get("input")
    assert isinstance(input_contract, dict)

    score_range = input_contract.get("score_range")
    assert isinstance(score_range, dict)

    minimum = score_range.get("min")
    maximum = score_range.get("max")

    assert isinstance(minimum, (int, float))
    assert not isinstance(minimum, bool)
    assert math.isfinite(float(minimum))

    assert isinstance(maximum, (int, float))
    assert not isinstance(maximum, bool)
    assert math.isfinite(float(maximum))

    assert float(minimum) == 0.0
    assert float(maximum) == 1.0

    states = input_contract.get("states")
    assert isinstance(states, list)
    assert set(states) == {"observed", "partial", "unknown"}

    output = data.get("output")
    assert isinstance(output, dict)

    risk_bands = output.get("risk_bands")
    assert isinstance(risk_bands, list)
    assert set(risk_bands) == {
        "high",
        "medium",
        "low",
        "unknown",
    }

    assert data.get("unknown_behavior") == "propagate"

    mapping = data.get("mapping")
    assert isinstance(mapping, dict)
    assert mapping.get("type") == "configured_rules"
    assert mapping.get("status") in {"definition_only", "active"}
    if mapping["status"] == "active":
        assert mapping.get("deterministic") is True
        rules = mapping.get("rules")
        assert isinstance(rules, list)
        assert rules
        rule_ids = [rule.get("rule_id") for rule in rules]
        priorities = [rule.get("priority") for rule in rules]
        assert all(isinstance(rule_id, str) and rule_id for rule_id in rule_ids)
        assert len(set(rule_ids)) == len(rule_ids)
        assert all(isinstance(priority, int) and not isinstance(priority, bool) for priority in priorities)
        assert len(set(priorities)) == len(priorities)
        assert all(rule.get("then") in risk_bands for rule in rules)

        # Conditions are part of the policy rule contract, but their actual
        # predicate language remains implementation-neutral at this stage.
        for rule in rules:
            condition = rule.get("condition")
            assert isinstance(condition, dict)
            assert isinstance(condition.get("type"), str) and condition["type"]
            assert isinstance(condition.get("parameters"), dict)

        # A rule set must declare what happens when no rule matches. The
        # concrete behavior is intentionally not fixed yet; importantly, a
        # silent default risk band is not allowed.
        assert isinstance(mapping.get("no_match_behavior"), str)
        assert mapping["no_match_behavior"]
        assert "default_risk_band" not in mapping

        # Overlapping conditions must resolve deterministically. Priority
        # identity alone is insufficient unless the policy also states how
        # priorities are interpreted and how matching terminates.
        assert mapping.get("resolution_strategy") == "first_match_by_priority"
        assert mapping.get("priority_order") == "ascending"
    else:
        assert "rules" not in mapping
        assert "deterministic" not in mapping


def test_risk_policy_contract_is_explicit_and_versioned() -> None:
    data = _load()
    _assert_risk_policy_contract(data)

    assert data["risk_policy_id"]
    assert data["version"]


def test_risk_policy_scope_binds_to_scorecard_version() -> None:
    data = _load()
    _assert_risk_policy_contract(data)

    assert data["scope"]["scorecard_id"] == "synthetic-scorecard"
    assert data["scope"]["scorecard_version"] == "synthetic-v1"


def test_risk_policy_accepts_canonical_score_range_only() -> None:
    data = _load()
    _assert_risk_policy_contract(data)

    assert data["input"]["score_range"] == {
        "min": 0.0,
        "max": 1.0,
    }


def test_risk_policy_preserves_unknown_as_unknown() -> None:
    data = _load()
    _assert_risk_policy_contract(data)

    assert data["unknown_behavior"] == "propagate"


def test_risk_policy_mapping_has_explicit_maturity_state() -> None:
    data = _load()
    _assert_risk_policy_contract(data)

    assert data["mapping"]["status"] == "definition_only"


def test_risk_policy_definition_only_does_not_claim_executable_rules() -> None:
    data = _load()
    _assert_risk_policy_contract(data)

    mapping = data["mapping"]

    assert mapping["status"] == "definition_only"
    assert "rules" not in mapping
    assert "deterministic" not in mapping


def test_risk_policy_contract_does_not_define_thresholds() -> None:
    data = _load()
    _assert_risk_policy_contract(data)

    mapping = data["mapping"]

    assert "thresholds" not in data
    assert "thresholds" not in mapping
    assert "high_min" not in data
    assert "medium_min" not in data
    assert "low_min" not in data


def test_risk_policy_rejects_invalid_score_range() -> None:
    data = _load()
    data["input"]["score_range"] = {
        "min": -1.0,
        "max": 1.0,
    }

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_risk_policy_rejects_unknown_as_low_semantics() -> None:
    data = _load()
    data["unknown_behavior"] = "low"

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_risk_policy_rejects_active_mapping_without_rules() -> None:
    data = _load()
    data["mapping"]["status"] = "active"

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_risk_policy_rejects_nondeterministic_active_mapping() -> None:
    data = _load()
    data["mapping"]["status"] = "active"
    data["mapping"]["rules"] = [
        {"rule_id": "synthetic-rule-1", "then": "unknown"}
    ]
    data["mapping"]["deterministic"] = False

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def _active_rule(
    rule_id: str,
    priority: int,
    then: str,
    *,
    condition_type: str = "predicate",
) -> dict:
    return {
        "rule_id": rule_id,
        "priority": priority,
        "condition": {
            "type": condition_type,
            "parameters": {},
        },
        "then": then,
    }


def _active_mapping_with_rules(rules: list[dict]) -> dict:
    data = _load()
    data["mapping"] = {
        "type": "configured_rules",
        "status": "active",
        "deterministic": True,
        "no_match_behavior": "policy_defined",
        "resolution_strategy": "first_match_by_priority",
        "priority_order": "ascending",
        "rules": rules,
    }
    return data


def test_active_rules_have_unique_identity_priority_condition_and_valid_band() -> None:
    data = _active_mapping_with_rules(
        [
            _active_rule("rule-1", 10, "low"),
            _active_rule("rule-2", 20, "medium"),
        ]
    )

    _assert_risk_policy_contract(data)


def test_active_rules_reject_duplicate_rule_ids() -> None:
    data = _active_mapping_with_rules(
        [
            {"rule_id": "rule-1", "priority": 10, "then": "low"},
            {"rule_id": "rule-1", "priority": 20, "then": "medium"},
        ]
    )

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_active_rules_reject_duplicate_priorities() -> None:
    data = _active_mapping_with_rules(
        [
            _active_rule("rule-1", 10, "low"),
            _active_rule("rule-2", 10, "medium"),
        ]
    )

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_active_rule_priorities_need_not_be_contiguous() -> None:
    data = _active_mapping_with_rules(
        [
            _active_rule("rule-1", 10, "low"),
            _active_rule("rule-2", 100, "medium"),
        ]
    )

    _assert_risk_policy_contract(data)


def test_active_rules_reject_invalid_risk_band() -> None:
    data = _active_mapping_with_rules(
        [
            _active_rule("rule-1", 10, "critical"),
        ]
    )

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)

def test_active_rules_reject_missing_condition() -> None:
    data = _active_mapping_with_rules(
        [_active_rule("rule-1", 10, "low")]
    )
    data["mapping"]["rules"][0].pop("condition")

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_active_rules_reject_empty_condition_type() -> None:
    data = _active_mapping_with_rules(
        [_active_rule("rule-1", 10, "low")]
    )
    data["mapping"]["rules"][0]["condition"]["type"] = ""

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_active_mapping_requires_explicit_no_match_behavior() -> None:
    data = _active_mapping_with_rules(
        [_active_rule("rule-1", 10, "low")]
    )
    data["mapping"].pop("no_match_behavior")

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_active_mapping_rejects_implicit_default_risk_band() -> None:
    data = _active_mapping_with_rules(
        [_active_rule("rule-1", 10, "low")]
    )
    data["mapping"]["default_risk_band"] = "low"

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_active_mapping_keeps_no_match_behavior_implementation_neutral() -> None:
    data = _active_mapping_with_rules(
        [_active_rule("rule-1", 10, "low")]
    )
    data["mapping"]["no_match_behavior"] = "future-explicit-policy"

    _assert_risk_policy_contract(data)


def test_active_mapping_requires_explicit_resolution_strategy() -> None:
    data = _active_mapping_with_rules(
        [_active_rule("rule-1", 10, "low")]
    )
    data["mapping"].pop("resolution_strategy")

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_active_mapping_requires_explicit_priority_order() -> None:
    data = _active_mapping_with_rules(
        [_active_rule("rule-1", 10, "low")]
    )
    data["mapping"].pop("priority_order")

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_active_mapping_rejects_ambiguous_resolution_strategy() -> None:
    data = _active_mapping_with_rules(
        [_active_rule("rule-1", 10, "low")]
    )
    data["mapping"]["resolution_strategy"] = "any_match"

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_active_mapping_rejects_ambiguous_priority_order() -> None:
    data = _active_mapping_with_rules(
        [_active_rule("rule-1", 10, "low")]
    )
    data["mapping"]["priority_order"] = "unspecified"

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)


def test_active_mapping_resolution_is_independent_of_numeric_thresholds() -> None:
    data = _active_mapping_with_rules(
        [
            _active_rule("rule-1", 10, "low"),
            _active_rule("rule-2", 100, "medium"),
        ]
    )

    _assert_risk_policy_contract(data)
    assert "thresholds" not in data["mapping"]
