
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
    assert mapping.get("deterministic") is True


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


def test_risk_policy_mapping_is_configured_and_deterministic() -> None:
    data = _load()
    _assert_risk_policy_contract(data)

    mapping = data["mapping"]

    assert mapping["type"] == "configured_rules"
    assert mapping["deterministic"] is True


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


def test_risk_policy_rejects_nondeterministic_mapping() -> None:
    data = _load()
    data["mapping"]["deterministic"] = False

    with pytest.raises(AssertionError):
        _assert_risk_policy_contract(data)
