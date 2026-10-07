from __future__ import annotations

from datetime import datetime
import json
import math
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "fixtures"


def _load() -> dict[str, Any]:
    return json.loads(
        (FIXTURES / "measurement_contract.json").read_text(encoding="utf-8")
    )


def _assert_timezone_aware_iso8601(value: Any) -> None:
    assert isinstance(value, str) and value
    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() is not None


def _assert_measurement_contract(data: dict[str, Any]) -> None:
    assert data["schema_version"] == "measurement-v1"
    measurements = data["measurements"]
    assert isinstance(measurements, list) and measurements

    ids: set[str] = set()
    for measurement in measurements:
        assert isinstance(measurement, dict)
        measurement_id = measurement.get("measurement_id")
        assert isinstance(measurement_id, str) and measurement_id
        assert measurement_id not in ids
        ids.add(measurement_id)

        assert isinstance(measurement.get("kpi_id"), str) and measurement["kpi_id"]
        assert measurement.get("measurement_type") in {
            "quantitative",
            "categorical",
            "distribution",
        }
        assert isinstance(measurement.get("unit"), str) and measurement["unit"]
        assert measurement.get("state") in {"observed", "unknown"}
        assert isinstance(measurement.get("source"), str) and measurement["source"]
        _assert_timezone_aware_iso8601(measurement.get("observed_at"))

        value = measurement.get("value")
        measurement_type = measurement["measurement_type"]

        if measurement["state"] == "unknown":
            assert value is None
        elif measurement_type == "quantitative":
            assert isinstance(value, (int, float)) and not isinstance(value, bool)
            assert math.isfinite(float(value))
        elif measurement_type == "categorical":
            assert isinstance(value, str) and value
        else:
            assert isinstance(value, dict) and value
            assert all(
                isinstance(key, str)
                and key
                and isinstance(item, (int, float))
                and not isinstance(item, bool)
                and math.isfinite(float(item))
                and item >= 0
                for key, item in value.items()
            )

        evidence_ids = measurement.get("evidence_ids", [])
        assert isinstance(evidence_ids, list)
        assert all(isinstance(item, str) and item for item in evidence_ids)

        provenance = measurement.get("provenance")
        assert isinstance(provenance, dict)
        assert isinstance(provenance.get("method"), str) and provenance["method"]
        assert (
            isinstance(provenance.get("method_version"), str)
            and provenance["method_version"]
        )
        assert provenance.get("derivation") in {"direct", "derived"}
        assert isinstance(provenance.get("input_refs"), list)
        assert all(isinstance(item, str) and item for item in provenance["input_refs"])


def test_measurement_contract_supports_quantitative_categorical_and_distribution() -> None:
    data = _load()
    _assert_measurement_contract(data)

    types = {item["measurement_type"] for item in data["measurements"]}
    assert types == {"quantitative", "categorical", "distribution"}


def test_measurement_contract_keeps_unknown_distinct_from_zero() -> None:
    data = _load()
    unknown = next(
        item
        for item in data["measurements"]
        if item["kpi_id"] == "higher_impact_activity_signals"
    )
    assert unknown["state"] == "unknown"
    assert unknown["value"] is None


def test_measurement_contract_requires_timezone_for_observed_at() -> None:
    data = _load()
    measurement = data["measurements"][0]

    valid = measurement["observed_at"]
    _assert_timezone_aware_iso8601(valid)

    measurement["observed_at"] = "2026-10-07"
    try:
        _assert_timezone_aware_iso8601(measurement["observed_at"])
    except (AssertionError, ValueError):
        pass
    else:
        raise AssertionError("date-only observed_at must be rejected")

    measurement["observed_at"] = "2026-10-07T00:00:00"
    try:
        _assert_timezone_aware_iso8601(measurement["observed_at"])
    except AssertionError:
        pass
    else:
        raise AssertionError("timezone-naive observed_at must be rejected")


def test_distribution_measurement_represents_category_counts_not_probabilities() -> None:
    data = _load()
    distribution = next(
        item
        for item in data["measurements"]
        if item["measurement_type"] == "distribution"
    )

    assert distribution["unit"] == "count"
    value = distribution["value"]
    assert isinstance(value, dict)
    assert value == {
        "reachable": 7,
        "unreachable": 1,
        "unknown": 2,
    }
    assert sum(value.values()) == 10
    assert not math.isclose(sum(value.values()), 1.0)
