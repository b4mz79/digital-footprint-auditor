from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .integration import evaluate_pipeline_scorecard


_ROOT = Path(__file__).resolve().parent
_CONFIG = _ROOT / "config"


def _load_json(name: str) -> dict[str, Any]:
    path = _CONFIG / name
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"scorecard config must be an object: {name}")
    return payload


def run(context: Mapping[str, Any]) -> dict[str, Any]:
    state = context.get("state")
    if not isinstance(state, Mapping):
        raise TypeError("scorecard add-on requires context['state']")

    # Package configuration is the add-on default. The host may supply an
    # explicit definition/policy when invoking the legacy scorecard bridge or
    # an equivalent configured integration path.
    definition = context.get("scorecard_definition")
    if definition is None:
        definition = _load_json("definition.json")
    if not isinstance(definition, Mapping):
        raise TypeError("scorecard_definition must be a mapping")

    risk_policy = context.get("scorecard_risk_policy")
    if risk_policy is None:
        risk_policy = _load_json("risk_policy.json")
    if not isinstance(risk_policy, Mapping):
        raise TypeError("scorecard_risk_policy must be a mapping")

    scorecard_input, scorecard_result = evaluate_pipeline_scorecard(
        state,
        scorecard_definition=definition,
        risk_policy=risk_policy,
    )
    return {
        "scorecard_input": scorecard_input.to_dict(),
        "scorecard": scorecard_result.to_dict(),
    }
