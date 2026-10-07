from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from services import pipeline
from services.addon_manager import AddonManager
from services.evidence.models import EvidenceDirectness, EvidenceRecord, EvidenceRelation

DUMP_PATH = Path(__file__).resolve().parent / "fixtures" / "contextual_filter_dump.md"


def _definition() -> dict:
    return {
        "schema_version": "scorecard-definition-v1",
        "scorecard_id": "integration-scorecard",
        "version": "v1",
        "score": {
            "canonical_range": {"min": 0.0, "max": 10.0},
            "precision": 2,
            "rounding": "half_even",
        },
        "aggregation": {
            "operation": "weighted_sum",
            "weights": {
                "service_discovery_count": 0.5,
                "relevant_security_evidence": 0.5,
            },
        },
    }


def _policy() -> dict:
    return {
        "schema_version": "risk-policy-v1",
        "risk_policy_id": "integration-policy",
        "version": "v1",
        "output": {"risk_bands": ["high", "medium", "low", "unknown"]},
        "mapping": {
            "rules": [
                {
                    "rule_id": "high",
                    "priority": 10,
                    "condition": {
                        "type": "score_threshold",
                        "parameters": {"operator": ">=", "value": 0.8},
                    },
                    "then": "high",
                },
                {
                    "rule_id": "low",
                    "priority": 20,
                    "condition": {
                        "type": "score_threshold",
                        "parameters": {"operator": ">=", "value": 0.0},
                    },
                    "then": "low",
                },
            ]
        },
    }


def _load_contextual_dump_records() -> list[dict]:
    if not DUMP_PATH.exists():
        pytest.fail(f"required real-case fixture is missing: {DUMP_PATH}")

    raw = DUMP_PATH.read_text(encoding="utf-8")
    marker = "AFTER\n```json\n"
    start = raw.find(marker)
    if start < 0:
        pytest.fail("contextual_filter_dump.md has no AFTER section")
    start += len(marker)
    end = raw.find("\n```", start)
    if end < 0:
        pytest.fail("contextual_filter_dump.md AFTER JSON is not closed")

    after = json.loads(raw[start:end])
    records = (
        after.get("accepted")
        or after.get("accepted_records")
        or after.get("records")
        or []
    )
    return [item for item in records if isinstance(item, dict)]




def _install_scorecard_addon(monkeypatch, tmp_path: Path) -> None:
    """Install the real repository Scorecard package into an isolated manager.

    The test must not depend on the developer's persistent add-on state,
    including a previous manual uninstall from the UI.
    """
    source_root = Path(__file__).resolve().parents[3] / "addons" / "scorecard"
    if not source_root.is_dir():
        pytest.fail(f"Scorecard add-on package is missing: {source_root}")

    manifest_path = source_root / "manifest.json"
    if not manifest_path.is_file():
        pytest.fail(f"Scorecard add-on manifest is missing: {manifest_path}")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in source_root.rglob("*"):
            if path.is_file():
                relative = path.relative_to(source_root).as_posix()
                archive.write(path, f"{source_root.name}/{relative}")

    manager = AddonManager(tmp_path / "addons")
    manager.install_zip(buffer.getvalue())
    manager.activate("scorecard")
    monkeypatch.setattr(pipeline, "get_addon_manager", lambda: manager)


def _patch_pipeline(monkeypatch) -> None:
    monkeypatch.setattr(pipeline, "discovery_cache_enabled", lambda: False)
    monkeypatch.setattr(
        pipeline,
        "scan_osint_footprint",
        lambda email, lang="id": [
            {
                "name": "Example",
                "domain": "example.com",
                "source": "OSINT / Holehe",
                "subject": "Active account detected",
            }
        ],
    )

    async def fake_enrich(records):
        contextual = []
        for index, item in enumerate(_load_contextual_dump_records()):
            contextual.append(
                EvidenceRecord(
                    evidence_id=str(
                        item.get("evidence_id") or f"dump-contextual-{index + 1}"
                    ),
                    source=str(
                        item.get("source")
                        or item.get("publisher")
                        or "contextual_filter_dump"
                    ),
                    source_type="security_publication",
                    relation=EvidenceRelation.SECURITY_PUBLICATION,
                    directness=EvidenceDirectness.CONTEXTUAL,
                    confidence=0.8,
                    observed_at="2026-10-07T01:00:00+00:00",
                    published_at=item.get("published_at"),
                    domain=str(item.get("domain") or "example.com"),
                    url=str(item.get("url") or ""),
                    title=str(item.get("title") or ""),
                    summary=str(item.get("summary") or item.get("text") or ""),
                    provenance={"source": "contextual_filter_dump"},
                    metadata={"finding_type": "security_context"},
                    assertion_scope="contextual",
                    verification_scope="url_accessibility",
                    verification_state="unknown",
                    verification_observed_at=None,
                )
            )
        return list(records) + contextual

    async def fake_verify(records):
        return list(records)

    monkeypatch.setattr(pipeline, "enrich_evidence", fake_enrich)
    monkeypatch.setattr(pipeline, "verify_evidence_records", fake_verify)


def _patch_ai(monkeypatch, captured: dict) -> None:
    async def fake_analyze(**kwargs):
        captured.update(kwargs)
        return {"provider_used": "test", "analysis": [], "exposures": []}

    monkeypatch.setattr(pipeline, "analyze_smart_cache", fake_analyze)


def test_scorecard_off_preserves_existing_ai_path(monkeypatch, tmp_path: Path) -> None:
    _patch_pipeline(monkeypatch)
    monkeypatch.setattr(
        pipeline,
        "get_addon_manager",
        lambda: AddonManager(tmp_path / "addons"),
    )
    captured: dict = {}
    _patch_ai(monkeypatch, captured)

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=True,
    )

    assert "scorecard" not in state["addons"]
    assert "scorecard" not in state
    assert captured.get("addon_results") == {}
    assert captured["evidence_records"]
    assert state["ai"]["provider_used"] == "test"


def test_scorecard_on_augments_existing_ai_payload(monkeypatch, tmp_path: Path) -> None:
    _install_scorecard_addon(monkeypatch, tmp_path)
    _patch_pipeline(monkeypatch)
    captured: dict = {}
    _patch_ai(monkeypatch, captured)

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=True,
        addon_contexts={
            "scorecard": {
                "scorecard_definition": _definition(),
                "scorecard_risk_policy": _policy(),
            }
        },
    )

    dump_count = len(_load_contextual_dump_records())

    assert state["addons"]["scorecard"]["scorecard_input"]["schema_version"] == "scorecard-input-v1"
    assert state["scorecard"]["schema_version"] == "scorecard-result-v1"
    expected_raw = (1 * 0.5) + (dump_count * 0.5)
    assert state["scorecard"]["score"] == round(expected_raw / 10.0, 2)
    assert captured["evidence_records"]
    addon_payload = captured["addon_results"]["scorecard"]
    assert addon_payload["scorecard"]["result_id"] == state["scorecard"]["result_id"]
    assert addon_payload["scorecard"]["score"] == state["scorecard"]["score"]
    assert addon_payload["scorecard"]["risk_band"] == state["scorecard"]["risk_band"]


def test_scorecard_failure_does_not_break_existing_ai(monkeypatch, tmp_path: Path) -> None:
    _install_scorecard_addon(monkeypatch, tmp_path)
    _patch_pipeline(monkeypatch)
    captured: dict = {}
    _patch_ai(monkeypatch, captured)

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=True,
        addon_contexts={
            "scorecard": {
                "scorecard_definition": {"broken": True},
                "scorecard_risk_policy": _policy(),
            }
        },
    )

    assert "scorecard" not in state["addons"]
    assert "scorecard" not in state
    assert captured.get("addon_results") == {}
    assert state["ai"]["provider_used"] == "test"
