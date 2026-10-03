from __future__ import annotations

from services import pipeline


def test_pipeline_import() -> None:
    assert pipeline is not None


def test_pipeline_exposes_normalized_evidence(monkeypatch) -> None:
    monkeypatch.setattr(
        pipeline,
        "scan_osint_footprint",
        lambda email, lang="id": [
            {
                "name": "Example",
                "domain": "sub.example.com",
                "source": "OSINT / Holehe",
                "subject": "Active account detected",
            }
        ],
    )

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=False,
    )

    assert len(state["services"]) == 1
    assert len(state["evidence"]) == 1
    evidence = state["evidence"][0]
    assert evidence["domain"] == "example.com"
    assert evidence["relation"] == "target_resource"
    assert evidence["directness"] == "direct"
    assert evidence["metadata"]["finding_type"] == "service_discovery"


def test_pipeline_forwards_evidence_to_ai(monkeypatch) -> None:
    captured: dict = {}

    monkeypatch.setattr(
        pipeline,
        "scan_osint_footprint",
        lambda email, lang="id": [
            {
                "name": "Example",
                "domain": "sub.example.com",
                "source": "OSINT / Holehe",
                "subject": "Active account detected",
            }
        ],
    )
    monkeypatch.setattr(
        pipeline,
        "analyze_smart_cache",
        lambda **kwargs: (
            captured.update(kwargs) or {
                "provider_used": "test",
                "analysis": [],
                "exposures": [],
            }
        ),
    )

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=True,
    )

    assert len(state["evidence"]) == 1
    assert captured["evidence_records"][0]["domain"] == "example.com"
    assert captured["evidence_records"][0]["relation"] == "target_resource"
