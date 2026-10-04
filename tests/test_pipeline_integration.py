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


def test_pipeline_passes_enriched_evidence_to_ai(monkeypatch) -> None:
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

    async def fake_enrich(records):
        base = list(records)
        base.append(
            type(base[0])(
                evidence_id="context-1",
                source="Kaspersky Securelist",
                source_type="security_publication",
                relation=__import__("services.evidence.models", fromlist=["EvidenceRelation"]).EvidenceRelation.SECURITY_PUBLICATION,
                directness=__import__("services.evidence.models", fromlist=["EvidenceDirectness"]).EvidenceDirectness.CONTEXTUAL,
                confidence=0.65,
                observed_at=base[0].observed_at,
                published_at="2026-01-01",
                domain="example.com",
                url="https://securelist.com/example",
                title="Example security context",
                summary="Security publication context.",
            )
        )
        return base

    monkeypatch.setattr(pipeline, "enrich_evidence", fake_enrich)
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

    assert len(state["evidence"]) == 2
    assert any(
        item["relation"] == "security_publication"
        for item in captured["evidence_records"]
    )
