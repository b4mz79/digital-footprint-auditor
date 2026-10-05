from __future__ import annotations

from services import pipeline
from services.evidence.models import EvidenceDirectness, EvidenceRelation


def test_pipeline_import() -> None:
    assert pipeline is not None


def test_pipeline_exposes_normalized_evidence(monkeypatch) -> None:
    monkeypatch.setenv("FIRECRAWL_API_KEY", "")
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
    assert evidence["assertion_scope"] == "service_association_only"
    assert evidence["provenance"]["assertion_scope"] == "service_association_only"
    assert evidence["verification_scope"] == "url_accessibility"
    assert evidence["verification_state"] == "unknown"
    assert evidence["verification_observed_at"] is None
    assert evidence["metadata"]["finding_type"] == "service_discovery"


def test_pipeline_forwards_evidence_to_ai(monkeypatch) -> None:
    monkeypatch.setenv("FIRECRAWL_API_KEY", "")
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
    assert captured["evidence_records"][0]["assertion_scope"] == "service_association_only"
    assert captured["evidence_records"][0]["provenance"]["assertion_scope"] == "service_association_only"
    assert captured["evidence_records"][0]["verification_scope"] == "url_accessibility"
    assert captured["evidence_records"][0]["verification_state"] == "unknown"


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
                relation=EvidenceRelation.SECURITY_PUBLICATION,
                directness=EvidenceDirectness.CONTEXTUAL,
                confidence=0.65,
                observed_at=base[0].observed_at,
                published_at="2026-01-01T00:00:00+00:00",
                domain="example.com",
                url="https://securelist.com/example",
                title="Example security context",
                summary="Security publication context.",
                provenance={
                    "provider": "firecrawl_search",
                    "publisher_domain": "securelist.com",
                    "query_scope": "domain_only",
                    "relevance_filter": "security_publication_context_v2",
                    "assertion_scope": "security_publication_context_only",
                },
                assertion_scope="security_publication_context_only",
            )
        )
        return base

    monkeypatch.setattr(pipeline, "enrich_evidence", fake_enrich)
    async def fake_verify(records):
        return list(records)

    monkeypatch.setattr(pipeline, "verify_evidence_records", fake_verify)
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
    contextual = next(
        item for item in captured["evidence_records"]
        if item["relation"] == "security_publication"
    )
    assert contextual["directness"] == "contextual"
    assert contextual["assertion_scope"] == "security_publication_context_only"
    assert contextual["provenance"]["assertion_scope"] == "security_publication_context_only"
    assert contextual["verification_scope"] == "url_accessibility"
    assert contextual["verification_state"] == "unknown"
