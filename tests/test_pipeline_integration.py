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


def test_pipeline_evidence_enrichment_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setenv("FIRECRAWL_API_KEY", "test-key")

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

    def unexpected(*args, **kwargs):
        raise AssertionError("Evidence stage must not execute when disabled")

    monkeypatch.setattr(pipeline, "service_findings_to_evidence", unexpected)
    monkeypatch.setattr(pipeline, "enrich_evidence", unexpected)
    monkeypatch.setattr(pipeline, "verify_evidence_records", unexpected)

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        enable_evidence_enrichment=False,
        with_ai=False,
    )

    assert len(state["services"]) == 1
    assert state["evidence"] == []
    assert not any(
        event.get("stage") in {"evidence_start", "evidence"}
        for event in state["events"]
    )


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

    # The normalized EvidenceRecord remains in pipeline state for provenance,
    # but it is a scanner mirror and must not be sent twice to the AI.
    assert len(state["evidence"]) == 1
    assert captured["evidence_records"] == []


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

    # Pipeline retains both the scanner mirror and the enrichment record,
    # while AI receives only the new enrichment evidence.
    assert len(state["evidence"]) == 2
    assert len(captured["evidence_records"]) == 1
    contextual = captured["evidence_records"][0]
    assert contextual["relation"] == "security_publication"
    assert contextual["directness"] == "contextual"
    assert contextual["assertion_scope"] == "security_publication_context_only"
    assert contextual["provenance"]["assertion_scope"] == "security_publication_context_only"
    assert contextual["verification_scope"] == "url_accessibility"
    assert contextual["verification_state"] == "unknown"


def test_pipeline_ai_failure_is_observable(monkeypatch) -> None:
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

    def fail_ai(**kwargs):
        raise RuntimeError("synthetic AI failure")

    monkeypatch.setattr(pipeline, "analyze_smart_cache", fail_ai)

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=True,
    )

    assert state["ai"] is None
    assert any(
        event.get("stage") == "ai"
        and event.get("level") == "error"
        and "RuntimeError" in (event.get("text") or "")
        for event in state["events"]
    )
