from __future__ import annotations

import pytest

from services import pipeline
from services.enrichment.evidence.models import (
    EvidenceDirectness,
    EvidenceRecord,
    EvidenceRelation,
)


def test_tenant_id_fails_closed_when_configured_value_is_invalid(monkeypatch) -> None:
    monkeypatch.setenv("TENANT_ID", "tenant with spaces")
    with pytest.raises(ValueError, match="TENANT_ID tidak valid"):
        pipeline.get_tenant_id()


def test_run_scan_rejects_invalid_explicit_tenant_id(monkeypatch) -> None:
    monkeypatch.delenv("TENANT_ID", raising=False)
    with pytest.raises(ValueError, match="TENANT_ID tidak valid"):
        pipeline.run_scan(
            email="subject@example.org",
            enable_imap=False,
            enable_osint=False,
            enable_breach=False,
            tenant_id="tenant/invalid",
            with_ai=False,
        )


def test_unconfigured_tenant_id_keeps_local_default(monkeypatch) -> None:
    monkeypatch.delenv("TENANT_ID", raising=False)
    assert pipeline.get_tenant_id() == "default"


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
    async def fake_analyze_smart_cache(**kwargs):
        captured.update(kwargs)
        return {
            "provider_used": "test",
            "analysis": [],
            "exposures": [],
        }

    monkeypatch.setattr(
        pipeline,
        "analyze_smart_cache",
        fake_analyze_smart_cache,
    )

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=True,
    )

    # Pipeline forwards the complete evidence ledger. Deduplication is an AI
    # payload concern and is exercised through build_user_prompt tests.
    assert len(state["evidence"]) == 1
    assert len(captured["evidence_records"]) == 1


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

    async def fake_enrich(records, **kwargs):
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
    async def fake_analyze_smart_cache(**kwargs):
        captured.update(kwargs)
        return {
            "provider_used": "test",
            "analysis": [],
            "exposures": [],
        }

    monkeypatch.setattr(
        pipeline,
        "analyze_smart_cache",
        fake_analyze_smart_cache,
    )

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=True,
    )

    # Pipeline retains both the scanner mirror and the enrichment record and
    # forwards the complete ledger. AI payload filtering is tested separately.
    assert len(state["evidence"]) == 2
    assert len(captured["evidence_records"]) == 2
    contextual = next(
        item for item in captured["evidence_records"]
        if item["relation"] == "security_publication"
    )
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
        and event.get("key") == "ai_failed"
        and event.get("args", {}).get("error_type") == "RuntimeError"
        and "synthetic AI failure" in event.get("args", {}).get("error", "")
        for event in state["events"]
    )

def test_pipeline_verification_failure_clears_stale_url_state(monkeypatch) -> None:
    record = EvidenceRecord(
        evidence_id="stale-verification",
        source="Example Security",
        source_type="security_publication",
        relation=EvidenceRelation.SECURITY_PUBLICATION,
        directness=EvidenceDirectness.CONTEXTUAL,
        confidence=0.65,
        observed_at="2026-10-09T00:00:00+00:00",
        published_at="2026-10-08T00:00:00+00:00",
        domain="example.com",
        url="https://example.com/report",
        title="Security report",
        summary="Security context.",
        assertion_scope="security_publication_context_only",
        verification_state="reachable",
        verification_observed_at="2026-10-08T00:00:00+00:00",
        metadata={
            "keep": "unrelated metadata",
            "url_verification": {"status_code": 200, "reachable": True},
        },
    )

    monkeypatch.setattr(
        pipeline,
        "service_findings_to_evidence",
        lambda services: [record],
    )

    async def fake_enrich(records, **kwargs):
        return list(records)

    async def failed_verification(records):
        raise RuntimeError("synthetic verifier failure")

    monkeypatch.setattr(pipeline, "enrich_evidence", fake_enrich)
    monkeypatch.setattr(pipeline, "verify_evidence_records", failed_verification)

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=False,
        enable_breach=False,
        with_ai=False,
    )

    assert len(state["evidence"]) == 1
    evidence = state["evidence"][0]
    assert evidence["verification_state"] == "unknown"
    assert evidence["verification_observed_at"] is None
    assert "url_verification" not in evidence["metadata"]
    assert evidence["metadata"]["keep"] == "unrelated metadata"



def test_pipeline_normalization_failure_does_not_abort_scan_or_ai(monkeypatch) -> None:
    monkeypatch.setenv("FIRECRAWL_API_KEY", "")
    captured: dict = {}

    monkeypatch.setattr(
        pipeline,
        "scan_osint_footprint",
        lambda email, lang="id": [
            {
                "name": "Example",
                "domain": "example.com",
                "source": "OSINT / Holehe",
                "subject": "Observed service association",
            }
        ],
    )

    def fail_normalization(*args, **kwargs):
        raise RuntimeError("synthetic normalizer failure")

    async def fake_analyze_smart_cache(**kwargs):
        captured.update(kwargs)
        return {"provider_used": "test", "analysis": [], "exposures": []}

    monkeypatch.setattr(pipeline, "service_findings_to_evidence", fail_normalization)
    monkeypatch.setattr(pipeline, "analyze_smart_cache", fake_analyze_smart_cache)

    state = pipeline.run_scan(
        email="subject@example.org",
        enable_imap=False,
        enable_osint=True,
        enable_breach=False,
        with_ai=True,
    )

    assert len(state["services"]) == 1
    assert state["evidence"] == []
    assert captured["evidence_records"] == []
    assert any(
        event.get("key") == "evidence_normalization_failed"
        and event.get("stage") == "evidence_start"
        for event in state["events"]
    )
