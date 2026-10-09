from __future__ import annotations

from services import ai_agent


def test_ai_agent_import() -> None:
    assert ai_agent is not None


def test_build_user_prompt_includes_structured_evidence_without_target_pii() -> None:
    prompt = ai_agent.build_user_prompt(
        "user@example.org",
        [
            {
                "name": "Example",
                "domain": "example.com",
                "source": "OSINT / Holehe",
                "subject": "Active account detected",
            }
        ],
        evidence_records=[
            {
                "evidence_id": "abc123",
                "source": "OSINT / Holehe",
                "source_type": "osint",
                "relation": "target_resource",
                "directness": "direct",
                "assertion_scope": "service_association_only",
                "verification_scope": "url_accessibility",
                "verification_state": "unknown",
                "verification_observed_at": "2026-10-05T00:00:00+00:00",
                "confidence": 0.8,
                "observed_at": "2026-10-03T00:00:00+00:00",
                "published_at": None,
                "domain": "example.com",
                "url": "",
                "title": "Target-associated service: Example",
                "summary": "Account user@example.org phone +62 812-3456-7890",
                "provenance": {
                    "provider": "osint",
                    "assertion_scope": "service_association_only",
                    "unexpected": "should not be sent",
                },
                "metadata": {
                    "raw_target": "user@example.org",
                },
            }
        ],
    )

    assert "<UNTRUSTED_EVIDENCE>" in prompt
    assert "target_resource" in prompt
    assert "service_association_only" in prompt
    assert "unexpected" not in prompt
    assert "user@example.org" not in prompt
    assert "+62 812-3456-7890" not in prompt
    assert "[EMAIL_REDACTED]" in prompt
    assert "[PHONE_REDACTED]" in prompt
    assert "url_accessibility" in prompt
    assert "unknown" in prompt
    assert "verification_observed_at" in prompt


def test_input_fingerprint_changes_when_evidence_changes() -> None:
    services = [{"name": "Example", "domain": "example.com", "source": "OSINT"}]
    findings: list[dict] = []

    first = ai_agent._input_fingerprint(
        services,
        findings,
        [
            {
                "evidence_id": "one",
                "source": "OSINT",
                "source_type": "osint",
                "relation": "target_resource",
                "directness": "direct",
                "confidence": 0.8,
                "domain": "example.com",
                "title": "One",
            }
        ],
    )
    second = ai_agent._input_fingerprint(
        services,
        findings,
        [
            {
                "evidence_id": "two",
                "source": "OSINT",
                "source_type": "osint",
                "relation": "target_resource",
                "directness": "direct",
                "confidence": 0.8,
                "domain": "example.com",
                "title": "Two",
            }
        ],
    )

    assert first != second


def test_evidence_lineage_is_attached_deterministically() -> None:
    services = [
        {
            "name": "Example",
            "domain": "sub.example.com",
        }
    ]
    evidence = [
        {
            "evidence_id": "direct-1",
            "domain": "example.com",
            "provenance": {
                "service_name": "Example",
                "assertion_scope": "service_association_only",
            },
        },
        {
            "evidence_id": "context-1",
            "domain": "example.com",
            "provenance": {
                "provider": "firecrawl_search",
                "publisher_domain": "securelist.com",
            },
        },
        {
            "evidence_id": "other-1",
            "domain": "other.example.net",
            "provenance": {
                "service_name": "Other",
            },
        },
    ]

    analysis = [{"service": "Example", "risk_key": "unknown"}]

    linked = ai_agent._attach_evidence_lineage(
        analysis,
        services,
        evidence,
    )

    assert linked[0]["evidence_ids"] == ["direct-1", "context-1"]


def test_cached_analysis_rebuild_rejects_forged_evidence_lineage() -> None:
    services = [{"name": "Example", "domain": "sub.example.com"}]
    findings: list[dict] = []
    evidence = [
        {
            "evidence_id": "real-evidence",
            "domain": "example.com",
            "provenance": {"service_name": "Example"},
        },
        {
            "evidence_id": "unrelated-evidence",
            "domain": "unrelated.example.net",
            "provenance": {"service_name": "Unrelated"},
        },
    ]
    cached_analysis = [
        {
            "service": "Example",
            "risk_level": "Low",
            "reason": "Cached reason",
            "delete_url": "-",
            "evidence_ids": ["forged-evidence", "unrelated-evidence"],
            "risk_guarded": False,
        }
    ]

    rebuilt, exposures = ai_agent._rebuild_cached_analysis(
        cached_analysis,
        services,
        findings,
        evidence,
        "id",
    )

    assert exposures == []
    assert rebuilt[0]["evidence_ids"] == ["real-evidence"]
    assert "forged-evidence" not in rebuilt[0]["evidence_ids"]
    assert "unrelated-evidence" not in rebuilt[0]["evidence_ids"]


def test_finalize_analysis_normalizes_unsupported_reason_when_already_unknown() -> None:
    services = [{"name": "Example", "domain": "example.com", "subject": "Welcome! Verify your email address."}]
    analysis = [{
        "service": "Example",
        "risk_key": "unknown",
        "risk_level": "Unknown",
        "reason": "Insufficient evidence to determine risk.",
        "delete_url": "https://example.com/delete",
    }]

    finalized, exposures = ai_agent._finalize_analysis(analysis, services, [], "en")

    assert exposures == []
    assert finalized[0]["risk_key"] == "unknown"
    assert finalized[0]["reason"] == ai_agent.t("unknown_generic_event_reason", lang="en")
    assert finalized[0]["delete_url"] == "-"
    assert finalized[0]["risk_guarded"] is True


def test_build_user_prompt_marks_incomplete_breach_scan() -> None:
    prompt = ai_agent.build_user_prompt(
        "user@example.org",
        [{"name": "Example", "domain": "example.com", "source": "OSINT"}],
        scan_status={
            "breach_scan_complete": False,
            "failed_engines": ["BreachDirectory", "DuckDuckGo"],
        },
    )

    assert "<SCAN_STATUS>" in prompt
    assert '"breach_scan_complete":false' in prompt
    assert "BreachDirectory" in prompt
    assert "DuckDuckGo" in prompt
    assert "do not describe the absence of breach findings" in prompt
