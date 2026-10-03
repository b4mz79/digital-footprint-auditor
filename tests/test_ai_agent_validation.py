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
