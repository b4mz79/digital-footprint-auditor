from services.ai_agent import (
    MAX_LLM_EVIDENCE_PAYLOAD_CHARS,
    build_user_prompt,
)


def test_build_user_prompt_bounds_large_evidence_payload() -> None:
    evidence = []
    for index in range(150):
        evidence.append(
            {
                "evidence_id": f"ev-{index}",
                "source": "Synthetic Publisher",
                "source_type": "security_publication",
                "relation": "security_publication",
                "directness": "contextual",
                "confidence": 0.8,
                "observed_at": "2026-10-07T00:00:00+00:00",
                "published_at": "2026-10-01",
                "domain": f"service-{index}.example.com",
                "url": f"https://service-{index}.example.com/security",
                "title": "Security publication " + ("x" * 1800),
                "summary": "Security context " + ("y" * 1800),
                "provenance": {"publisher": "Synthetic Publisher"},
                "metadata": {"finding_type": "security_context"},
            }
        )

    prompt = build_user_prompt(
        email="subject@example.org",
        found_services=[
            {
                "name": "Example Service",
                "domain": "example.com",
                "source": "synthetic",
            }
        ],
        lang="id",
        evidence_records=evidence,
        addon_results=None,
        scan_status={"breach_scan_complete": False, "failed_engines": ["BreachDirectory"]},
    )

    assert len(prompt) < 60_000
    marker = "<UNTRUSTED_EVIDENCE>\n"
    evidence_start = prompt.index(marker) + len(marker)
    evidence_end = prompt.index("\n</UNTRUSTED_EVIDENCE>", evidence_start)
    evidence_payload = prompt[evidence_start:evidence_end]
    assert len(evidence_payload) <= MAX_LLM_EVIDENCE_PAYLOAD_CHARS


def test_build_user_prompt_excludes_scanner_mirror_but_keeps_new_evidence() -> None:
    prompt = build_user_prompt(
        email="subject@example.org",
        found_services=[
            {
                "name": "Example Service",
                "domain": "example.com",
                "source": "OSINT / Holehe",
                "subject": "Active account detected",
            }
        ],
        lang="id",
        evidence_records=[
            {
                "evidence_id": "scanner-mirror",
                "source": "OSINT / Holehe",
                "source_type": "osint",
                "relation": "target_resource",
                "directness": "direct",
                "confidence": 0.8,
                "observed_at": "2026-10-07T00:00:00+00:00",
                "published_at": None,
                "domain": "example.com",
                "url": "",
                "title": "Target-associated service: Example Service",
                "summary": "Active account detected",
                "provenance": {
                    "provider": "osint",
                    "normalizer": "service_findings_to_evidence",
                    "assertion_scope": "service_association_only",
                },
                "metadata": {
                    "finding_type": "service_discovery",
                    "service_name": "Example Service",
                    "scanner_source": "OSINT / Holehe",
                },
                "assertion_scope": "service_association_only",
                "verification_scope": "url_accessibility",
                "verification_state": "unknown",
            },
            {
                "evidence_id": "context-1",
                "source": "Kaspersky Securelist",
                "source_type": "security_publication",
                "relation": "security_publication",
                "directness": "contextual",
                "confidence": 0.65,
                "observed_at": "2026-10-07T00:00:00+00:00",
                "published_at": "2026-10-01",
                "domain": "example.com",
                "url": "https://securelist.com/example",
                "title": "Example security context",
                "summary": "Security incident context.",
                "provenance": {
                    "provider": "firecrawl_search",
                    "normalizer": "security_publication_context",
                    "assertion_scope": "security_publication_context_only",
                },
                "metadata": {
                    "finding_type": "security_context",
                },
                "assertion_scope": "security_publication_context_only",
                "verification_scope": "url_accessibility",
                "verification_state": "unknown",
            },
        ],
        scan_status={"breach_scan_complete": True, "failed_engines": []},
    )

    marker = "<UNTRUSTED_EVIDENCE>\n"
    evidence_start = prompt.index(marker) + len(marker)
    evidence_end = prompt.index("\n</UNTRUSTED_EVIDENCE>", evidence_start)
    evidence_payload = prompt[evidence_start:evidence_end]

    assert "scanner-mirror" not in evidence_payload
    assert "context-1" in evidence_payload

def test_contextual_evidence_after_scanner_mirror_cap_reaches_prompt() -> None:
    scanner_mirrors = [
        {
            "evidence_id": f"scanner-mirror-{index}",
            "source": "OSINT / Holehe",
            "source_type": "osint",
            "relation": "target_resource",
            "directness": "direct",
            "confidence": 0.8,
            "observed_at": "2026-10-07T00:00:00+00:00",
            "published_at": None,
            "domain": f"service-{index}.example.com",
            "url": "",
            "title": "Target-associated service",
            "summary": "Scanner observation.",
            "provenance": {
                "provider": "osint",
                "normalizer": "service_findings_to_evidence",
                "assertion_scope": "service_association_only",
            },
            "metadata": {"finding_type": "service_discovery"},
            "assertion_scope": "service_association_only",
        }
        for index in range(150)
    ]
    contextual = {
        "evidence_id": "context-after-scanner-cap",
        "source": "Kaspersky Securelist",
        "source_type": "security_publication",
        "relation": "security_publication",
        "directness": "contextual",
        "confidence": 0.65,
        "observed_at": "2026-10-07T00:00:00+00:00",
        "published_at": "2026-10-01",
        "domain": "example.com",
        "url": "https://securelist.com/example",
        "title": "Example security context",
        "summary": "Security incident context.",
        "provenance": {
            "provider": "firecrawl_search",
            "publisher_domain": "securelist.com",
            "query_scope": "domain_only",
            "assertion_scope": "security_publication_context_only",
        },
        "metadata": {"finding_type": "security_context"},
        "assertion_scope": "security_publication_context_only",
    }

    prompt = build_user_prompt(
        email="subject@example.org",
        found_services=[
            {"name": "Example Service", "domain": "example.com", "source": "OSINT"}
        ],
        lang="id",
        evidence_records=scanner_mirrors + [contextual],
    )

    marker = "<UNTRUSTED_EVIDENCE>\\n"
    evidence_start = prompt.index(marker) + len(marker)
    evidence_end = prompt.index("\\n</UNTRUSTED_EVIDENCE>", evidence_start)
    evidence_payload = prompt[evidence_start:evidence_end]

    assert "context-after-scanner-cap" in evidence_payload
    assert "scanner-mirror-" not in evidence_payload


def test_prompt_defines_url_verification_as_accessibility_only() -> None:
    prompt = build_user_prompt(
        email="subject@example.org",
        found_services=[{"name": "Example Service", "domain": "example.com"}],
        evidence_records=[
            {
                "evidence_id": "unreachable-publication",
                "source": "Kaspersky Securelist",
                "source_type": "security_publication",
                "relation": "security_publication",
                "directness": "contextual",
                "assertion_scope": "security_publication_context_only",
                "verification_scope": "url_accessibility",
                "verification_state": "unreachable",
                "domain": "example.com",
                "url": "https://securelist.com/example",
                "title": "Example security context",
                "summary": "Security incident context.",
            }
        ],
    )

    assert "Neither state proves or " in prompt
    assert "Never raise risk solely because a URL is unreachable." in prompt

