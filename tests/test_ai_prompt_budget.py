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
        scorecard_result=None,
        scan_status={"breach_scan_complete": False, "failed_engines": ["BreachDirectory"]},
    )

    assert len(prompt) < 60_000
    marker = "<UNTRUSTED_EVIDENCE>\n"
    evidence_start = prompt.index(marker) + len(marker)
    evidence_end = prompt.index("\n</UNTRUSTED_EVIDENCE>", evidence_start)
    evidence_payload = prompt[evidence_start:evidence_end]
    assert len(evidence_payload) <= MAX_LLM_EVIDENCE_PAYLOAD_CHARS
