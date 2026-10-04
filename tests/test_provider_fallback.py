from __future__ import annotations

import pytest

from services import ai_agent


def test_provider_fallback_contract():
    providers = ["Gemini", "Groq"]
    assert providers[-1] == "Groq"


def test_finalize_caps_order_high_without_high_activity() -> None:
    services = [
        {
            "name": "Example Shop",
            "domain": "example.com",
            "subject": "Order confirmation for your purchase",
        }
    ]
    analysis = [
        {
            "service": "Example Shop",
            "risk_key": "high",
            "reason": "The model inferred high risk from the order.",
            "delete_url": "",
        }
    ]

    final, exposures = ai_agent._finalize_analysis(
        analysis,
        services,
        [],
        "en",
    )

    assert exposures == []
    assert final[0]["risk_key"] == "medium"
    assert final[0]["risk_level"] == ai_agent.t("risk_medium", lang="en")
    assert final[0]["reason"] == ai_agent.t("medium_activity_guard_reason", lang="en")


@pytest.mark.asyncio
async def test_ollama_partial_failure_rotates_to_next_provider(monkeypatch) -> None:
    async def fake_ollama(*args, **kwargs):
        raise ValueError("Ollama menghasilkan output parsial")

    async def fake_groq(*args, **kwargs):
        return '{"analysis":[{"service":"Example","risk_level":"unknown","reason":"Insufficient evidence.","delete_url":""}]}'

    monkeypatch.setattr(ai_agent, "call_ollama_async", fake_ollama)
    monkeypatch.setattr(ai_agent, "call_groq_async", fake_groq)
    monkeypatch.setattr(
        ai_agent,
        "_provider_order",
        lambda: ["ollama", "groq"],
    )

    parsed, provider = await ai_agent._run_provider_chain(
        "prompt",
        "system",
        "en",
    )

    assert provider == "Groq Cloud"
    assert parsed is not None
    assert parsed["analysis"][0]["service"] == "Example"



def test_rule_based_fallback_keeps_medium_reason_coherent() -> None:
    services = [
        {
            "name": "Example Shop",
            "domain": "example.com",
            "subject": "Order confirmation for your purchase",
        }
    ]

    final, exposures = ai_agent._finalize_analysis([], services, [], "en")

    assert exposures == []
    assert final[0]["risk_key"] == "medium"
    assert final[0]["risk_level"] == ai_agent.t("risk_medium", lang="en")
    assert final[0]["reason"] == ai_agent.t("medium_activity_guard_reason", lang="en")


def test_rule_based_fallback_keeps_high_reason_coherent() -> None:
    services = [
        {
            "name": "Example Bank",
            "domain": "example.com",
            "subject": "Your banking authentication code",
        }
    ]

    final, exposures = ai_agent._finalize_analysis([], services, [], "en")

    assert exposures == []
    assert final[0]["risk_key"] == "high"
    assert final[0]["risk_level"] == ai_agent.t("risk_high", lang="en")
    assert final[0]["reason"] == ai_agent.t("fallback_reason", lang="en")


def test_model_insufficient_reason_does_not_override_explicit_activity_floor() -> None:
    services = [
        {
            "name": "Example Bank",
            "domain": "example.com",
            "subject": "Payment received for your account",
        }
    ]
    analysis = [
        {
            "service": "Example Bank",
            "risk_key": "medium",
            "reason": "Insufficient evidence to determine risk.",
            "delete_url": "",
        }
    ]

    final, exposures = ai_agent._finalize_analysis(analysis, services, [], "en")

    assert exposures == []
    assert final[0]["risk_key"] == "high"
    assert final[0]["reason"] == ai_agent.t("fallback_reason", lang="en")


def test_breach_floor_raises_risk_with_coherent_reason() -> None:
    services = [
        {
            "name": "Example Bank",
            "domain": "example.com",
            "subject": "Welcome to Example Bank",
        }
    ]
    findings = [
        {
            "kind": "breach_db",
            "dataset": "Example Bank breach",
            "has_password": True,
            "record_count": 10,
        }
    ]
    analysis = [
        {
            "service": "Example Bank",
            "risk_key": "unknown",
            "reason": "Insufficient evidence to determine risk.",
            "delete_url": "",
        }
    ]

    final, exposures = ai_agent._finalize_analysis(analysis, services, findings, "en")

    assert exposures == []
    assert final[0]["risk_key"] == "high"
    assert final[0]["risk_level"] == ai_agent.t("risk_high", lang="en")
    assert final[0]["risk_raised"] is True
    assert final[0]["risk_guarded"] is True
    assert final[0]["reason"] == ai_agent.t(
        "evidence_note",
        lang="en",
        count=1,
        level=ai_agent.t("risk_high", lang="en"),
    )


def test_medium_breach_floor_raises_risk_with_coherent_reason() -> None:
    services = [
        {
            "name": "Example Shop",
            "domain": "example.com",
            "subject": "Welcome to Example Shop",
        }
    ]
    findings = [
        {
            "kind": "breach_db",
            "dataset": "Example Shop breach",
            "has_password": False,
            "record_count": 10,
        }
    ]
    analysis = [
        {
            "service": "Example Shop",
            "risk_key": "unknown",
            "reason": "Insufficient evidence to determine risk.",
            "delete_url": "",
        }
    ]

    final, exposures = ai_agent._finalize_analysis(analysis, services, findings, "en")

    assert exposures == []
    assert final[0]["risk_key"] == "medium"
    assert final[0]["risk_level"] == ai_agent.t("risk_medium", lang="en")
    assert final[0]["risk_raised"] is True
    assert final[0]["risk_guarded"] is True
    assert final[0]["reason"] == ai_agent.t(
        "evidence_note",
        lang="en",
        count=1,
        level=ai_agent.t("risk_medium", lang="en"),
    )
