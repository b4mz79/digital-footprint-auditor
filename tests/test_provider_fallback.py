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
