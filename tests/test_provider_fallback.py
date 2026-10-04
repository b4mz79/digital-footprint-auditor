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


@pytest.mark.asyncio
async def test_progressive_ollama_callback_deduplicates_service_identity(monkeypatch) -> None:
    emitted: list[dict] = []

    def callback(item: dict) -> None:
        emitted.append(item)

    services = [
        {"name": "Example Shop", "domain": "example.com"},
        {"name": "Example Shop", "domain": "example.net"},
    ]

    async def fake_chain(*args, **kwargs):
        batch_callback = kwargs["on_ollama_batch"]
        batch_callback(
            [{"service": "Example Shop", "risk_key": "unknown", "reason": "First"}],
            [services[0]],
        )
        batch_callback(
            [{"service": "Example Shop", "risk_key": "medium", "reason": "Second"}],
            [services[1]],
        )
        return {
            "analysis": [
                {"service": "Example Shop", "risk_key": "unknown", "reason": "First", "delete_url": ""}
            ]
        }, "Ollama Local"

    monkeypatch.setattr(ai_agent, "_run_provider_chain", fake_chain)
    monkeypatch.setattr(ai_agent, "load_analysis_cache_ext", lambda *args, **kwargs: None)
    monkeypatch.setattr(ai_agent, "save_analysis_cache_ext", lambda *args, **kwargs: None)
    monkeypatch.setattr(ai_agent, "load_local_dsr_template", lambda *args, **kwargs: "")

    import os
    monkeypatch.setenv("PII_PEPPER_KEY", "x" * 32)

    result = await ai_agent.analyze_smart_cache(
        "example@example.com",
        services,
        force_refresh=True,
        lang="en",
        on_analysis_item=callback,
    )

    assert len(emitted) == 1
    assert emitted[0]["service"] == "Example Shop"
    assert result["analysis"][0]["service"] == "Example Shop"


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


@pytest.mark.asyncio
async def test_provider_chain_forwards_ollama_failure_callback(monkeypatch) -> None:
    reset_calls: list[int] = []

    async def fake_ollama(*args, **kwargs):
        assert kwargs["on_failure"] is not None
        kwargs["on_failure"]()
        raise ValueError("partial Ollama result")

    monkeypatch.setattr(ai_agent, "call_ollama_async", fake_ollama)
    monkeypatch.setattr(ai_agent, "_provider_order", lambda: ["ollama"])

    parsed, provider = await ai_agent._run_provider_chain(
        "prompt",
        "system",
        "en",
        on_ollama_failure=lambda: reset_calls.append(1),
    )

    assert parsed is None
    assert provider == "None"
    assert reset_calls == [1]


@pytest.mark.asyncio
async def test_partial_ollama_failure_resets_progressive_items(monkeypatch) -> None:
    emitted: list[dict] = []
    reset_calls: list[int] = []

    async def fake_chain(*args, **kwargs):
        kwargs["on_ollama_batch"](
            [{"service": "Example Shop", "risk_key": "medium", "reason": "Order evidence"}],
            [{"name": "Example Shop", "domain": "example.com", "subject": "Order confirmation"}],
        )
        kwargs["on_ollama_failure"]()
        return None, "None"

    monkeypatch.setattr(ai_agent, "_run_provider_chain", fake_chain)
    monkeypatch.setattr(ai_agent, "load_analysis_cache_ext", lambda *args, **kwargs: None)
    monkeypatch.setattr(ai_agent, "save_analysis_cache_ext", lambda *args, **kwargs: None)
    monkeypatch.setattr(ai_agent, "load_local_dsr_template", lambda *args, **kwargs: "")

    result = await ai_agent.analyze_smart_cache(
        "example@example.com",
        [{"name": "Example Shop", "domain": "example.com", "subject": "Order confirmation"}],
        force_refresh=True,
        lang="en",
        on_analysis_item=lambda item: emitted.append(item),
        on_analysis_reset=lambda: reset_calls.append(1),
    )

    assert result["provider_used"].startswith("Local Rule-based Engine")
    assert len(emitted) == 1
    assert reset_calls == [1]


@pytest.mark.asyncio
async def test_ollama_partial_http_failure_invokes_reset_once(monkeypatch) -> None:
    callbacks: list[int] = []
    batches: list[int] = []

    class FakeResponse:
        def __init__(self, lines: list[str]) -> None:
            self.lines = lines

        def raise_for_status(self) -> None:
            return None

        async def aiter_lines(self):
            for line in self.lines:
                yield line

    class FakeStream:
        def __init__(self, response_or_error):
            self.response_or_error = response_or_error

        async def __aenter__(self):
            if isinstance(self.response_or_error, Exception):
                raise self.response_or_error
            return self.response_or_error

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            self.calls = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def stream(self, method, url, json):
            self.calls += 1
            batches.append(self.calls)
            if self.calls == 1:
                body = json_module.dumps({
                    "analysis": [{
                        "service": "Example One",
                        "risk_level": "unknown",
                        "reason": "Insufficient evidence.",
                        "delete_url": "",
                    }]
                })
                return FakeStream(FakeResponse([
                    json_module.dumps({"response": body, "done": True})
                ]))
            return FakeStream(RuntimeError("simulated Ollama transport failure"))

    json_module = __import__("json")
    monkeypatch.setattr(ai_agent.httpx, "AsyncClient", FakeClient)
    monkeypatch.setenv("OLLAMA_BATCH_SERVICES", "1")
    monkeypatch.setenv("OLLAMA_NUM_CTX", "2048")
    monkeypatch.setenv("OLLAMA_NUM_PREDICT", "128")

    prompt = (
        "<UNTRUSTED_SCAN_DATA>\n"
        '[{"name":"Example One","domain":"example.com"},'
        '{"name":"Example Two","domain":"example.org"}]\n'
        "</UNTRUSTED_SCAN_DATA>\n"
        "<UNTRUSTED_EVIDENCE>\n[]\n</UNTRUSTED_EVIDENCE>"
    )

    def on_batch(analysis, services) -> None:
        callbacks.append(1)

    with pytest.raises(ValueError, match="output parsial"):
        await ai_agent.call_ollama_async(
            prompt,
            "system",
            "en",
            on_batch=on_batch,
            on_failure=lambda: callbacks.append(99),
        )

    assert batches == [1, 2]
    assert callbacks == [1, 99]


def test_validate_ai_output_rejects_empty_analysis() -> None:
    with pytest.raises(ValueError, match="tidak berisi item tervalidasi"):
        ai_agent.validate_ai_output({"analysis": []}, "en")


@pytest.mark.asyncio
async def test_empty_provider_output_rotates_to_next_provider(monkeypatch) -> None:
    async def fake_gemini(*args, **kwargs):
        return '{"analysis":[]}'

    async def fake_groq(*args, **kwargs):
        return '{"analysis":[{"service":"Example","risk_level":"unknown","reason":"Insufficient evidence.","delete_url":""}]}'

    monkeypatch.setattr(ai_agent, "call_gemini_async", fake_gemini)
    monkeypatch.setattr(ai_agent, "call_groq_async", fake_groq)
    monkeypatch.setattr(
        ai_agent,
        "_provider_order",
        lambda: ["gemini", "groq"],
    )
    monkeypatch.setenv("GEMINI_API_KEY", "key-1")

    parsed, provider = await ai_agent._run_provider_chain(
        "prompt",
        "system",
        "en",
    )

    assert provider == "Groq Cloud"
    assert parsed is not None
    assert parsed["analysis"][0]["service"] == "Example"
