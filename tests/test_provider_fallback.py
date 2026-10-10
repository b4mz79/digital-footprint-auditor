from __future__ import annotations

import json

import pytest

from services import ai_agent


@pytest.mark.asyncio
async def test_timed_provider_call_logs_elapsed_time_and_preserves_result(caplog) -> None:
    async def fake_call(value: str) -> str:
        return value

    with caplog.at_level("INFO"):
        result = await ai_agent._timed_provider_call(
            "Gemini",
            "Key #2",
            fake_call,
            "response",
        )

    assert result == "response"
    assert any(
        "[AI Timing] provider=Gemini attempt=Key #2 phase=api_call elapsed_seconds="
        in record.message
        for record in caplog.records
    )


@pytest.mark.asyncio
async def test_timed_provider_call_logs_elapsed_time_and_preserves_exception(caplog) -> None:
    async def fake_call() -> str:
        raise RuntimeError("provider failed")

    with caplog.at_level("INFO"):
        with pytest.raises(RuntimeError, match="provider failed"):
            await ai_agent._timed_provider_call(
                "Groq Cloud",
                "single attempt",
                fake_call,
            )

    assert any(
        "[AI Timing] provider=Groq Cloud attempt=single attempt phase=api_call elapsed_seconds="
        in record.message
        for record in caplog.records
    )


def test_timed_response_validation_logs_elapsed_time_and_preserves_validation(caplog) -> None:
    valid = {
        "analysis": [
            {
                "service": "Example",
                "risk_level": "Unknown",
                "reason": "Insufficient evidence.",
                "delete_url": "",
            }
        ]
    }
    raw = json.dumps(valid)

    with caplog.at_level("INFO"):
        result = ai_agent._timed_response_validation(
            "OpenAI",
            "single attempt",
            raw,
            "en",
        )

    assert result["analysis"][0]["service"] == "Example"
    assert any(
        "[AI Timing] provider=OpenAI attempt=single attempt phase=response_validation elapsed_seconds="
        in record.message
        for record in caplog.records
    )


@pytest.mark.asyncio
async def test_provider_chain_logs_total_elapsed_time(monkeypatch, caplog) -> None:
    async def fake_impl(*args, **kwargs):
        return None, "None"

    monkeypatch.setattr(ai_agent, "_run_provider_chain_impl", fake_impl)

    with caplog.at_level("INFO"):
        result = await ai_agent._run_provider_chain("prompt", "system", "en")

    assert result == (None, "None")
    assert any(
        "[AI Timing] phase=provider_chain elapsed_seconds=" in record.message
        and "outcome=None" in record.message
        for record in caplog.records
    )


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
    # The provider chain checks configuration before invoking the mocked SDK call.
    monkeypatch.setenv("GROQ_API_KEY", "test-groq-key")

    async def fake_ollama(*args, **kwargs):
        raise ValueError("Ollama returned a partial result")

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

    with pytest.raises(ValueError, match="partial result"):
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
    with pytest.raises(ValueError, match="contains no validated items"):
        ai_agent.validate_ai_output({"analysis": []}, "en")


@pytest.mark.asyncio
async def test_empty_provider_output_rotates_to_next_provider(monkeypatch) -> None:
    # Keep the fallback test independent of a developer's local .env file.
    monkeypatch.setenv("GROQ_API_KEY", "test-groq-key")

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


@pytest.mark.asyncio
async def test_analyze_smart_cache_rejects_invalid_cached_payload(monkeypatch) -> None:
    services = [
        {"name": "Example Shop", "domain": "example.com", "subject": "Order confirmation"},
    ]
    findings: list[dict] = []
    evidence: list[dict] = []
    scan_status = {
        "breach_scan_complete": True,
        "failed_engines": [],
    }

    fingerprint = ai_agent._input_fingerprint(
        services,
        findings,
        evidence,
        scan_status,
    )

    # Same fingerprint, but an unusable cached analysis. This must be a
    # cache miss rather than a successful cached result.
    invalid_cache = {
        "provider_used": "Groq Cloud",
        "is_from_cache": True,
        "input_fp": fingerprint,
        "analysis": [],
        "exposures": [],
        "dsr_template": "",
    }

    provider_calls: list[int] = []

    async def fake_chain(*args, **kwargs):
        provider_calls.append(1)
        return (
            {
                "analysis": [
                    {
                        "service": "Example Shop",
                        "risk_key": "medium",
                        "risk_level": "Medium",
                        "reason": "Order evidence.",
                        "delete_url": "",
                    }
                ]
            },
            "Groq Cloud",
        )

    monkeypatch.setattr(
        ai_agent,
        "load_analysis_cache_ext",
        lambda *args, **kwargs: invalid_cache,
    )
    monkeypatch.setattr(
        ai_agent,
        "save_analysis_cache_ext",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        ai_agent,
        "load_local_dsr_template",
        lambda *args, **kwargs: "",
    )
    monkeypatch.setattr(ai_agent, "_run_provider_chain", fake_chain)

    result = await ai_agent.analyze_smart_cache(
        "example@example.com",
        services,
        force_refresh=False,
        lang="en",
        breach_findings=findings,
        evidence_records=evidence,
        scan_status=scan_status,
    )

    assert provider_calls == [1]
    assert result["is_from_cache"] is False
    assert result["provider_used"] == "Groq Cloud"
    assert result["analysis"][0]["service"] == "Example Shop"


@pytest.mark.asyncio
async def test_analyze_smart_cache_rejects_cached_none_provider(monkeypatch) -> None:
    services = [
        {"name": "Example Shop", "domain": "example.com"},
    ]
    scan_status = {
        "breach_scan_complete": True,
        "failed_engines": [],
    }
    fingerprint = ai_agent._input_fingerprint(
        services,
        [],
        [],
        scan_status,
    )

    invalid_cache = {
        "provider_used": "None",
        "is_from_cache": True,
        "input_fp": fingerprint,
        "analysis": [
            {
                "service": "Example Shop",
                "risk_level": "Unknown",
                "reason": "Insufficient evidence.",
                "delete_url": "",
            }
        ],
        "exposures": [],
        "dsr_template": "",
    }

    provider_calls: list[int] = []

    async def fake_chain(*args, **kwargs):
        provider_calls.append(1)
        return (
            {
                "analysis": [
                    {
                        "service": "Example Shop",
                        "risk_key": "unknown",
                        "risk_level": "Unknown",
                        "reason": "Insufficient evidence.",
                        "delete_url": "",
                    }
                ]
            },
            "Google Gemini",
        )

    monkeypatch.setattr(
        ai_agent,
        "load_analysis_cache_ext",
        lambda *args, **kwargs: invalid_cache,
    )
    monkeypatch.setattr(
        ai_agent,
        "save_analysis_cache_ext",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        ai_agent,
        "load_local_dsr_template",
        lambda *args, **kwargs: "",
    )
    monkeypatch.setattr(ai_agent, "_run_provider_chain", fake_chain)

    result = await ai_agent.analyze_smart_cache(
        "example@example.com",
        services,
        force_refresh=False,
        lang="en",
        scan_status=scan_status,
    )

    assert provider_calls == [1]
    assert result["is_from_cache"] is False
    assert result["provider_used"] == "Google Gemini"


@pytest.mark.asyncio
async def test_gemini_invalid_output_rotates_to_next_key(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_gemini(prompt, key, sys_prompt):
        calls.append(key)
        if key == "key-1":
            return '{"analysis":[]}'
        return '{"analysis":[{"service":"Example","risk_level":"unknown","reason":"Insufficient evidence.","delete_url":""}]}'

    monkeypatch.setenv("GEMINI_API_KEY", "key-1")
    monkeypatch.setenv("GOOGLE_API_KEY", "key-2")
    for index in range(1, 7):
        monkeypatch.delenv(f"GOOGLE_API_KEY_{index}", raising=False)

    monkeypatch.setattr(ai_agent, "call_gemini_async", fake_gemini)
    monkeypatch.setattr(
        ai_agent,
        "_provider_order",
        lambda: ["gemini", "groq"],
    )

    parsed, provider = await ai_agent._run_provider_chain(
        "prompt",
        "system",
        "en",
    )

    assert calls == ["key-1", "key-2"]
    assert provider == "Google Gemini"
    assert parsed is not None
    assert parsed["analysis"][0]["service"] == "Example"


@pytest.mark.asyncio
async def test_gemini_transport_failure_rotates_to_next_key(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_gemini(prompt, key, sys_prompt):
        calls.append(key)
        if key == "key-1":
            raise RuntimeError("temporary Gemini failure")
        return '{"analysis":[{"service":"Example","risk_level":"unknown","reason":"Insufficient evidence.","delete_url":""}]}'

    monkeypatch.setenv("GEMINI_API_KEY", "key-1")
    monkeypatch.setenv("GOOGLE_API_KEY", "key-2")
    for index in range(1, 7):
        monkeypatch.delenv(f"GOOGLE_API_KEY_{index}", raising=False)

    monkeypatch.setattr(ai_agent, "call_gemini_async", fake_gemini)
    monkeypatch.setattr(
        ai_agent,
        "_provider_order",
        lambda: ["gemini", "groq"],
    )

    parsed, provider = await ai_agent._run_provider_chain(
        "prompt",
        "system",
        "en",
    )

    assert calls == ["key-1", "key-2"]
    assert provider == "Google Gemini"
    assert parsed is not None
    assert parsed["analysis"][0]["service"] == "Example"


def test_default_provider_order_keeps_ollama_as_last_fallback(monkeypatch) -> None:
    monkeypatch.delenv("LLM_LOCAL_ONLY", raising=False)
    monkeypatch.delenv("LLM_PROVIDER_ORDER", raising=False)
    assert ai_agent._provider_order() == ["gemini", "groq", "openai", "ollama"]


def test_provider_order_configuration_is_deterministic(monkeypatch) -> None:
    monkeypatch.delenv("LLM_LOCAL_ONLY", raising=False)
    monkeypatch.setenv("LLM_PROVIDER_ORDER", " groq,invalid,gemini,groq,ollama ")
    assert ai_agent._provider_order() == ["groq", "gemini", "ollama"]


def test_local_only_overrides_provider_order(monkeypatch) -> None:
    monkeypatch.setenv("LLM_LOCAL_ONLY", "true")
    monkeypatch.setenv("LLM_PROVIDER_ORDER", "groq,gemini")
    assert ai_agent._provider_order() == ["ollama"]


@pytest.mark.asyncio
async def test_provider_chain_exhaustion_returns_explicit_none(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_groq(*args, **kwargs):
        calls.append("groq")
        raise RuntimeError("groq unavailable")

    async def fake_openai(*args, **kwargs):
        calls.append("openai")
        return ""

    async def fake_ollama(*args, **kwargs):
        calls.append("ollama")
        raise ValueError("ollama invalid output")

    monkeypatch.setenv("GROQ_API_KEY", "groq-key")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setattr(ai_agent, "call_groq_async", fake_groq)
    monkeypatch.setattr(ai_agent, "call_openai_async", fake_openai)
    monkeypatch.setattr(ai_agent, "call_ollama_async", fake_ollama)
    monkeypatch.setattr(ai_agent, "_provider_order", lambda: ["groq", "openai", "ollama"])

    parsed, provider = await ai_agent._run_provider_chain("prompt", "system", "en")

    assert calls == ["groq", "openai", "ollama"]
    assert parsed is None
    assert provider == "None"


@pytest.mark.asyncio
async def test_analyze_smart_cache_all_provider_failure_uses_uncached_fallback(monkeypatch) -> None:
    services = [
        {"name": "Example Shop", "domain": "example.com", "subject": "Welcome to Example Shop"}
    ]
    scan_status = {"breach_scan_complete": True, "failed_engines": []}
    saved: list[dict] = []

    async def fake_chain(*args, **kwargs):
        return None, "None"

    def fake_save(*args, **kwargs):
        saved.append(kwargs)

    monkeypatch.setenv("PII_PEPPER_KEY", "x" * 32)
    monkeypatch.setattr(ai_agent, "_run_provider_chain", fake_chain)
    monkeypatch.setattr(ai_agent, "load_analysis_cache_ext", lambda *args, **kwargs: None)
    monkeypatch.setattr(ai_agent, "save_analysis_cache_ext", fake_save)
    monkeypatch.setattr(ai_agent, "load_local_dsr_template", lambda *args, **kwargs: "")

    result = await ai_agent.analyze_smart_cache(
        "example@example.com",
        services,
        force_refresh=True,
        lang="en",
        scan_status=scan_status,
    )

    assert result["provider_used"] == "Local Rule-based Engine (Offline Fallback)"
    assert result["is_from_cache"] is False
    assert result["analysis"][0]["risk_key"] == "unknown"
    assert saved == []


@pytest.mark.asyncio
async def test_background_cache_write_does_not_overwrite_newer_result(monkeypatch) -> None:
    services = [
        {
            "name": "Example Shop",
            "domain": "example.com",
            "subject": "Order confirmation",
        }
    ]
    saved: list[dict] = []
    def fake_time() -> float:
        # The test controls generation ordering, not the number of internal
        # time.time() calls made by the production path or its dependencies.
        return 200.0 if not saved else 100.0

    class ImmediateThread:
        def __init__(self, target, **kwargs):
            self.target = target

        def start(self) -> None:
            self.target()

    async def fake_chain(*args, **kwargs):
        return (
            {
                "analysis": [
                    {
                        "service": "Example Shop",
                        "risk_level": "medium",
                        "reason": "Order evidence.",
                        "delete_url": "",
                    }
                ]
            },
            "Groq Cloud",
        )

    def fake_load_encrypted_json(*args, **kwargs):
        return saved[-1] if saved else None

    def fake_save(*args, **kwargs):
        # save_analysis_cache_ext receives the cache payload positionally.
        payload = args[1] if len(args) > 1 else kwargs.get("data", {})
        saved.append(dict(payload))

    monkeypatch.setenv("PII_PEPPER_KEY", "x" * 32)
    monkeypatch.setattr(ai_agent, "_run_provider_chain", fake_chain)
    monkeypatch.setattr(ai_agent, "load_analysis_cache_ext", lambda *args, **kwargs: None)
    monkeypatch.setattr(ai_agent, "load_local_dsr_template", lambda *args, **kwargs: "")
    monkeypatch.setattr(ai_agent, "get_cache_filepath_ext", lambda *args, **kwargs: "ignored")
    monkeypatch.setattr(ai_agent, "load_encrypted_json", fake_load_encrypted_json)
    monkeypatch.setattr(ai_agent, "save_analysis_cache_ext", fake_save)
    monkeypatch.setattr(ai_agent.time, "time", fake_time)
    monkeypatch.setattr(ai_agent.threading, "Thread", ImmediateThread)

    first = await ai_agent.analyze_smart_cache(
        "example@example.com",
        services,
        force_refresh=True,
        lang="en",
    )
    second = await ai_agent.analyze_smart_cache(
        "example@example.com",
        services,
        force_refresh=True,
        lang="en",
    )

    assert first["provider_used"] == "Groq Cloud"
    assert second["provider_used"] == "Groq Cloud"
    assert len(saved) == 1
    assert saved[0][ai_agent.CACHE_GENERATION_FIELD] == 200.0
