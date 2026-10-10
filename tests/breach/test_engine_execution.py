import asyncio

import pytest
import services.breach_scanner as breach_scanner
from services.breach_scanner import (
    run_engine_queue_v2,
)
from services.breach.models import (
    EngineStatus,
)


def test_engine_queue_execution():

    async def runner():

        async def fake_engine():
            return [
                {
                    "title": "test",
                    "url": "https://example.com",
                }
            ]


        plan = [
            (
                "engine1",
                fake_engine,
            )
        ]


        results = await run_engine_queue_v2(
            plan
        )


        assert len(results) == 1

        result = results[0]

        assert result.engine == "engine1"

        assert result.status == EngineStatus.SUCCESS

        assert len(result.findings) == 1


    asyncio.run(runner())

@pytest.mark.asyncio
async def test_engine_queue_clamps_zero_workers_instead_of_hanging(monkeypatch):
    monkeypatch.setattr(breach_scanner, "BREACH_QUEUE_WORKERS", 0)

    async def fake_engine():
        return []

    results = await asyncio.wait_for(
        breach_scanner.run_engine_queue_v2([("engine-zero-worker-test", fake_engine)]),
        timeout=1.0,
    )

    assert len(results) == 1
    assert results[0].engine == "engine-zero-worker-test"
    assert results[0].status == EngineStatus.SUCCESS


@pytest.mark.asyncio
async def test_circuit_open_job_is_not_counted_as_started(monkeypatch):
    called = False

    async def fake_engine():
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(breach_scanner.ENGINE_CIRCUITS, "allow", lambda _name: False)

    results = await breach_scanner.run_engine_queue_v2(
        [("engine-circuit-open-metrics-test", fake_engine)]
    )

    assert len(results) == 1
    assert results[0].status == EngineStatus.CIRCUIT_OPEN
    assert results[0].metadata.get("execution_started", False) is False
    assert called is False


@pytest.mark.asyncio
async def test_execution_started_is_recorded_when_engine_await_begins(monkeypatch):
    async def fake_engine():
        return []

    monkeypatch.setattr(breach_scanner.ENGINE_CIRCUITS, "allow", lambda _name: True)
    monkeypatch.setattr(breach_scanner.ENGINE_LIMITERS, "allow", lambda _name: True)

    results = await breach_scanner.run_engine_queue_v2(
        [("engine-started-metrics-test", fake_engine)]
    )

    assert len(results) == 1
    assert results[0].status == EngineStatus.SUCCESS
    assert results[0].metadata["execution_started"] is True
