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
