import asyncio

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