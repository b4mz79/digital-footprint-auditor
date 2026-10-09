import pytest

from services.breach.models import (
    EngineResult,
    EngineStatus,
)


def test_partial_engine_failure_does_not_mark_complete():

    """
    Simulasi:
    - BreachDirectory gagal (429)
    - Bing berhasil
    - Tavily berhasil

    Expected:
    - hasil scan tetap membawa engine sehat
    - complete harus False
    """


    engine_results = [
        EngineResult(
            engine="BreachDirectory",
            status=EngineStatus.RATE_LIMITED,
            error="HTTP 429",
        ),

        EngineResult(
            engine="Bing Scraper",
            status=EngineStatus.SUCCESS,
            findings=[
                {
                    "title": "Exposure Finding",
                    "url": "https://example.com/result",
                    "snippet": "test",
                }
            ],
        ),

        EngineResult(
            engine="Tavily",
            status=EngineStatus.SUCCESS,
            findings=[],
        ),
    ]


    engines_report = {}

    for result in engine_results:

        if result.status == EngineStatus.SUCCESS:
            engines_report[result.engine] = {
                "status": "ok"
            }

        elif result.status == EngineStatus.RATE_LIMITED:
            engines_report[result.engine] = {
                "status": "error"
            }


    complete = all(
        item["status"] == "ok"
        for item in engines_report.values()
    )


    assert engines_report["BreachDirectory"]["status"] == "error"

    assert engines_report["Bing Scraper"]["status"] == "ok"

    assert complete is False



def test_successful_engine_results_are_preserved():

    """
    Engine sehat tetap menghasilkan finding
    walaupun engine lain gagal.
    """


    result = EngineResult(
        engine="Bing Scraper",
        status=EngineStatus.SUCCESS,
        findings=[
            {
                "source": "Bing Search",
                "url": "https://example.com",
            }
        ],
    )


    assert result.status == EngineStatus.SUCCESS

    assert len(result.findings) == 1



def test_rate_limited_engine_is_not_clean_result():

    """
    Memastikan:
    RATE_LIMITED != tidak ada breach.
    """


    result = EngineResult(
        engine="BreachDirectory",
        status=EngineStatus.RATE_LIMITED,
    )


    assert result.status != EngineStatus.SUCCESS

    assert result.findings == []

def test_cached_success_with_no_findings_is_distinct_from_cache_miss():
    from services.breach_scanner import _cached_engine_findings

    cache = {"user@example.com": {"Bing Scraper": []}}

    found, findings = _cached_engine_findings(cache, "user@example.com", "Bing Scraper")

    assert found is True
    assert findings == []


def test_missing_engine_result_remains_a_cache_miss_for_retry():
    from services.breach_scanner import _cached_engine_findings

    cache = {"user@example.com": {"Bing Scraper": []}}

    found, findings = _cached_engine_findings(cache, "user@example.com", "BreachDirectory")

    assert found is False
    assert findings == []


def test_successful_engine_findings_are_stored_per_target_and_engine():
    from services.breach_scanner import _store_engine_findings

    cache = {}
    finding = {"title": "Exposure", "url": "https://example.com/result"}

    _store_engine_findings(cache, "user@example.com", "Bing Scraper", [finding])
    _store_engine_findings(cache, "user@example.com", "Tavily", [])

    assert cache == {
        "user@example.com": {
            "Bing Scraper": [finding],
            "Tavily": [],
        }
    }

