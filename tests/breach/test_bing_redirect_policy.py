from __future__ import annotations

import httpx
import pytest

import services.breach_scanner as breach_scanner


@pytest.mark.asyncio
async def test_bing_scraper_does_not_follow_untrusted_redirects(monkeypatch):
    observed = {}

    async def fake_request_text_limited(client, method, url, **kwargs):
        observed.update(kwargs)
        return 200, "<html></html>"

    monkeypatch.setattr(
        breach_scanner,
        "_request_text_limited",
        fake_request_text_limited,
    )

    async with httpx.AsyncClient(follow_redirects=False) as client:
        findings = await breach_scanner.scan_bing_scrape_async(
            client,
            "target@example.com",
        )

    assert findings == []
    assert observed["follow_redirects"] is False
