from __future__ import annotations

import httpx
import pytest

from services.enrichment.evidence.url_verifier import verify_public_url


class MockTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "text/html",
                "server": "test",
            },
            content=b"<html><head><title>Example page</title></head></html>",
            request=request,
        )


@pytest.mark.asyncio
async def test_verify_public_url_uses_existing_url_without_following_redirects() -> None:
    client = httpx.AsyncClient(transport=MockTransport(), follow_redirects=False)

    try:
        result = await verify_public_url(
            "https://example.com/public",
            client=client,
            fetch_title=True,
        )
    finally:
        await client.aclose()

    assert result.reachable is True
    assert result.status_code == 200
    assert result.content_type == "text/html"
    assert result.title == "Example page"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8501/",
        "http://localhost/",
        "http://10.0.0.1/",
        "ftp://example.com/file",
        "https://user:password@example.com/",
    ],
)
async def test_verify_public_url_rejects_unsafe_targets(url: str) -> None:
    with pytest.raises(ValueError):
        await verify_public_url(url)
