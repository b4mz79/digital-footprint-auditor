from __future__ import annotations

import httpx
import pytest

from services.enrichment.evidence import url_verifier

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


@pytest.mark.parametrize("resolved", [[], None])
def test_verify_public_url_rejects_unresolvable_hostname(monkeypatch, resolved) -> None:
    def fake_getaddrinfo(*args, **kwargs):
        if resolved is None:
            raise OSError("synthetic DNS failure")
        return resolved

    monkeypatch.setattr(url_verifier.socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError, match="hostname is not public"):
        url_verifier._validate_url("https://unresolvable.example/report")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("head_status", "fetch_title", "expected_methods"),
    [
        (302, False, ["HEAD"]),
        (200, True, ["HEAD", "GET"]),
        (405, False, ["HEAD", "GET"]),
    ],
)
async def test_verifier_never_follows_redirects_from_injected_client(
    monkeypatch: pytest.MonkeyPatch,
    head_status: int,
    fetch_title: bool,
    expected_methods: list[str],
) -> None:
    url = "https://public.example/report"
    private_redirect = "http://127.0.0.1/admin"
    requests: list[httpx.Request] = []

    # Keep this test deterministic and independent of live DNS.
    monkeypatch.setattr(
        "services.enrichment.evidence.url_verifier._is_public_hostname",
        lambda hostname: True,
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "HEAD":
            headers = {"location": private_redirect} if head_status == 302 else {}
            return httpx.Response(head_status, headers=headers, request=request)

        return httpx.Response(
            302,
            headers={"location": private_redirect},
            request=request,
        )

    # Deliberately use a client configured to follow redirects. The verifier
    # must enforce its own security policy on each request.
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    ) as client:
        result = await verify_public_url(
            url,
            client=client,
            fetch_title=fetch_title,
        )

    assert [request.method for request in requests] == expected_methods
    assert all(str(request.url) == url for request in requests)
    if head_status == 200:
        # The HEAD result remains the reachability result; the optional title
        # GET must still stop at its redirect instead of reaching the target.
        assert result.status_code == 200
        assert result.redirected is False
        assert result.title == ""
    else:
        assert result.status_code == 302
        assert result.redirected is True
        assert result.location == private_redirect
    assert result.final_url == url
