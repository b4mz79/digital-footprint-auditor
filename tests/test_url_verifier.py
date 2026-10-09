from __future__ import annotations

import socket

import httpx
import pytest

from services.enrichment.evidence import url_verifier
from services.enrichment.evidence.url_verifier import verify_public_url


PUBLIC_IP = "93.184.216.34"


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
async def test_verify_public_url_pins_ip_and_preserves_host_and_tls_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []

    monkeypatch.setattr(
        url_verifier,
        "_resolve_public_addresses",
        lambda hostname, port=None: [PUBLIC_IP],
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "text/html", "server": "test"},
            content=b"<html><head><title>Example page</title></head></html>",
            request=request,
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    ) as client:
        result = await verify_public_url(
            "https://example.com/public",
            client=client,
            fetch_title=True,
        )

    assert result.reachable is True
    assert result.status_code == 200
    assert result.final_url == "https://example.com/public"
    assert result.content_type == "text/html"
    assert result.title == "Example page"
    assert result.metadata["resolved_ip"] == PUBLIC_IP
    assert result.metadata["dns_pinned"] is True
    assert [request.method for request in requests] == ["HEAD", "GET"]
    assert all(str(request.url) == f"https://{PUBLIC_IP}/public" for request in requests)
    assert all(request.headers["host"] == "example.com" for request in requests)
    assert all(request.extensions["sni_hostname"] == "example.com" for request in requests)


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


def test_resolver_rejects_mixed_public_and_private_dns_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        url_verifier.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ],
    )

    with pytest.raises(ValueError, match="hostname is not public"):
        url_verifier._validate_url("https://mixed.example/report")


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
    pinned_url = f"https://{PUBLIC_IP}/report"
    private_redirect = "http://127.0.0.1/admin"
    requests: list[httpx.Request] = []

    # Deterministic public DNS result. HTTP requests must use this IP literal.
    monkeypatch.setattr(
        url_verifier,
        "_resolve_public_addresses",
        lambda hostname, port=None: [PUBLIC_IP],
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
    # must enforce its own per-request policy and pin the destination IP.
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
    assert all(str(request.url) == pinned_url for request in requests)
    assert all(request.headers["host"] == "public.example" for request in requests)
    assert all(request.extensions["sni_hostname"] == "public.example" for request in requests)
    if head_status == 200:
        assert result.status_code == 200
        assert result.redirected is False
        assert result.title == ""
    else:
        assert result.status_code == 302
        assert result.redirected is True
        assert result.location == private_redirect
    assert result.final_url == url
