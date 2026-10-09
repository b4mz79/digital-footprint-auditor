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
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "https://example.com:99999/",
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
        (302, True, ["HEAD"]),
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



class TrackingStream(httpx.AsyncByteStream):
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.bytes_yielded = 0
        self.closed = False

    async def __aiter__(self):
        for offset in range(0, len(self.payload), 1024):
            chunk = self.payload[offset : offset + 1024]
            self.bytes_yielded += len(chunk)
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_fallback_get_does_not_buffer_body_and_closes_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        url_verifier,
        "_resolve_public_addresses",
        lambda hostname, port=None: [PUBLIC_IP],
    )
    streams: dict[str, TrackingStream] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        stream = TrackingStream(b"x" * 200_000)
        streams[request.method] = stream
        status = 405 if request.method == "HEAD" else 200
        return httpx.Response(status, stream=stream, request=request)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    ) as client:
        result = await verify_public_url(
            "https://public.example/report",
            client=client,
        )

    assert result.reachable is True
    assert result.status_code == 200
    assert streams["HEAD"].closed is True
    assert streams["GET"].closed is True
    # The fallback GET is used for headers/status only; its body is never read.
    assert streams["GET"].bytes_yielded == 0


@pytest.mark.asyncio
async def test_title_fetch_reads_only_bounded_body_and_closes_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        url_verifier,
        "_resolve_public_addresses",
        lambda hostname, port=None: [PUBLIC_IP],
    )
    streams: dict[str, TrackingStream] = {}
    extracted_lengths: list[int] = []
    original_extract_title = url_verifier._extract_title

    def inspect_extract_title(content: bytes) -> str:
        extracted_lengths.append(len(content))
        return original_extract_title(content)

    monkeypatch.setattr(url_verifier, "_extract_title", inspect_extract_title)
    payload = b"<html><head><title>Bounded</title></head><body>" + b"x" * 200_000

    async def handler(request: httpx.Request) -> httpx.Response:
        stream = TrackingStream(b"" if request.method == "HEAD" else payload)
        streams[request.method] = stream
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            stream=stream,
            request=request,
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    ) as client:
        result = await verify_public_url(
            "https://public.example/report",
            client=client,
            fetch_title=True,
        )

    assert result.title == "Bounded"
    assert extracted_lengths and extracted_lengths[0] <= url_verifier.MAX_TITLE_BYTES
    assert streams["HEAD"].closed is True
    assert streams["GET"].closed is True
    # Streaming may read at most one additional 8 KiB chunk before truncation;
    # it must never consume the entire 200 KiB response.
    assert streams["GET"].bytes_yielded <= url_verifier.MAX_TITLE_BYTES + 8192
