"""Public-URL verification with DNS-pinned outbound requests.

This verifier checks accessibility only. It is not a source-trust or target-risk
assessment. Requests are pinned to an IP address resolved and validated for the
URL so a second DNS resolution by the HTTP stack cannot redirect the connection
to a private/local destination.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx


DEFAULT_TIMEOUT_SECONDS = 12.0
MAX_TITLE_BYTES = 64_000


@dataclass(slots=True)
class URLVerification:
    url: str
    reachable: bool
    status_code: int | None
    final_url: str
    content_type: str
    redirected: bool
    location: str | None
    title: str
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "final_url": self.final_url,
            "content_type": self.content_type,
            "redirected": self.redirected,
            "location": self.location,
            "title": self.title,
            "error": self.error,
            "metadata": self.metadata,
        }


def _resolve_public_addresses(hostname: str, port: int | None = None) -> list[str]:
    """Resolve a host once and return only a fully public, validated address set."""
    host = (hostname or "").strip().lower().rstrip(".")
    if not host or "%" in host:
        raise ValueError("URL hostname is not public.")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            results = socket.getaddrinfo(
                host,
                port,
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise ValueError("URL hostname is not public.") from exc
        addresses = list(dict.fromkeys(item[4][0] for item in results))
    else:
        addresses = [str(literal)]

    if not addresses:
        raise ValueError("URL hostname is not public.")

    normalized: list[str] = []
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("URL hostname is not public.") from exc
        # Reject the entire answer if even one A/AAAA result is non-public.
        # This avoids accepting mixed public/private DNS answers.
        if not ip.is_global:
            raise ValueError("URL hostname is not public.")
        normalized.append(str(ip))

    return list(dict.fromkeys(normalized))


def _is_public_hostname(hostname: str) -> bool:
    try:
        return bool(_resolve_public_addresses(hostname))
    except (OSError, ValueError):
        return False


def _validated_url_target(
    url: str,
) -> tuple[str, Any, str, str, list[str]]:
    value = (url or "").strip()
    if not value or len(value) > 4096:
        raise ValueError("URL is empty or too long.")

    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only public HTTP(S) URLs are supported.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing credentials are not supported.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL port is invalid.") from exc

    hostname = parsed.hostname.lower().rstrip(".")
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        if "%" in hostname:
            raise ValueError("URL hostname is not public.")
        try:
            tls_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("URL hostname is invalid.") from exc
        host_header = tls_hostname
    else:
        tls_hostname = str(literal)
        host_header = f"[{literal}]" if literal.version == 6 else str(literal)

    if port is not None:
        host_header = f"{host_header}:{port}"

    addresses = _resolve_public_addresses(hostname, port)
    return value, parsed, host_header, tls_hostname, addresses


def _validate_url(url: str) -> str:
    """Validate URL syntax and destination addresses; kept for existing callers/tests."""
    return _validated_url_target(url)[0]


def _pinned_url(parsed: Any, address: str) -> str:
    ip = ipaddress.ip_address(address)
    host = f"[{ip}]" if ip.version == 6 else str(ip)
    port = parsed.port
    if port is not None:
        host = f"{host}:{port}"
    # Fragments are client-side only and must not be sent in the HTTP request.
    return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, ""))


async def _send_pinned_request(
    client: httpx.AsyncClient,
    method: str,
    request_url: str,
    *,
    timeout_seconds: float,
    host_header: str,
    tls_hostname: str,
    scheme: str,
) -> httpx.Response:
    """Send one pinned request as a stream; caller must close the response."""
    extensions: dict[str, Any] = {}
    if scheme == "https":
        # httpcore consumes this extension for TLS SNI and certificate hostname
        # verification while the TCP destination remains the pinned IP literal.
        extensions["sni_hostname"] = tls_hostname

    request = client.build_request(
        method,
        request_url,
        timeout=timeout_seconds,
        headers={"Host": host_header, "Accept-Encoding": "identity"},
        extensions=extensions,
    )
    # Enforce redirect policy on the individual request, even for injected
    # clients configured with follow_redirects=True. Streaming prevents HTTPX
    # from buffering an arbitrary response body before the caller can bound it.
    return await client.send(request, stream=True, follow_redirects=False)


async def _read_limited_body(
    response: httpx.Response,
    *,
    max_bytes: int,
) -> bytes:
    """Read at most max_bytes of raw response bytes."""
    if max_bytes <= 0:
        return b""

    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_raw(chunk_size=8192):
        remaining = max_bytes - total
        if remaining <= 0:
            break
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            total += remaining
            break
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            break
    return b"".join(chunks)


def _extract_title(content: bytes) -> str:
    head = content[:MAX_TITLE_BYTES].decode("utf-8", errors="ignore")
    lower = head.lower()
    start = lower.find("<title")
    if start < 0:
        return ""
    start = head.find(">", start)
    if start < 0:
        return ""
    end = lower.find("</title>", start + 1)
    if end < 0:
        return ""
    return " ".join(head[start + 1 : end].split())[:512]


async def verify_public_url(
    url: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    client: httpx.AsyncClient | None = None,
    fetch_title: bool = False,
) -> URLVerification:
    """Verify URL accessibility using validated IPs; never follow redirects.

    An injected client is caller-controlled infrastructure: its transport must
    honor the pinned IP destination and must not disable TLS certificate checks.
    """
    value, parsed, host_header, tls_hostname, addresses = _validated_url_target(url)
    owns_client = client is None
    http = client or httpx.AsyncClient(
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": "PrivacyAuditor/EvidenceVerifier"},
    )

    last_error: httpx.HTTPError | None = None
    try:
        for address in addresses:
            pinned_url = _pinned_url(parsed, address)
            response: httpx.Response | None = None
            try:
                response = await _send_pinned_request(
                    http,
                    "HEAD",
                    pinned_url,
                    timeout_seconds=timeout_seconds,
                    host_header=host_header,
                    tls_hostname=tls_hostname,
                    scheme=parsed.scheme.lower(),
                )
                if response.status_code in {405, 501}:
                    # The HEAD response is no longer needed. Close it before
                    # opening the fallback GET so connections are not leaked.
                    await response.aclose()
                    response = await _send_pinned_request(
                        http,
                        "GET",
                        pinned_url,
                        timeout_seconds=timeout_seconds,
                        host_header=host_header,
                        tls_hostname=tls_hostname,
                        scheme=parsed.scheme.lower(),
                    )
            except httpx.HTTPError as exc:
                if response is not None:
                    await response.aclose()
                last_error = exc
                continue

            try:
                location = response.headers.get("location")
                content_type = response.headers.get("content-type", "")
                title = ""

                if (
                    fetch_title
                    and response.request.method == "HEAD"
                    and not response.is_redirect
                ):
                    get_response: httpx.Response | None = None
                    try:
                        get_response = await _send_pinned_request(
                            http,
                            "GET",
                            pinned_url,
                            timeout_seconds=timeout_seconds,
                            host_header=host_header,
                            tls_hostname=tls_hostname,
                            scheme=parsed.scheme.lower(),
                        )
                        content_encoding = get_response.headers.get(
                            "content-encoding", ""
                        ).strip().lower()
                        if (
                            get_response.status_code < 500
                            and not get_response.is_redirect
                            and content_encoding in {"", "identity"}
                        ):
                            body = await _read_limited_body(
                                get_response,
                                max_bytes=MAX_TITLE_BYTES,
                            )
                            title = _extract_title(body)
                    except httpx.HTTPError:
                        pass
                    finally:
                        if get_response is not None:
                            await get_response.aclose()

                return URLVerification(
                    url=value,
                    reachable=True,
                    status_code=response.status_code,
                    # The verifier never follows redirects, so the original URL is
                    # the final URL requested regardless of Location's value.
                    final_url=value,
                    content_type=content_type,
                    redirected=bool(location),
                    location=location,
                    title=title,
                    metadata={
                        "method": response.request.method,
                        "server": response.headers.get("server", ""),
                        "resolved_ip": address,
                        "dns_pinned": True,
                    },
                )
            finally:
                await response.aclose()

        return URLVerification(
            url=value,
            reachable=False,
            status_code=None,
            final_url=value,
            content_type="",
            redirected=False,
            location=None,
            title="",
            error=type(last_error).__name__ if last_error else "ConnectionError",
            metadata={"dns_pinned": True},
        )
    finally:
        if owns_client:
            await http.aclose()
