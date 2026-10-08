"""Minimal public-URL verification for already discovered evidence.

This verifier is deliberately conservative: it verifies an existing public URL,
does not perform crawling, does not follow redirects automatically, and blocks
obvious private/local destinations to reduce SSRF risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit

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


def _is_public_hostname(hostname: str) -> bool:
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return False

    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                host,
                None,
                type=socket.SOCK_STREAM,
            )
        }
    except OSError:
        # DNS failure is not evidence that a hostname is public. Fail closed
        # rather than allowing an unresolvable name through the SSRF guard.
        return False

    if not addresses:
        return False

    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
    return True


def _validate_url(url: str) -> str:
    value = (url or "").strip()
    if not value or len(value) > 4096:
        raise ValueError("URL is empty or too long.")

    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only public HTTP(S) URLs are supported.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing credentials are not supported.")
    if not _is_public_hostname(parsed.hostname):
        raise ValueError("URL hostname is not public.")
    return value


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
    """Verify reachability without following redirects automatically."""
    value = _validate_url(url)
    owns_client = client is None
    http = client or httpx.AsyncClient(
        follow_redirects=False,
        headers={"User-Agent": "PrivacyAuditor/EvidenceVerifier"},
    )

    try:
        try:
            response = await http.head(value, timeout=timeout_seconds)
            if response.status_code in {405, 501}:
                response = await http.get(value, timeout=timeout_seconds)
        except httpx.HTTPError as exc:
            return URLVerification(
                url=value,
                reachable=False,
                status_code=None,
                final_url=value,
                content_type="",
                redirected=False,
                location=None,
                title="",
                error=type(exc).__name__,
            )

        location = response.headers.get("location")
        content_type = response.headers.get("content-type", "")
        title = ""

        if fetch_title and response.request.method == "HEAD":
            try:
                get_response = await http.get(value, timeout=timeout_seconds)
                if get_response.status_code < 500:
                    title = _extract_title(get_response.content)
            except httpx.HTTPError:
                pass

        return URLVerification(
            url=value,
            reachable=True,
            status_code=response.status_code,
            final_url=str(response.url),
            content_type=content_type,
            redirected=bool(location),
            location=location,
            title=title,
            metadata={
                "method": response.request.method,
                "server": response.headers.get("server", ""),
            },
        )
    finally:
        if owns_client:
            await http.aclose()
