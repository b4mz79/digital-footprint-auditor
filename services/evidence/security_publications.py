"""Public security-publication enrichment.

The provider only accepts a normalized domain. No email address or phone
number is sent to the external search provider by this module.

Firecrawl's Search API is used only as an optional enrichment source. Search
results are recorded as contextual evidence, never as proof that the audited
subject was compromised.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import os
import re
from typing import Any, Iterable
from urllib.parse import urlsplit
import time

import httpx

from services.evidence.models import (
    EvidenceDirectness,
    EvidenceRecord,
    EvidenceRelation,
    make_evidence_id,
)
from utils.domains import root_domain
from utils.logging_setup import get_logger
from utils.paths import resolve_data_path
from utils.privacy import clean_web_snippet, clean_web_title

logger = get_logger("FirecrawlEvidence")


FIRECRAWL_SEARCH_URL = "https://api.firecrawl.dev/v2/search"
DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_MAX_RESULTS = 5
DEFAULT_MAX_CONCURRENCY = 2
DEFAULT_REQUESTS_PER_MINUTE = 10
DEFAULT_COOLDOWN_SECONDS = 60.0
MAX_RESPONSE_BYTES = 1_000_000
MAX_TITLE_LENGTH = 512
MAX_SUMMARY_LENGTH = 2_000
CONTEXTUAL_FILTER_BEFORE_FILE = "contextual_filter_before.json"
CONTEXTUAL_FILTER_AFTER_FILE = "contextual_filter_after.json"
CONTEXTUAL_FILTER_DUMP_SCHEMA_VERSION = "contextual-filter-dump-v1"

SECURITY_QUERY_TERMS = (
    "security",
    "phishing",
    "malware",
    "ransomware",
    "breach",
    "incident",
    "vulnerability",
    "exploit",
    "campaign",
    "IOC",
)

# These are public editorial/research surfaces rather than reputation verdicts.
DEFAULT_SECURITY_PUBLISHERS = (
    ("Kaspersky Securelist", "securelist.com"),
    ("ESET Research", "welivesecurity.com"),
    ("Microsoft Security", "microsoft.com"),
    ("Palo Alto Networks Unit 42", "unit42.paloaltonetworks.com"),
)


class SecurityPublicationError(RuntimeError):
    """The security-publication enrichment source could not be queried."""


class SecurityPublicationRateLimited(SecurityPublicationError):
    """The provider is rate-limited and must pause before new requests."""


@dataclass(frozen=True, slots=True)
class SecurityPublisher:
    name: str
    domain: str


class _RequestRateGate:
    """Space outbound requests so the provider stays within a configured RPM."""

    def __init__(self, requests_per_minute: int) -> None:
        self.requests_per_minute = max(1, int(requests_per_minute))
        self.interval_seconds = 60.0 / self.requests_per_minute
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = self._next_allowed - now
            if delay > 0:
                await asyncio.sleep(delay)
                now = time.monotonic()
            self._next_allowed = max(now, self._next_allowed) + self.interval_seconds


def _is_private_ip(hostname: str) -> bool:
    try:
        return ipaddress.ip_address(hostname).is_private or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def normalize_domain(value: str) -> str:
    """Normalize a domain or URL and reject values carrying target identifiers."""
    value = (value or "").strip()
    if not value or len(value) > 253:
        raise ValueError("Domain is empty or too long.")

    # This module must never become a PII search path.
    if "@" in value or re.search(r"\+?\d[\d\s().-]{6,}", value):
        raise ValueError("Security-publication lookup accepts domain-only input.")

    candidate = value if "://" in value else f"https://{value}"
    parsed = urlsplit(candidate)
    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname or _is_private_ip(hostname):
        raise ValueError("Domain is invalid or resolves to an IP literal that is not suitable.")

    try:
        hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domain contains invalid hostname characters.") from exc

    if any(ch.isspace() for ch in hostname):
        raise ValueError("Domain contains whitespace.")

    return root_domain(hostname)


def _safe_url(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw or len(raw) > 4096:
        return ""
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    if _is_private_ip(parsed.hostname):
        return ""
    return raw


def _publisher_matches(url: str, publisher: SecurityPublisher) -> bool:
    safe = _safe_url(url)
    if not safe:
        return False
    try:
        host = (urlsplit(safe).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    expected = publisher.domain.lower().lstrip(".")
    return host == expected or host.endswith("." + expected)


def _build_query(domain: str) -> str:
    terms = " OR ".join(SECURITY_QUERY_TERMS)
    return f'"{domain}" ({terms})'


def _contextual_relevance(
    domain: str,
    *,
    url: str,
    title: str,
    summary: str,
) -> bool:
    """Accept only results with both target-domain and security-context signals."""
    domain_pattern = re.compile(rf"(?<![a-z0-9-]){re.escape(domain)}(?![a-z0-9-])")
    security_pattern = re.compile(
        r"(?<![a-z0-9])(?:"
        + "|".join(re.escape(term.casefold()) for term in SECURITY_QUERY_TERMS)
        + r")(?![a-z0-9])"
    )
    searchable = " ".join((url, title, summary)).casefold()
    return bool(domain_pattern.search(searchable) and security_pattern.search(searchable))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FirecrawlSecurityPublicationProvider:
    """Search trusted public security-research publishers for domain context."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_results: int = DEFAULT_MAX_RESULTS,
        client: httpx.AsyncClient | None = None,
        publishers: Iterable[tuple[str, str]] = DEFAULT_SECURITY_PUBLISHERS,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        requests_per_minute: int = DEFAULT_REQUESTS_PER_MINUTE,
        cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS,
    ) -> None:
        # None means "use configured environment"; an explicit empty string
        # means "disabled". This keeps dependency injection deterministic and
        # prevents a caller from accidentally re-enabling the provider.
        configured_key = (
            os.getenv("FIRECRAWL_API_KEY", "")
            if api_key is None
            else api_key
        )
        self.api_key = str(configured_key or "").strip()
        self.timeout_seconds = float(timeout_seconds)
        self.max_results = max(1, min(int(max_results), 10))
        self._client = client
        self.max_concurrency = max(1, min(int(max_concurrency), 16))
        self.cooldown_seconds = max(1.0, float(cooldown_seconds))
        self.requests_per_minute = max(1, int(requests_per_minute))
        self._request_gate = asyncio.Semaphore(self.max_concurrency)
        self._request_rate_gate = _RequestRateGate(self.requests_per_minute)
        self._cooldown_until = 0.0
        self._cooldown_lock = asyncio.Lock()
        self._filter_dump_lock = asyncio.Lock()
        self._filter_dump_dir = resolve_data_path(
            os.getenv("EVIDENCE_CONTEXTUAL_FILTER_DUMP_DIR"),
            "cache/evidence",
        )
        self._filter_candidates: list[dict[str, Any]] = []
        self._filter_accepted: list[dict[str, Any]] = []
        self._reset_filter_dumps()
        self.publishers = tuple(
            SecurityPublisher(name=name, domain=domain)
            for name, domain in publishers
        )
        logger.debug(
            "[Firecrawl] Provider initialized; enabled=%s publishers=%d max_results=%d timeout=%.1fs",
            self.enabled,
            len(self.publishers),
            self.max_results,
            self.timeout_seconds,
        )

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    @property
    def cooldown_active(self) -> bool:
        """Return whether the provider-wide cooldown is currently active."""
        return self._cooldown_until > time.monotonic()

    async def _check_cooldown(self) -> None:
        remaining = self._cooldown_until - time.monotonic()
        if remaining > 0:
            raise SecurityPublicationRateLimited(f"Firecrawl cooldown active for {remaining:.1f}s")

    async def _set_cooldown(self) -> None:
        async with self._cooldown_lock:
            self._cooldown_until = max(self._cooldown_until, time.monotonic() + self.cooldown_seconds)

    @staticmethod
    def _dump_item(
        *,
        domain: str,
        publisher: SecurityPublisher,
        url: str,
        title: str,
        summary: str,
        published_at: Any,
    ) -> dict[str, Any]:
        return {
            "domain": domain,
            "publisher": publisher.name,
            "publisher_domain": publisher.domain,
            "url": url,
            "title": title,
            "summary": summary,
            "published_at": None if published_at is None else str(published_at)[:64],
        }

    def _reset_filter_dumps(self) -> None:
        try:
            self._filter_dump_dir.mkdir(parents=True, exist_ok=True)
            for filename in (
                CONTEXTUAL_FILTER_BEFORE_FILE,
                CONTEXTUAL_FILTER_AFTER_FILE,
            ):
                (self._filter_dump_dir / filename).write_text(
                    json.dumps(
                        {
                            "schema_version": CONTEXTUAL_FILTER_DUMP_SCHEMA_VERSION,
                            "filter": "security_publication_context_v1",
                            "generated_at": _utc_now(),
                            "records": [],
                        },
                        ensure_ascii=False,
                        indent=2,
                    ) + "\n",
                    encoding="utf-8",
                )
        except OSError as exc:
            logger.warning("[Firecrawl] Could not initialize contextual filter dumps: %s", exc)

    async def _record_filter_dump(
        self,
        *,
        candidate: dict[str, Any],
        accepted: bool,
    ) -> None:
        async with self._filter_dump_lock:
            self._filter_candidates.append(candidate)
            if accepted:
                self._filter_accepted.append(candidate)
            try:
                self._filter_dump_dir.mkdir(parents=True, exist_ok=True)
                for filename, records in (
                    (CONTEXTUAL_FILTER_BEFORE_FILE, self._filter_candidates),
                    (CONTEXTUAL_FILTER_AFTER_FILE, self._filter_accepted),
                ):
                    (self._filter_dump_dir / filename).write_text(
                        json.dumps(
                            {
                                "schema_version": CONTEXTUAL_FILTER_DUMP_SCHEMA_VERSION,
                                "filter": "security_publication_context_v1",
                                "generated_at": _utc_now(),
                                "records": records,
                            },
                            ensure_ascii=False,
                            indent=2,
                        ) + "\n",
                        encoding="utf-8",
                    )
            except (OSError, TypeError, ValueError) as exc:
                logger.warning("[Firecrawl] Could not write contextual filter dumps: %s", exc)

    async def _search_publisher(
        self,
        domain: str,
        publisher: SecurityPublisher,
        client: httpx.AsyncClient,
    ) -> list[EvidenceRecord]:
        payload = {
            "query": _build_query(domain),
            "limit": self.max_results,
            "sources": ["web"],
            "includeDomains": [publisher.domain],
            "safe": True,
            "highlights": True,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        logger.info(
            "[Firecrawl] Searching publisher=%s domain=%s",
            publisher.name,
            domain,
        )
        await self._check_cooldown()
        try:
            async with self._request_gate:
                await self._check_cooldown()
                await self._request_rate_gate.wait()
                await self._check_cooldown()
                response = await client.post(
                    FIRECRAWL_SEARCH_URL,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout_seconds,
                )
        except httpx.HTTPError as exc:
            logger.warning(
                "[Firecrawl] Request failed publisher=%s domain=%s error=%s",
                publisher.name,
                domain,
                type(exc).__name__,
            )
            raise SecurityPublicationError(
                f"{publisher.name}: {type(exc).__name__}"
            ) from exc

        if response.content and len(response.content) > MAX_RESPONSE_BYTES:
            raise SecurityPublicationError(f"{publisher.name}: response too large.")

        if response.status_code == 429:
            await self._set_cooldown()
            logger.warning(
                "[Firecrawl] Rate limited publisher=%s domain=%s cooldown=%.1fs",
                publisher.name,
                domain,
                self.cooldown_seconds,
            )
            raise SecurityPublicationRateLimited(f"{publisher.name}: HTTP 429")

        if response.status_code >= 400:
            logger.warning(
                "[Firecrawl] HTTP failure publisher=%s domain=%s status=%d",
                publisher.name,
                domain,
                response.status_code,
            )
            raise SecurityPublicationError(
                f"{publisher.name}: HTTP {response.status_code}"
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise SecurityPublicationError(
                f"{publisher.name}: invalid JSON response"
            ) from exc

        if not isinstance(body, dict) or not body.get("success", False):
            message = str(body.get("error", "unsuccessful response")) if isinstance(body, dict) else "unsuccessful response"
            raise SecurityPublicationError(f"{publisher.name}: {message[:200]}")

        data = body.get("data", {})
        items = data.get("web", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            raise SecurityPublicationError(f"{publisher.name}: invalid result shape.")

        evidence: list[EvidenceRecord] = []
        observed_at = _utc_now()
        logger.info(
            "[Firecrawl] Response received publisher=%s domain=%s candidates=%d",
            publisher.name,
            domain,
            len(items),
        )

        for item in items[: self.max_results]:
            if not isinstance(item, dict):
                continue

            url = _safe_url(item.get("url"))
            if not url or not _publisher_matches(url, publisher):
                continue

            title = clean_web_title(
                item.get("title") or "",
                max_length=MAX_TITLE_LENGTH,
            )
            description = clean_web_snippet(
                item.get("description") or "",
                max_length=MAX_SUMMARY_LENGTH,
            )

            metadata = item.get("metadata")
            metadata = metadata if isinstance(metadata, dict) else {}
            published_at = metadata.get("publishedTime") or metadata.get("published_time")

            candidate_dump = self._dump_item(
                domain=domain,
                publisher=publisher,
                url=url,
                title=title,
                summary=description,
                published_at=published_at,
            )
            accepted = _contextual_relevance(
                domain,
                url=url,
                title=title,
                summary=description,
            )
            await self._record_filter_dump(
                candidate=candidate_dump,
                accepted=accepted,
            )

            if not accepted:
                continue

            evidence_id = make_evidence_id(
                source=publisher.name,
                source_type="security_publication",
                domain=domain,
                url=url,
                title=title,
            )

            evidence.append(
                EvidenceRecord(
                    evidence_id=evidence_id,
                    source=publisher.name,
                    source_type="security_publication",
                    relation=EvidenceRelation.SECURITY_PUBLICATION,
                    directness=EvidenceDirectness.CONTEXTUAL,
                    confidence=0.65,
                    observed_at=observed_at,
                    published_at=published_at,
                    domain=domain,
                    url=url,
                    title=title or f"Security publication mentioning {domain}",
                    summary=description,
                    provenance={
                        "provider": "firecrawl_search",
                        "publisher_domain": publisher.domain,
                        "query_scope": "domain_only",
                        "relevance_filter": "security_publication_context_v1",
                    },
                    metadata={
                        "status": "contextual_accepted",
                        "credits_used": body.get("creditsUsed"),
                    },
                )
            )

        logger.info(
            "[Firecrawl] Publisher completed publisher=%s domain=%s accepted=%d",
            publisher.name,
            domain,
            len(evidence),
        )
        return evidence

    async def search_domain(self, domain: str) -> list[EvidenceRecord]:
        """Search all configured publishers concurrently for one domain."""
        normalized = normalize_domain(domain)
        if not self.enabled:
            logger.info("[Firecrawl] Disabled; domain=%s skipped.", normalized)
            return []

        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(
            follow_redirects=False,
            headers={"User-Agent": "PrivacyAuditor/Evidence"},
        )

        try:
            results = await asyncio.gather(
                *(
                    self._search_publisher(normalized, publisher, client)
                    for publisher in self.publishers
                ),
                return_exceptions=True,
            )
        finally:
            if owns_client:
                await client.aclose()

        evidence: list[EvidenceRecord] = []
        failed = 0
        rate_limited = 0
        for result in results:
            if isinstance(result, SecurityPublicationRateLimited):
                rate_limited += 1
                logger.warning("[Firecrawl] Publisher rate limited: %s", result)
                continue
            if isinstance(result, SecurityPublicationError):
                failed += 1
                logger.warning("[Firecrawl] Publisher enrichment failed: %s", result)
                continue
            if isinstance(result, Exception):
                failed += 1
                logger.warning(
                    "[Firecrawl] Publisher enrichment failed: %s",
                    type(result).__name__,
                )
                continue
            evidence.extend(result)

        # Deduplicate by evidence id while retaining publisher provenance.
        unique: dict[str, EvidenceRecord] = {}
        for item in evidence:
            unique[item.evidence_id] = item
        output = list(unique.values())
        logger.info(
            "[Firecrawl] Domain completed domain=%s accepted=%d failed_publishers=%d rate_limited=%d",
            normalized,
            len(output),
            failed,
            rate_limited,
        )
        return output
