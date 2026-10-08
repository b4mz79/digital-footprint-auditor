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
import hashlib
import ipaddress
import json
import os
import re
from typing import Any, Iterable
from urllib.parse import urlsplit
import time

import httpx

from services.enrichment.evidence.models import (
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
MAX_SUMMARY_LENGTH = 600
CONTEXTUAL_FILTER_DUMP_FILE = "contextual_filter_dump.md"
CONTEXTUAL_FILTER_DUMP_SCHEMA_VERSION = "contextual-filter-dump-v2"
CONTEXTUAL_FILTER_NAME = "security_publication_context_v2"

PAGE_TYPE_REJECT_PATTERNS = (r"/(?:category|categories|author|authors|tag|tags|topic|topics|archive|archives|search)(?:/|$)", r"/page/\d+(?:/|$)", r"(?:^|&)(?:page|paged|offset)=\d+")
PAGE_TITLE_REJECT_PATTERNS = (r"^category(?:\s*[:|]|$)", r"^author(?:\s*[:|]|$)", r"^(?:tag|topic|archive|search)(?:\s*[:|]|$)", r"\bpage\s+\d+\b")
NON_ARTICLE_PATH_PATTERNS = (
    r"/(?:questions?|q|answers?)(?:/|$)",
    r"/(?:store|products?|apps?)(?:/|$)",
    r"/(?:certification|certifications|compliance|catalog|marketplace)(?:/|$)",
)

REFERENCE_TITLE_PATTERNS = (
    r"^(?:browsing|how to|guide to|tips for|understanding|what is|introduction to)\b",
)

PRODUCT_METADATA_TITLE_PATTERNS = (
    r"\bapp certification\b",
    r"^application information\b",
    r"\bapplication information\b",
)

STRONG_SECURITY_TERMS = (
    "phishing", "malware", "ransomware", "breach", "incident",
    "vulnerability", "exploit", "compromised", "attack", "attacked",
    "infected", "stolen", "exposed", "campaign",
    "trojanized", "backdoor", "supply-chain", "supply chain",
    "security certificate", "security certificates", "abused certificate",
    "abused certificates",
)

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


def _response_fingerprint(items: list[Any]) -> str:
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            normalized.append(item)
            continue
        normalized.append({"url": item.get("url"), "title": item.get("title"), "description": item.get("description"), "metadata": item.get("metadata")})
    payload = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _build_query(domain: str) -> str:
    terms = " OR ".join(SECURITY_QUERY_TERMS)
    return f'"{domain}" ({terms})'


def _domain_aliases(domain: str) -> tuple[str, ...]:
    normalized = domain.casefold().strip(".")
    labels = normalized.split(".")
    registrable = labels[-2] if len(labels) >= 2 else normalized
    aliases = {normalized, registrable}
    aliases.update(token for token in re.split(r"[-_]+", registrable) if len(token) >= 3)
    return tuple(sorted(aliases, key=lambda value: (-len(value), value)))

def _contains_term(text: str, terms: Iterable[str]) -> bool:
    folded = text.casefold()
    return any(re.search(rf"(?<![a-z0-9]){re.escape(term.casefold())}(?![a-z0-9])", folded) for term in terms)

def _page_type(url: str, title: str) -> str:
    safe = _safe_url(url)
    parsed = urlsplit(safe) if safe else None
    path = (parsed.path if parsed else "").casefold()
    query = (parsed.query if parsed else "").casefold()
    title_folded = title.casefold().strip()
    for pattern in PAGE_TYPE_REJECT_PATTERNS:
        if re.search(pattern, path) or re.search(pattern, query):
            return "navigation"
    for pattern in PAGE_TITLE_REJECT_PATTERNS:
        if re.search(pattern, title_folded):
            return "navigation"
    for pattern in NON_ARTICLE_PATH_PATTERNS:
        if re.search(pattern, path):
            return "non_article"
    for pattern in PRODUCT_METADATA_TITLE_PATTERNS:
        if re.search(pattern, title_folded):
            return "product_metadata"
    return "article"

def _reference_page(title: str) -> bool:
    title_folded = title.casefold().strip()
    return any(re.search(pattern, title_folded) for pattern in REFERENCE_TITLE_PATTERNS)

def _target_subject_signal(
    domain: str,
    *,
    url: str,
    title: str,
    summary: str,
) -> tuple[bool, str, str]:
    """Determine whether the target is substantively identified by the result."""
    aliases = _domain_aliases(domain)
    if _contains_term(title, aliases):
        return True, "title_alias", "strong"
    if _contains_term(summary, (domain,)):
        return True, "summary_domain", "medium"
    if _contains_term(summary, aliases):
        return True, "summary_alias", "weak"
    # Some publishers encode the target in a canonical/result URL rather than
    # repeating it in the title or excerpt. This is still target identification,
    # but URL-only identification must remain weak and cannot bypass the
    # substantive security-context floor.
    if _contains_term(url, aliases):
        return True, "url_alias", "weak"

    # Certification/catalog publishers may compact a domain into a URL slug,
    # e.g. "atlassiancom-jira-data-center" for "atlassian.com". Treat only
    # the compact registrable-domain form as a URL signal; do not add it to
    # title/summary matching, where this heuristic would be too permissive.
    normalized_domain = domain.casefold().strip(".")
    labels = normalized_domain.split(".")
    registrable_domain = ".".join(labels[-2:]) if len(labels) >= 2 else normalized_domain
    compact_registrable = re.sub(r"[^a-z0-9]", "", registrable_domain)
    if compact_registrable and re.search(
        rf"(?<![a-z0-9]){re.escape(compact_registrable)}(?![a-z0-9])",
        url.casefold(),
    ):
        return True, "url_alias", "weak"
    return False, "none", "none"

def _incidental_target_mention(domain: str, title: str, summary: str) -> bool:
    aliases = _domain_aliases(domain)
    pattern = "|".join(re.escape(alias.casefold()) for alias in aliases)
    # List-style mentions are useful for detecting incidental references even
    # when the surrounding article has only generic "security" wording.
    # Example/reference wording is intentionally excluded here; it must still
    # pass the substantive security-context floor.
    incidental_patterns = (
        r"\bmentions?\b.{0,100}\b(?:and|among|including)\b",
        r"\b(?:among|including)\b.{0,100}\b(?:other|various|multiple)\b",
        r"\b(?:other|various|multiple)\s+(?:companies|organizations|retailers|vendors|providers)\b",
    )
    for text2 in (title, summary):
        folded = text2.casefold()
        if not re.search(pattern, folded):
            continue
        if any(re.search(item, folded) for item in incidental_patterns):
            return True
    return False


def _security_near_target(domain: str, title: str, summary: str) -> bool:
    aliases = _domain_aliases(domain)
    pattern = "|".join(re.escape(alias.casefold()) for alias in aliases)
    for text2 in (title, summary):
        folded = text2.casefold()
        for match in re.finditer(pattern, folded):
            if _contains_term(folded[max(0, match.start()-140):match.end()+180], STRONG_SECURITY_TERMS): return True
    return False

def _contextual_relevance(domain: str, *, url: str, title: str, summary: str) -> tuple[bool, dict[str, str | bool]]:
    page_type = _page_type(url, title)
    if page_type != "article":
        return False, {
            "page_type": page_type,
            "target": "none",
            "target_strength": "none",
            "security": False,
            "reason": f"{page_type}_page",
        }
    target, target_signal, target_strength = _target_subject_signal(
        domain,
        url=url,
        title=title,
        summary=summary,
    )
    # Generic "security" wording is insufficient for contextual evidence.
    # Require a substantive threat/incident signal so product, compliance,
    # capability, and generic security-reference pages do not become evidence.
    security = _contains_term(" ".join((title, summary)), STRONG_SECURITY_TERMS)
    if not target:
        return False, {
            "page_type": page_type,
            "target": "none",
            "target_strength": "none",
            "security": security,
            "reason": "target_not_subject",
        }
    # Generic guides/reference pages are not target-specific security
    # evidence when the target appears only incidentally in the body.
    if target_strength in {"weak", "medium"} and _reference_page(title):
        return False, {
            "page_type": "reference",
            "target": target_signal,
            "target_strength": target_strength,
            "security": security,
            "reason": "reference_page",
        }

    # List-style multi-entity mentions are incidental by definition and
    # should be classified as such even when the article has only generic
    # security wording. This is intentionally narrower than example/reference
    # language, which must still satisfy the substantive security floor.
    if target_strength in {"weak", "medium"} and _incidental_target_mention(
        domain, title, summary
    ):
        return False, {
            "page_type": page_type,
            "target": target_signal,
            "target_strength": target_strength,
            "security": security,
            "reason": "incidental_target_mention",
        }
    # Check the substantive security floor before proximity. A page that
    # merely mentions the target while discussing generic security material
    # must be classified as missing security context, not incidental mention.
    if not security:
        return False, {
            "page_type": page_type,
            "target": target_signal,
            "target_strength": target_strength,
            "security": False,
            "reason": "security_context_missing",
        }
    if target_strength in {"weak", "medium"} and not _security_near_target(
        domain, title, summary
    ):
        return False, {
            "page_type": page_type,
            "target": target_signal,
            "target_strength": target_strength,
            "security": True,
            "reason": "incidental_target_mention",
        }
    return True, {
        "page_type": page_type,
        "target": target_signal,
        "target_strength": target_strength,
        "security": True,
        "reason": "target_subject_security_context",
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_source_timestamp(value: Any) -> str | None:
    """Accept source-reported ISO-8601 dates or timezone-aware timestamps."""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if len(raw) == 10:
        try:
            datetime.fromisoformat(raw)
        except ValueError:
            return None
        return raw

    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return raw


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
        self._filter_dump_finalized = False
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
    def _dump_item(*, domain: str, publisher: SecurityPublisher, url: str, title: str, summary: str, published_at: Any, decision: str, decision_reason: str, signals: dict[str, str | bool]) -> dict[str, Any]:
        return {"domain": domain, "publisher": publisher.name, "publisher_domain": publisher.domain, "url": url, "title": title, "summary": summary, "published_at": None if published_at is None else str(published_at)[:64], "decision": decision, "decision_reason": decision_reason, "signals": signals}

    def _render_filter_dump(self) -> str:
        before = {"schema_version": CONTEXTUAL_FILTER_DUMP_SCHEMA_VERSION, "filter": CONTEXTUAL_FILTER_NAME, "generated_at": _utc_now(), "records": self._filter_candidates}
        after = {"schema_version": CONTEXTUAL_FILTER_DUMP_SCHEMA_VERSION, "filter": CONTEXTUAL_FILTER_NAME, "generated_at": _utc_now(), "records": self._filter_accepted}
        return "BEFORE\n```json\n" + json.dumps(before, ensure_ascii=False, indent=2) + "\n```\n---\nAFTER\n```json\n" + json.dumps(after, ensure_ascii=False, indent=2) + "\n```\n"

    def _reset_filter_dumps(self) -> None:
        # Start a new in-memory run. The dump file is written only when the
        # run is finalized, so readers never observe a partially-built dump.
        self._filter_candidates.clear()
        self._filter_accepted.clear()
        self._filter_dump_finalized = False

    async def _record_filter_dump(self, *, candidate: dict[str, Any], accepted: bool) -> None:
        async with self._filter_dump_lock:
            if self._filter_dump_finalized:
                raise RuntimeError("Contextual filter dump already finalized.")
            self._filter_candidates.append(candidate)
            if accepted:
                self._filter_accepted.append(candidate)

    async def finalize_filter_dump(self) -> None:
        """Persist one complete dump for the current enrichment run."""
        async with self._filter_dump_lock:
            if self._filter_dump_finalized:
                return
            try:
                self._filter_dump_dir.mkdir(parents=True, exist_ok=True)
                dump_path = self._filter_dump_dir / CONTEXTUAL_FILTER_DUMP_FILE
                dump_path.write_text(self._render_filter_dump(), encoding="utf-8")
                self._filter_dump_finalized = True
                logger.info(
                    "[Firecrawl] Contextual filter dump finalized; candidates=%d accepted=%d path=%s",
                    len(self._filter_candidates),
                    len(self._filter_accepted),
                    dump_path,
                )
            except (OSError, TypeError, ValueError) as exc:
                logger.warning("[Firecrawl] Could not finalize contextual filter dump: %s", exc)

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
        logger.info(
            "[Firecrawl] Response fingerprint publisher=%s domain=%s candidates=%d results_sha256=%s",
            publisher.name,
            domain,
            len(items),
            _response_fingerprint(items),
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
            published_at = _normalize_source_timestamp(
                metadata.get("publishedTime") or metadata.get("published_time")
            )

            accepted, signals = _contextual_relevance(domain, url=url, title=title, summary=description)
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
                        "relevance_filter": CONTEXTUAL_FILTER_NAME,
                        # Preserve the assertion contract in the provenance
                        # projection consumed by downstream/legacy serializers.
                        "assertion_scope": "security_publication_context_only",
                    },
                    assertion_scope="security_publication_context_only",
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
