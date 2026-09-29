import os
import json
import re
import time
import html
import asyncio
import logging
import hmac
import hashlib
import ipaddress
import socket
from urllib.parse import urlparse, urlsplit, urlunsplit
from pathlib import Path

import httpx
from dotenv import load_dotenv
from utils.translations import t
from cache_security import save_encrypted_json, load_encrypted_json


# =============================================================================
# Configuration / secure defaults
# =============================================================================

load_dotenv(override=False)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_non_negative_int(name: str, default: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)).strip())
    except (TypeError, ValueError):
        value = default
    return max(0, min(value, maximum))


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").strip().upper() or "INFO"
LOG_LEVEL_VALUE = getattr(logging, LOG_LEVEL, logging.INFO)


# =============================================================================
# Logging redaction
# =============================================================================

class SensitiveDataFilter(logging.Filter):
    """Redact PII, credentials and URL query strings from log records."""

    _URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
    _EMAIL_RE = re.compile(
        r"([\w.\-+%]+)((?:@|%40))([\w.\-]+)(\.\w+)",
        re.IGNORECASE,
    )
    _SECRET_RE = re.compile(
        r"(?i)\b(?:password|token|api[_-]?key|secret|authorization|cookie|set-cookie|access[_-]?token|refresh[_-]?token|rapidapi-key|key)\b"
        r"([\s\"']*[:=][\s\"']*)[^\s,;&]+"
    )
    _BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
    _PHONE_RE = re.compile(
        r"(?:\+|%2B|0)\d[\d%20\s+().-]{6,18}\d\b",
        re.IGNORECASE,
    )

    @staticmethod
    def _sanitize_url(match: re.Match[str]) -> str:
        raw = match.group(0)
        trailing = ""
        while raw and raw[-1] in ".,);]}>":
            trailing = raw[-1] + trailing
            raw = raw[:-1]

        try:
            parsed = urlsplit(raw)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return "[URL_REDACTED]" + trailing

            # Never expose userinfo and never expose query strings/fragments.
            hostname = parsed.hostname or ""
            port = ""
            try:
                if parsed.port is not None:
                    port = f":{parsed.port}"
            except ValueError:
                port = ""

            safe_netloc = hostname
            if ":" in hostname and not hostname.startswith("["):
                safe_netloc = f"[{hostname}]"
            safe_netloc += port

            sanitized = urlunsplit(
                (parsed.scheme, safe_netloc, parsed.path or "/", "", "")
            )
            return sanitized + "?[QUERY_REDACTED]" + trailing if parsed.query else sanitized + trailing
        except Exception:
            return "[URL_REDACTED]" + trailing

    @staticmethod
    def _mask_email(match: re.Match[str]) -> str:
        username = match.group(1)
        separator = match.group(2)
        domain_name = match.group(3)
        tld = match.group(4)
        masked_user = username[:2] + "***" if len(username) > 2 else "***"
        masked_domain = "***" + domain_name[-2:] if len(domain_name) > 2 else "***"
        return f"{masked_user}{separator}{masked_domain}{tld}"

    @staticmethod
    def _mask_phone(match: re.Match[str]) -> str:
        original = match.group(0)
        clean_phone = re.sub(r"%20", "", original, flags=re.IGNORECASE)
        clean_phone = re.sub(r"[^0-9]", "", clean_phone)
        if not (7 <= len(clean_phone) <= 16):
            return "[PHONE_REDACTED]"
        return clean_phone[:3] + "***" + clean_phone[-2:]

    @staticmethod
    def _more_mask(text: str) -> str:
        if not text:
            return ""

        masked = re.sub(
            r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "[EMAIL_REDACTED]",
            text,
        )
        masked = re.sub(r"\+?\b\d{9,15}\b", "[PHONE_REDACTED]", masked)
        masked = re.sub(
            r"\b(?:\+62|62|0)[ \-]?\d{2,4}[ \-]?\d{3,4}[ \-]?\d{3,5}\b",
            "[PHONE_REDACTED]",
            masked,
        )
        masked = re.sub(r"\b\d{4,8}\b", "[NUMERIC_CODE_REDACTED]", masked)
        masked = re.sub(
            r"(?i)\b(otp|pin|kode|code|token|sandi|password)\b[\s:=]+[A-Za-z0-9._~+/-]{4,64}\b",
            r"\1 [REDACTED]",
            masked,
        )
        return masked

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            actual_msg = record.getMessage()
            actual_msg = self._URL_RE.sub(self._sanitize_url, actual_msg)
            actual_msg = self._BEARER_RE.sub("Bearer [REDACTED]", actual_msg)
            actual_msg = self._SECRET_RE.sub("[SECRET_REDACTED]", actual_msg)
            actual_msg = self._EMAIL_RE.sub(self._mask_email, actual_msg)
            actual_msg = self._PHONE_RE.sub(self._mask_phone, actual_msg)
            actual_msg = self._more_mask(actual_msg)
            record.msg = actual_msg
            record.args = ()
        except Exception:
            # Logging must never break application execution.
            record.msg = "[LOG_MESSAGE_REDACTION_FAILED]"
            record.args = ()
        return True


logging.basicConfig(
    level=LOG_LEVEL_VALUE,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

# HTTPX/HTTPCore request logs may contain query parameters. Do not emit them at INFO.
for noisy_logger_name in (
    "httpx",
    "httpcore",
    "ddgs",
    "googlesearch",
    "urllib3",
    "requests",
):
    logging.getLogger(noisy_logger_name).setLevel(logging.WARNING)

for handler in logging.root.handlers:
    handler.addFilter(SensitiveDataFilter())

logger = logging.getLogger("BreachScanner")
logger.setLevel(LOG_LEVEL_VALUE)


# =============================================================================
# Files / runtime configuration
# =============================================================================

BREACH_CACHE_DIR = Path("cache/breach")
BREACH_CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
if os.name != "nt":
    try:
        os.chmod(BREACH_CACHE_DIR, 0o700)
    except OSError:
        pass

DELAY_SECONDS = _env_non_negative_int("DELAY_SECONDS", 2, maximum=300)

IGNORED_DOMAINS_FILE = Path("ignored_domains.txt")
DEFAULT_IGNORED_DOMAINS = [
    "cbinsights.com",
    "zoominfo.com",
    "tracxn.com",
    "pitchbook.com",
    "crunchbase.com",
    "craft.co",
    "datanyze.com",
    "similarweb.com",
    "chinsights.com",
]

MAX_TARGET_LENGTH = 254
MAX_PHONE_DIGITS = 15
MAX_SNIPPET_INPUT = 16_000
MAX_RESULT_URL_LENGTH = 4096
MAX_TITLE_LENGTH = 512
MAX_RESULT_SNIPPET_LENGTH = 2_000
MAX_FINDINGS_PER_ENGINE = 10
MAX_TOTAL_FINDINGS = 100
MAX_HTTP_REDIRECTS = 3
RESPONSE_LIMIT_JSON = 2 * 1024 * 1024
RESPONSE_LIMIT_HTML = 2 * 1024 * 1024
RESPONSE_LIMIT_SEARXNG = 4 * 1024 * 1024
RESPONSE_LIMIT_TAVILY = 3 * 1024 * 1024
REQUEST_TIMEOUT = httpx.Timeout(12.0, connect=5.0)
TRUST_ENV = _env_bool("HTTPX_TRUST_ENV", False)


# SearXNG is administrator-configured, including the case of a private/self-hosted instance.
def _validate_searxng_base_url(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"}:
            return ""
        if not parsed.hostname:
            return ""
        if parsed.username is not None or parsed.password is not None:
            return ""
        if parsed.query or parsed.fragment:
            return ""
        return value
    except Exception:
        return ""


SEARXNG_INSTANCE_URL = _validate_searxng_base_url(
    os.getenv("SEARXNG_INSTANCE_URL", "")
)


# =============================================================================
# Input / utility helpers
# =============================================================================

EMAIL_TARGET_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+$"
)
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _safe_text(value: object, max_len: int) -> str:
    if value is None:
        return ""
    text = str(value)
    text = CONTROL_CHARS_RE.sub(" ", text)
    return text[:max_len]


def _validate_email_target(email: str) -> str:
    email = email.strip().lower()
    if not email or len(email) > MAX_TARGET_LENGTH:
        raise ValueError("Email target tidak valid atau terlalu panjang.")
    if CONTROL_CHARS_RE.search(email) or not EMAIL_TARGET_RE.fullmatch(email):
        raise ValueError("Email target tidak valid.")
    if email.count("@") != 1:
        raise ValueError("Email target tidak valid.")
    local, domain = email.rsplit("@", 1)
    if not local or len(local) > 64 or not domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("Email target tidak valid.")
    return email


def _validate_phone_target(phone: str) -> str:
    phone = phone.strip()
    if not phone or len(phone) > 32 or CONTROL_CHARS_RE.search(phone):
        raise ValueError("Phone target tidak valid.")
    clean_num = re.sub(r"\D", "", phone)
    if not (7 <= len(clean_num) <= MAX_PHONE_DIGITS):
        raise ValueError("Phone target harus memiliki 7-15 digit.")
    return phone


def mask_pii(text: str) -> str:
    """Strict logging redaction: do not put partial email/phone into logs."""
    if not text:
        return ""
    if "@" in text:
        return "[EMAIL_REDACTED]"
    return "[PHONE_REDACTED]"


def mask_sensitive_snippet(subject_text: str) -> str:
    """Redact PII, phone numbers and common credential-like tokens from text."""
    if not subject_text:
        return ""

    masked = subject_text[:MAX_SNIPPET_INPUT]
    masked = re.sub(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "[EMAIL_REDACTED]",
        masked,
    )
    masked = re.sub(r"\+?\b\d{9,15}\b", "[PHONE_REDACTED]", masked)
    masked = re.sub(
        r"\b(?:\+62|62|0)[ \-]?\d{2,4}[ \-]?\d{3,4}[ \-]?\d{3,5}\b",
        "[PHONE_REDACTED]",
        masked,
    )
    masked = re.sub(r"\bG-\d{4,8}\b", "G-[REDACTED]", masked, flags=re.IGNORECASE)
    masked = re.sub(r"\b\d{4,8}\b", "[NUMERIC_CODE_REDACTED]", masked)
    masked = re.sub(
        r"(?i)\b(otp|pin|kode|code|token|sandi|password)\b[\s:=]+[A-Za-z0-9._~+/-]{4,64}\b",
        r"\1 [REDACTED]",
        masked,
    )
    return masked


def safe_filename_identity(email_addr: str, phone: str = "") -> str:
    """Create an HMAC-based cache identity without a hard-coded fallback key."""
    secret_pepper = os.getenv("PII_PEPPER_KEY", "").strip()
    if len(secret_pepper) < 32:
        raise RuntimeError("PII_PEPPER_KEY harus dikonfigurasi dan minimal 32 karakter.")

    normalized_email = email_addr.strip().lower()
    normalized_phone = re.sub(r"\D", "", phone.strip())
    raw_id = f"{normalized_email}_{normalized_phone}".encode("utf-8")
    return hmac.new(
        secret_pepper.encode("utf-8"),
        raw_id,
        hashlib.sha256,
    ).hexdigest()


def safe_tenant_identity(tenant_id: str) -> str:
    secret_pepper = os.getenv("PII_PEPPER_KEY", "").strip()
    if len(secret_pepper) < 32:
        raise RuntimeError("PII_PEPPER_KEY harus dikonfigurasi dan minimal 32 karakter.")
    tenant_id = tenant_id.strip()
    if not tenant_id or len(tenant_id) > 128 or CONTROL_CHARS_RE.search(tenant_id):
        raise ValueError("tenant_id tidak valid.")
    return hmac.new(
        secret_pepper.encode("utf-8"),
        tenant_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def is_safe_external_url(url: str) -> bool:
    """Validate a URL before an outbound fetch.

    This blocks non-HTTP schemes, userinfo, and IPs in private/local/reserved ranges.
    DNS is resolved only for validation; callers that actually fetch arbitrary URLs
    should also use a network-layer egress policy because DNS can change after this check.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        if parsed.username is not None or parsed.password is not None:
            return False

        hostname = parsed.hostname.rstrip(".").lower()
        if hostname in {
            "localhost",
            "localhost.localdomain",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "169.254.169.254",
        }:
            return False

        resolved = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
        if not resolved:
            return False

        for item in resolved:
            ip = ipaddress.ip_address(item[4][0])
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
    except Exception:
        return False


def normalize_phone_number(phone: str) -> list[str]:
    _validate_phone_target(phone)
    clean_num = re.sub(r"\D", "", phone.strip())
    if not clean_num:
        return []

    formats: set[str] = set()
    if clean_num.startswith("62"):
        local_num = "0" + clean_num[2:]
        intl_num = clean_num
    elif clean_num.startswith("0"):
        local_num = clean_num
        intl_num = "62" + clean_num[1:]
    else:
        local_num = "0" + clean_num
        intl_num = "62" + clean_num

    formats.add(local_num)
    formats.add(intl_num)
    formats.add("+" + intl_num)

    if len(local_num) >= 10:
        prefix_local = local_num[:4]
        prefix_intl_code = "+62"
        prefix_intl_body = intl_num[2:5]

        rest_local = local_num[4:]
        rest_intl = intl_num[5:]

        mid_len = len(rest_local) // 2
        part1_local = rest_local[:mid_len]
        part2_local = rest_local[mid_len:]

        part1_intl = rest_intl[:mid_len]
        part2_intl = rest_intl[mid_len:]

        formats.add(f"{prefix_local} {part1_local} {part2_local}")
        formats.add(f"{prefix_local}-{part1_local}-{part2_local}")
        formats.add(f"{prefix_intl_code} {prefix_intl_body} {part1_intl} {part2_intl}")
        formats.add(f"{prefix_intl_code}-{prefix_intl_body}-{part1_intl}-{part2_intl}")

    return sorted(formats)


def clean_snippet(text: str, max_len: int = 220, lang: str = "id") -> str:
    if not text:
        return t("no_summary", lang=lang)

    # Keep the parser input bounded before regex processing.
    bounded = _safe_text(text, MAX_SNIPPET_INPUT)
    decoded_text = html.unescape(bounded)
    clean_tags = re.sub(r"<[^<]+?>", "", decoded_text)
    cleaned = " ".join(clean_tags.split())
    cleaned = mask_sensitive_snippet(cleaned)

    if len(cleaned) > max_len:
        return cleaned[:max_len] + "..."
    return cleaned


def _normalize_result_url(url: object) -> str:
    """Allow only HTTP(S) result links; remove credentials/fragments and bound length."""
    raw = _safe_text(url, MAX_RESULT_URL_LENGTH).strip()
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        if parsed.username is not None or parsed.password is not None:
            return ""
        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.query,
                "",  # fragments do not need to be persisted
            )
        )[:MAX_RESULT_URL_LENGTH]
    except Exception:
        return ""


def _ignored_domain(hostname: str, ignored_domains: list[str]) -> bool:
    normalized_host = hostname.rstrip(".").lower()
    for domain in ignored_domains:
        domain = domain.strip().lower().lstrip(".")
        if normalized_host == domain or normalized_host.endswith("." + domain):
            return True
    return False


def load_ignored_domains() -> list[str]:
    if not IGNORED_DOMAINS_FILE.exists():
        try:
            with open(IGNORED_DOMAINS_FILE, "x", encoding="utf-8") as f:
                f.write("\n".join(DEFAULT_IGNORED_DOMAINS) + "\n")
            return DEFAULT_IGNORED_DOMAINS.copy()
        except FileExistsError:
            pass
        except OSError:
            return DEFAULT_IGNORED_DOMAINS.copy()

    try:
        with open(IGNORED_DOMAINS_FILE, "r", encoding="utf-8") as f:
            domains = []
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#") and len(line) <= 253:
                    domains.append(line)
            return domains or DEFAULT_IGNORED_DOMAINS.copy()
    except OSError:
        return DEFAULT_IGNORED_DOMAINS.copy()


def is_valid_finding(url: str, target: str = "", title: str = "", snippet: str = "") -> bool:
    if not isinstance(url, str) or not url:
        return False

    normalized_url = _normalize_result_url(url)
    if not normalized_url:
        return False

    try:
        parsed = urlsplit(normalized_url)
        hostname = parsed.hostname or ""
    except Exception:
        return False

    if _ignored_domain(hostname, load_ignored_domains()):
        return False

    if target and target.strip():
        target_lower = target.strip().lower()
        combined_text = f"{title} {snippet}".lower()
        if target_lower not in combined_text:
            return False

    return True


# =============================================================================
# Cache helpers
# =============================================================================

def get_breach_cache_filepath(
    email_addr: str,
    phone: str = "",
    tenant_id: str = "default",
) -> Path:
    tenant_hash = safe_tenant_identity(tenant_id)
    identity_hash = safe_filename_identity(email_addr, phone)
    tenant_dir = BREACH_CACHE_DIR / tenant_hash
    tenant_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        try:
            os.chmod(tenant_dir, 0o700)
        except OSError:
            pass
    return tenant_dir / f"breach_cache_{identity_hash}.json"


def load_breach_cache(
    email_addr: str,
    phone: str = "",
    max_age_hours: float = 12.0,
    tenant_id: str = "default",
) -> dict | None:
    try:
        if max_age_hours < 0:
            raise ValueError("max_age_hours must be >= 0")

        cache_file = get_breach_cache_filepath(email_addr, phone, tenant_id)
        if not cache_file.exists():
            return None

        # Expiry is authenticated by Fernet's token timestamp rather than relying
        # on filesystem mtime, which may be changed independently of the token.
        max_age_seconds = int(max_age_hours * 3600)
        data = load_encrypted_json(
            cache_file,
            tenant_id=tenant_id,
            max_age_seconds=max_age_seconds,
        )
        if isinstance(data, dict):
            data["is_from_cache"] = True
            return data
        return None
    except Exception:
        # Cache failure must not fail the scan.
        return None


def save_breach_cache(
    email_addr: str,
    data: dict,
    phone: str = "",
    tenant_id: str = "default",
) -> None:
    try:
        cache_file = get_breach_cache_filepath(email_addr, phone, tenant_id)
        save_encrypted_json(cache_file, data, tenant_id=tenant_id)
        if os.name != "nt":
            try:
                os.chmod(cache_file, 0o600)
            except OSError:
                pass
    except Exception as exc:
        logger.error(
            "[Breach Cache] Error saving: %s",
            type(exc).__name__,
        )


# =============================================================================
# HTTP helpers
# =============================================================================

class ResponseTooLargeError(RuntimeError):
    pass


class EngineSkipped(Exception):
    """Raised by an engine that is not configured; reported as 'skipped', not 'ok'."""


# Stable engine identifiers used in the scan report (not shown as finding sources).
ENGINE_BREACHDIRECTORY = "BreachDirectory"
ENGINE_GOOGLE_API = "Google Custom Search"
ENGINE_GOOGLE_SCRAPER = "Google Scraper"
ENGINE_BING = "Bing Scraper"
ENGINE_TAVILY = "Tavily"
ENGINE_SEARXNG = "SearXNG"
ENGINE_DDG = "DuckDuckGo"

# Hard ceiling per engine call (thread-based scrapers have no reliable timeout of their own).
ENGINE_TIMEOUT_SECONDS = 45.0


async def _read_response_limited(
    response: httpx.Response,
    max_bytes: int,
) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            declared = int(content_length)
            if declared > max_bytes:
                raise ResponseTooLargeError(
                    f"Response exceeds configured limit ({max_bytes} bytes)."
                )
        except ValueError:
            pass

    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > max_bytes:
            raise ResponseTooLargeError(
                f"Response exceeds configured limit ({max_bytes} bytes)."
            )
        body.extend(chunk)
    return bytes(body)


async def _request_limited(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_bytes: int,
    raise_for_status: bool = True,
    **kwargs,
) -> tuple[int, dict[str, str], bytes]:
    async with client.stream(method, url, **kwargs) as response:
        if raise_for_status:
            response.raise_for_status()
        body = await _read_response_limited(response, max_bytes)
        return response.status_code, dict(response.headers), body


async def _request_json_limited(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_bytes: int,
    **kwargs,
) -> dict | list:
    _, _, body = await _request_limited(
        client,
        method,
        url,
        max_bytes=max_bytes,
        raise_for_status=True,
        **kwargs,
    )
    data = json.loads(body)
    if not isinstance(data, (dict, list)):
        raise ValueError("Unexpected JSON response type.")
    return data


async def _request_text_limited(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_bytes: int,
    raise_for_status: bool = True,
    **kwargs,
) -> tuple[int, str]:
    status_code, headers, body = await _request_limited(
        client,
        method,
        url,
        max_bytes=max_bytes,
        raise_for_status=raise_for_status,
        **kwargs,
    )
    content_type = headers.get("content-type", "")
    charset_match = re.search(r"charset=([^;\s]+)", content_type, flags=re.IGNORECASE)
    encoding = charset_match.group(1).strip('"\'') if charset_match else "utf-8"
    try:
        text_value = body.decode(encoding, errors="replace")
    except (LookupError, UnicodeError):
        text_value = body.decode("utf-8", errors="replace")
    return status_code, text_value


def _log_http_error(source: str, exc: Exception) -> None:
    """Log errors without serializing exception messages that may contain URLs/PII."""
    if isinstance(exc, httpx.HTTPStatusError):
        logger.warning(
            "[%s] HTTP request failed: status=%s",
            source,
            exc.response.status_code,
        )
    elif isinstance(exc, httpx.TimeoutException):
        logger.warning("[%s] Request timeout: %s", source, type(exc).__name__)
    elif isinstance(exc, httpx.RequestError):
        logger.warning("[%s] Network error: %s", source, type(exc).__name__)
    else:
        logger.warning("[%s] Error: %s", source, type(exc).__name__)


# =============================================================================
# Scanner engines
# =============================================================================

async def scan_breachdirectory_async(
    client: httpx.AsyncClient,
    target: str,
    rapidapi_key: str,
) -> list[dict]:
    logger.info("[BreachDirectory] Memulai scan untuk target: %s", mask_pii(target))
    url = "https://breachdirectory.p.rapidapi.com/"
    headers = {
        "X-RapidAPI-Key": rapidapi_key,
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
    }
    params = {"func": "auto", "term": target}

    try:
        data = await _request_json_limited(
            client,
            "GET",
            url,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT,
            max_bytes=RESPONSE_LIMIT_JSON,
        )

        if not isinstance(data, dict):
            raise ValueError("Unexpected response shape.")

        findings: list[dict] = []
        if data.get("success") and data.get("result"):
            results = data.get("result", [])
            if isinstance(results, list):
                for item in results[:MAX_FINDINGS_PER_ENGINE]:
                    if not isinstance(item, dict):
                        continue
                    line = _safe_text(item.get("line", "Database Dump"), MAX_TITLE_LENGTH)
                    findings.append(
                        {
                            "source": "BreachDirectory DB API",
                            "title": f"Leak Detected: {line or 'Database Dump'}",
                            "url": "https://breachdirectory.org",
                            "snippet": f"Credentials exposed. Hash Status: {_safe_text(item.get('has_password', 'Available'), 64)}",
                        }
                    )

        logger.info(
            "[BreachDirectory] Selesai. Ditemukan: %d temuan.",
            len(findings),
        )
        return findings
    except Exception as exc:
        _log_http_error("BreachDirectory", exc)
        raise


async def scan_google_custom_search_async(
    client: httpx.AsyncClient,
    target: str,
    api_key: str,
    cx_id: str,
    lang: str = "id",
) -> list[dict]:
    logger.info("[Google Custom Search] Memulai scan untuk target: %s", mask_pii(target))
    url = "https://www.googleapis.com/customsearch/v1"
    query = f'"{target}" (breach OR leak OR "database dump" OR "combolist" OR "site:pastebin.com")'
    params = {"key": api_key, "cx": cx_id, "q": query, "num": 5}

    try:
        data = await _request_json_limited(
            client,
            "GET",
            url,
            params=params,
            timeout=REQUEST_TIMEOUT,
            max_bytes=RESPONSE_LIMIT_JSON,
        )

        findings: list[dict] = []
        if not isinstance(data, dict):
            raise ValueError("Unexpected response shape.")

        items = data.get("items", [])
        if not isinstance(items, list):
            raise ValueError("Unexpected response shape.")

        for item in items[:MAX_FINDINGS_PER_ENGINE]:
            if not isinstance(item, dict):
                continue
            item_url = _normalize_result_url(item.get("link", ""))
            title = _safe_text(item.get("title", ""), MAX_TITLE_LENGTH)
            snippet = _safe_text(item.get("snippet", ""), MAX_RESULT_SNIPPET_LENGTH)

            if is_valid_finding(item_url, target=target, title=title, snippet=snippet):
                findings.append(
                    {
                        "source": "Google Custom Search API",
                        "title": title or "Google Exposure Finding",
                        "url": item_url,
                        "snippet": clean_snippet(snippet, lang=lang),
                    }
                )

        logger.info(
            "[Google Custom Search] Selesai. Ditemukan: %d temuan.",
            len(findings),
        )
        return findings
    except Exception as exc:
        _log_http_error("Google Custom Search", exc)
        raise


def scan_googlesearch_python(target: str, lang: str = "id") -> list[dict]:
    """Blocking Google Search library executed in a worker thread."""
    logger.info(
        "[Google Scraper] Memulai scan via thread untuk target: %s",
        mask_pii(target),
    )
    try:
        from googlesearch import search

        query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'
        findings: list[dict] = []

        # Prefer explicit library-level timeout/TLS verification when supported by
        # the installed googlesearch-python version.
        import inspect
        search_kwargs = {"num_results": 5, "advanced": True}
        try:
            parameters = inspect.signature(search).parameters
            if "timeout" in parameters:
                search_kwargs["timeout"] = 8
            if "ssl_verify" in parameters:
                search_kwargs["ssl_verify"] = True
        except (TypeError, ValueError):
            pass

        results = search(query, **search_kwargs)
        for r in list(results)[:MAX_FINDINGS_PER_ENGINE]:
            item_url = _normalize_result_url(getattr(r, "url", ""))
            title = _safe_text(getattr(r, "title", ""), MAX_TITLE_LENGTH)
            snippet = _safe_text(
                getattr(r, "description", ""),
                MAX_RESULT_SNIPPET_LENGTH,
            )

            if is_valid_finding(item_url, target=target, title=title, snippet=snippet):
                findings.append(
                    {
                        "source": "Google Search (Scraper)",
                        "title": title or "Google Exposure Finding",
                        "url": item_url,
                        "snippet": clean_snippet(snippet, lang=lang),
                    }
                )

        logger.info(
            "[Google Scraper] Selesai. Ditemukan: %d temuan.",
            len(findings),
        )
        return findings
    except Exception as exc:
        logger.warning("[Google Scraper] Error: %s", type(exc).__name__)
        raise


async def scan_bing_scrape_async(
    client: httpx.AsyncClient,
    target: str,
    lang: str = "id",
) -> list[dict]:
    logger.info("[Bing Scraper] Memulai scan untuk target: %s", mask_pii(target))
    try:
        from bs4 import BeautifulSoup

        query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept-Language": "en-US,en;q=0.9",
        }
        url = "https://www.bing.com/search"

        status_code, response_text = await _request_text_limited(
            client,
            "GET",
            url,
            headers=headers,
            params={"q": query},
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
            max_bytes=RESPONSE_LIMIT_HTML,
            raise_for_status=False,
        )
        if status_code != 200:
            logger.warning("[Bing Scraper] HTTP status: %s", status_code)
            raise RuntimeError(f"Bing returned HTTP {status_code}")

        soup = BeautifulSoup(response_text, "html.parser")
        findings: list[dict] = []

        result_items = soup.select("li.b_algo")
        if not result_items and re.search(
            r"captcha|unusual traffic", response_text, re.IGNORECASE
        ):
            raise RuntimeError("Bing returned a bot-check page")

        for item in result_items[:MAX_FINDINGS_PER_ENGINE]:
            title_elem = item.select_one("h2 a")
            if not title_elem:
                continue

            title = _safe_text(title_elem.get_text(strip=True), MAX_TITLE_LENGTH)
            item_url = _normalize_result_url(title_elem.get("href", ""))
            snippet_elem = item.select_one("div.b_caption p, p.b_algoSlug, p")
            snippet = _safe_text(
                snippet_elem.get_text(strip=True) if snippet_elem else "",
                MAX_RESULT_SNIPPET_LENGTH,
            )

            if is_valid_finding(item_url, target=target, title=title, snippet=snippet):
                findings.append(
                    {
                        "source": "Bing Search (Scraper)",
                        "title": title or "Bing Exposure Finding",
                        "url": item_url,
                        "snippet": clean_snippet(snippet, lang=lang),
                    }
                )

        logger.info(
            "[Bing Scraper] Selesai. Ditemukan: %d temuan.",
            len(findings),
        )
        return findings
    except Exception as exc:
        _log_http_error("Bing Scraper", exc)
        raise


async def scan_searxng_async(
    client: httpx.AsyncClient,
    target: str,
    lang: str = "id",
) -> list[dict]:
    """Scan via administrator-configured SearXNG instance."""
    if not SEARXNG_INSTANCE_URL:
        logger.info(
            "[SearXNG] Pemindaian dilewati: SEARXNG_INSTANCE_URL tidak dikonfigurasi/invalid."
        )
        raise EngineSkipped(ENGINE_SEARXNG)

    query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'
    params = {
        "q": query,
        "format": "json",
        "categories": "general",
    }
    search_endpoint = f"{SEARXNG_INSTANCE_URL}/search"

    try:
        # Deliberately log only a fixed administrator-configured origin, never query data.
        logger.info(
            "[SearXNG] Memulai scan ke instance yang dikonfigurasi untuk target: %s",
            mask_pii(target),
        )
        data = await _request_json_limited(
            client,
            "GET",
            search_endpoint,
            params=params,
            timeout=REQUEST_TIMEOUT,
            max_bytes=RESPONSE_LIMIT_SEARXNG,
        )

        if not isinstance(data, dict):
            raise ValueError("Unexpected response shape.")

        results = data.get("results", [])
        if not isinstance(results, list):
            raise ValueError("Unexpected response shape.")

        findings: list[dict] = []
        for r in results[:MAX_FINDINGS_PER_ENGINE]:
            if not isinstance(r, dict):
                continue
            title = _safe_text(r.get("title", ""), MAX_TITLE_LENGTH)
            item_url = _normalize_result_url(r.get("url", ""))
            snippet = _safe_text(r.get("content", ""), MAX_RESULT_SNIPPET_LENGTH)

            if is_valid_finding(item_url, target=target, title=title, snippet=snippet):
                findings.append(
                    {
                        "title": title,
                        "url": item_url,
                        "snippet": clean_snippet(snippet, lang=lang),
                        "source": "SearXNG (Self-Hosted)",
                    }
                )
        return findings
    except Exception as exc:
        _log_http_error("SearXNG", exc)
        raise


async def scan_breaches_tavily_async(
    client: httpx.AsyncClient,
    target: str,
    api_key: str,
    lang: str = "id",
) -> list[dict]:
    logger.info("[Tavily AI] Memulai scan untuk target: %s", mask_pii(target))
    url = "https://api.tavily.com/search"
    query = f'"{target}" "breach" OR "leak" OR "combolist"'
    payload = {
        "api_key": api_key,
        "query": query,
        "search_depth": "basic",
        "max_results": 7,
    }

    try:
        data = await _request_json_limited(
            client,
            "POST",
            url,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            max_bytes=RESPONSE_LIMIT_TAVILY,
        )

        findings: list[dict] = []
        if not isinstance(data, dict):
            raise ValueError("Unexpected response shape.")

        results = data.get("results", [])
        if not isinstance(results, list):
            raise ValueError("Unexpected response shape.")

        for result in results[:MAX_FINDINGS_PER_ENGINE]:
            if not isinstance(result, dict):
                continue
            item_url = _normalize_result_url(result.get("url", ""))
            title = _safe_text(result.get("title", ""), MAX_TITLE_LENGTH)
            raw_content = _safe_text(
                result.get("content", ""),
                MAX_RESULT_SNIPPET_LENGTH,
            )

            if is_valid_finding(
                item_url,
                target=target,
                title=title,
                snippet=raw_content,
            ):
                findings.append(
                    {
                        "source": "Tavily AI Search",
                        "title": title or "Tavily AI Exposure Finding",
                        "url": item_url,
                        "snippet": clean_snippet(raw_content, lang=lang),
                    }
                )

        logger.info("[Tavily AI] Selesai. Ditemukan: %d temuan.", len(findings))
        return findings
    except Exception as exc:
        _log_http_error("Tavily AI", exc)
        raise


def scan_breaches_ddg(target: str, lang: str = "id") -> list[dict]:
    """Blocking DuckDuckGo library executed in a worker thread."""
    logger.info(
        "[DuckDuckGo] Memulai scan via thread untuk target: %s",
        mask_pii(target),
    )
    try:
        from ddgs import DDGS

        query = f'"{target}" (breach OR leak OR "database dump" OR "combolist")'
        findings: list[dict] = []
        results = list(DDGS().text(query, max_results=5))

        for r in results[:MAX_FINDINGS_PER_ENGINE]:
            if not isinstance(r, dict):
                continue
            item_url = _normalize_result_url(r.get("href", ""))
            title = _safe_text(r.get("title", ""), MAX_TITLE_LENGTH)
            snippet = _safe_text(r.get("body", ""), MAX_RESULT_SNIPPET_LENGTH)

            if is_valid_finding(item_url, target=target, title=title, snippet=snippet):
                findings.append(
                    {
                        "source": "DuckDuckGo Search",
                        "title": title or "DuckDuckGo Exposure Finding",
                        "url": item_url,
                        "snippet": clean_snippet(snippet, lang=lang),
                    }
                )

        logger.info(
            "[DuckDuckGo] Selesai. Ditemukan: %d temuan.",
            len(findings),
        )
        return findings
    except Exception as exc:
        logger.warning("[DuckDuckGo] Error: %s", type(exc).__name__)
        raise


# =============================================================================
# Orchestrator
# =============================================================================

async def scan_data_breaches(
    email: str,
    phone: str = "",
    force_refresh: bool = False,
    lang: str = "id",
    tenant_id: str = "default",
) -> dict:
    """Run all configured breach scanners asynchronously with bounded resources."""

    email = _validate_email_target(email)
    phone = _validate_phone_target(phone) if phone and phone.strip() else ""

    if not isinstance(force_refresh, bool):
        force_refresh = bool(force_refresh)

    # Cache is tenant-scoped. The caller in a multi-tenant deployment must pass the
    # authenticated tenant identifier; it must not be taken from untrusted form data.
    tenant_id = tenant_id.strip()
    if not tenant_id or len(tenant_id) > 128 or CONTROL_CHARS_RE.search(tenant_id):
        raise ValueError("tenant_id tidak valid.")

    if not force_refresh:
        cached_result = load_breach_cache(
            email,
            phone,
            max_age_hours=12.0,
            tenant_id=tenant_id,
        )
        # Only trust caches written by a *complete* scan. Entries without the flag
        # predate engine-status tracking and may be false "clean" results.
        if cached_result and cached_result.get("complete") is True:
            logger.info("[BreachScan] Memuat hasil dari Local Cache.")
            return cached_result

    search_targets = [email]
    if phone:
        search_targets.extend(normalize_phone_number(phone))

    tavily_key = os.getenv("TAVILY_API_KEY", "").strip()
    google_search_key = os.getenv("GOOGLE_SEARCH_API_KEY", "").strip()
    google_cx_id = os.getenv("GOOGLE_CX_ID", "").strip()
    rapidapi_key = os.getenv("RAPIDAPI_KEY", "").strip()

    engine_enabled = {
        ENGINE_BREACHDIRECTORY: bool(rapidapi_key),
        ENGINE_GOOGLE_API: bool(google_search_key and google_cx_id),
        ENGINE_GOOGLE_SCRAPER: True,
        ENGINE_BING: True,
        ENGINE_TAVILY: bool(tavily_key),
        ENGINE_SEARXNG: bool(SEARXNG_INSTANCE_URL),
        ENGINE_DDG: True,
    }
    stats = {name: {"ok": 0, "failed": 0} for name, on in engine_enabled.items() if on}
    skipped_engines = [name for name, on in engine_enabled.items() if not on]

    def build_plan(client: httpx.AsyncClient, target: str) -> list[tuple[str, object]]:
        plan: list[tuple[str, object]] = []
        if engine_enabled[ENGINE_BREACHDIRECTORY]:
            plan.append((ENGINE_BREACHDIRECTORY, scan_breachdirectory_async(client, target, rapidapi_key)))
        if engine_enabled[ENGINE_GOOGLE_API]:
            plan.append((ENGINE_GOOGLE_API, scan_google_custom_search_async(
                client, target, google_search_key, google_cx_id, lang=lang)))
        plan.append((ENGINE_GOOGLE_SCRAPER, asyncio.to_thread(scan_googlesearch_python, target, lang=lang)))
        plan.append((ENGINE_BING, scan_bing_scrape_async(client, target, lang=lang)))
        if engine_enabled[ENGINE_TAVILY]:
            plan.append((ENGINE_TAVILY, scan_breaches_tavily_async(client, target, tavily_key, lang=lang)))
        if engine_enabled[ENGINE_SEARXNG]:
            plan.append((ENGINE_SEARXNG, scan_searxng_async(client, target, lang=lang)))
        plan.append((ENGINE_DDG, asyncio.to_thread(scan_breaches_ddg, target, lang=lang)))
        return plan

    all_findings: list[dict] = []
    active_engines: set[str] = set()

    start_time = time.monotonic()
    logger.info(
        "=== MEMULAI PARALLEL DATA BREACH SCAN (%d target) ===",
        len(search_targets),
    )

    limits = httpx.Limits(
        max_connections=20,
        max_keepalive_connections=10,
    )

    async with httpx.AsyncClient(
        limits=limits,
        timeout=REQUEST_TIMEOUT,
        follow_redirects=False,
        max_redirects=MAX_HTTP_REDIRECTS,
        trust_env=TRUST_ENV,
        verify=True,
    ) as client:
        for idx, target in enumerate(search_targets, start=1):
            if idx > 1 and DELAY_SECONDS:
                logger.info(
                    "Jeda %ds sebelum scan target berikutnya...",
                    DELAY_SECONDS,
                )
                await asyncio.sleep(DELAY_SECONDS)

            plan = build_plan(client, target)
            results = await asyncio.gather(
                *(asyncio.wait_for(coro, timeout=ENGINE_TIMEOUT_SECONDS) for _, coro in plan),
                return_exceptions=True,
            )

            for (name, _coro), res in zip(plan, results):
                if isinstance(res, EngineSkipped):
                    continue
                if isinstance(res, BaseException):
                    stats[name]["failed"] += 1
                    logger.warning("[%s] Engine gagal: %s", name, type(res).__name__)
                    continue

                stats[name]["ok"] += 1
                if isinstance(res, list) and res:
                    remaining = MAX_TOTAL_FINDINGS - len(all_findings)
                    if remaining <= 0:
                        continue
                    bounded_results = res[:remaining]
                    all_findings.extend(bounded_results)
                    for item in bounded_results:
                        if isinstance(item, dict) and item.get("source"):
                            active_engines.add(str(item["source"]))

            if len(all_findings) >= MAX_TOTAL_FINDINGS:
                logger.warning(
                    "[BreachScan] Batas maksimum temuan (%d) tercapai.",
                    MAX_TOTAL_FINDINGS,
                )
                break

    elapsed = time.monotonic() - start_time
    logger.info(
        "=== PARALLEL SCAN SELESAI Dalam %.2f detik ===",
        elapsed,
    )

    # Per-engine outcome. "ok" means it answered for every target queried.
    engines_report: dict[str, dict] = {}
    for name, st in stats.items():
        if st["failed"] == 0:
            status = "ok"
        elif st["ok"] == 0:
            status = "error"
        else:
            status = "partial"
        engines_report[name] = {
            "status": status,
            "targets_ok": st["ok"],
            "targets_failed": st["failed"],
        }
    for name in skipped_engines:
        engines_report[name] = {"status": "skipped", "targets_ok": 0, "targets_failed": 0}

    # A scan is "complete" only if every enabled engine answered. An empty result from an
    # incomplete scan is NOT evidence that nothing was found.
    complete = bool(stats) and all(
        v["status"] == "ok" for v in engines_report.values() if v["status"] != "skipped"
    )
    if not complete:
        failed_names = [n for n, v in engines_report.items() if v["status"] in {"error", "partial"}]
        logger.warning("[BreachScan] Scan tidak lengkap. Engine bermasalah: %s", ", ".join(failed_names) or "-")

    # De-duplicate by normalized URL.
    unique_findings: list[dict] = []
    seen_urls: set[str] = set()
    for item in all_findings:
        if not isinstance(item, dict):
            continue
        url = _normalize_result_url(item.get("url", ""))
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        sanitized_item = dict(item)
        sanitized_item["url"] = url
        unique_findings.append(sanitized_item)

        if len(unique_findings) >= MAX_TOTAL_FINDINGS:
            break

    output = {
        "engine": ", ".join(sorted(active_engines)) if active_engines else "None",
        "results": unique_findings,
        "is_from_cache": False,
        "engines": engines_report,
        "complete": complete,
    }

    # Never cache an incomplete scan: it would replay a possibly false "clean" result for 12h.
    if complete:
        save_breach_cache(
            email,
            output,
            phone,
            tenant_id=tenant_id,
        )
    return output
