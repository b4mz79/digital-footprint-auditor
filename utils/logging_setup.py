"""One place for logging configuration and log redaction.

Previously breach_scanner, imap_scanner and osint_scanner each called logging.basicConfig()
(first import won, and the default level NOTSET logged everything), and two copies of the
redaction filter lived in different modules.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit, urlunsplit

from utils.privacy import NUMERIC_CODE_PATTERN, redact_loose_phones

import os

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
NOISY_LOGGERS = (
    "httpx", "httpcore", "openai", "groq", "google", "google.genai",
    "ddgs", "googlesearch", "urllib3", "requests",
)


class SensitiveDataFilter(logging.Filter):
    """Redact PII, credentials and URL query strings from log records."""

    _URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
    _EMAIL_RE = re.compile(r"([\w.\-+%]+)((?:@|%40))([\w.\-]+)(\.\w+)", re.IGNORECASE)
    _SECRET_RE = re.compile(
        r"(?i)\b(?:password|token|api[_-]?key|secret|authorization|cookie|set-cookie|access[_-]?token|refresh[_-]?token|rapidapi-key|key)\b"
        r"([\s\"']*[:=][\s\"']*)[^\s,;&]+"
    )
    _BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
    _PHONE_RE = re.compile(r"(?:\+|%2B|0)\d[\d%20\s+().-]{6,18}\d\b", re.IGNORECASE)

    @staticmethod
    def _sanitize_url(match: re.Match[str]) -> str:
        raw = match.group(0)
        trailing = ""
        while raw and raw[-1] in ".,);]}>\"'":
            trailing = raw[-1] + trailing
            raw = raw[:-1]
        try:
            parsed = urlsplit(raw)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return "[URL_REDACTED]" + trailing
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
            sanitized = urlunsplit((parsed.scheme, safe_netloc, parsed.path or "/", "", ""))
            return sanitized + "?[QUERY_REDACTED]" + trailing if parsed.query else sanitized + trailing
        except Exception:
            return "[URL_REDACTED]" + trailing

    @staticmethod
    def _mask_email(match: re.Match[str]) -> str:
        username, separator, domain_name, tld = match.group(1), match.group(2), match.group(3), match.group(4)
        masked_user = username[:2] + "***" if len(username) > 2 else "***"
        masked_domain = "***" + domain_name[-2:] if len(domain_name) > 2 else "***"
        return f"{masked_user}{separator}{masked_domain}{tld}"

    @staticmethod
    def _mask_phone(match: re.Match[str]) -> str:
        clean_phone = re.sub(r"%20", "", match.group(0), flags=re.IGNORECASE)
        clean_phone = re.sub(r"[^0-9]", "", clean_phone)
        if not (7 <= len(clean_phone) <= 16):
            return "[PHONE_REDACTED]"
        return clean_phone[:3] + "***" + clean_phone[-2:]

    @staticmethod
    def _more_mask(text: str) -> str:
        if not text:
            return ""
        masked = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[EMAIL_REDACTED]", text)
        masked = re.sub(r"\+?\b\d{9,15}\b", "[PHONE_REDACTED]", masked)
        masked = re.sub(
            r"\b(?:\+62|62|0)[ \-]?\d{2,4}[ \-]?\d{3,4}[ \-]?\d{3,5}\b", "[PHONE_REDACTED]", masked
        )
        masked = NUMERIC_CODE_PATTERN.sub("[NUMERIC_CODE_REDACTED]", masked)
        masked = re.sub(
            r"(?i)\b(otp|pin|kode|code|token|sandi|password)\b[\s:=]+[A-Za-z0-9._~+/-]{4,64}\b",
            r"\1 [REDACTED]",
            masked,
        )
        return masked

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
            msg = self._URL_RE.sub(self._sanitize_url, msg)
            msg = self._BEARER_RE.sub("Bearer [REDACTED]", msg)
            msg = self._SECRET_RE.sub("[SECRET_REDACTED]", msg)
            msg = self._EMAIL_RE.sub(self._mask_email, msg)
            msg = self._PHONE_RE.sub(self._mask_phone, msg)
            msg = self._more_mask(msg)
            msg = _CONTROL_CHARS_RE.sub(" ", msg)
            record.msg = msg[:4000]
            record.args = ()
        except Exception:
            record.msg = "[LOG_MESSAGE_REDACTION_FAILED]"
            record.args = ()
        return True


def log_level() -> int:
    name = os.getenv("LOG_LEVEL", "INFO").strip().upper() or "INFO"
    return getattr(logging, name, logging.INFO)


def configure_logging() -> int:
    """Idempotent. Configures the root logger once, hardens noisy SDK loggers, and makes sure
    every root handler redacts. Returns the effective level."""
    level = log_level()
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
    for handler in root.handlers:
        if not any(isinstance(f, SensitiveDataFilter) for f in handler.filters):
            handler.addFilter(SensitiveDataFilter())
    return level


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    lg = logging.getLogger(name)
    lg.setLevel(log_level())
    if not any(isinstance(f, SensitiveDataFilter) for f in lg.filters):
        lg.addFilter(SensitiveDataFilter())
    return lg
