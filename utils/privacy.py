"""Shared redaction helpers."""
from __future__ import annotations

import re
import html

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

# 4-8 digit numbers are usually OTPs/PINs and get redacted, but plain years (1900-2099) carry
# the "when did this leak" evidence and must survive.
NUMERIC_CODE_PATTERN = re.compile(r"\b(?!(?:19|20)\d{2}\b)\d{4,8}\b")

# Dates and year ranges that a broad phone regex would otherwise swallow.
_DATE_LIKE = re.compile(r"^(?:\d{4}[-./]\d{1,2}(?:[-./]\d{1,2})?|\d{1,2}[-./]\d{1,2}[-./]\d{2,4}|\d{4}\s*[-–]\s*\d{4})$")
LOOSE_PHONE_PATTERN = re.compile(r"(?<!\d)\+?\d[\d\s().-]{5,18}\d(?!\d)")


def mask_email(email_str: str) -> str:
    """Strict PII masking for display/logging: 'jo***@g***.com'."""
    if email_str and "@" in email_str:
        local, _, domain = email_str.partition("@")
        labels = domain.split(".")
        return f"{local[:2]}***@{labels[0][:1]}***.{labels[-1]}"
    return "***"


def redact_loose_phones(text: str, placeholder: str) -> str:
    """Replace phone-like digit runs but keep dates and year ranges."""
    def _sub(match: re.Match[str]) -> str:
        value = match.group(0)
        return value if _DATE_LIKE.match(value.strip()) else placeholder
    return LOOSE_PHONE_PATTERN.sub(_sub, text)


_HTML_BLOCK_PATTERN = re.compile(r"(?is)<(?:script|style|noscript|svg|img|iframe|object|embed)\b[^>]*>.*?</(?:script|style|noscript|svg|img|iframe|object|embed)\s*>")
_HTML_TAG_PATTERN = re.compile(r"(?s)<[^>]+>")
_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}\b"
    r"|\b(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|secret|password|passwd)"
    r"\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}"
)
_MARKDOWN_IMAGE_PATTERN = re.compile(r"!\[([^\]]*)\]\([^)]*\)")
_MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_MARKDOWN_DECORATION_PATTERN = re.compile(r"#{1,6}\s+|[*_~`]+")
_WHITESPACE_PATTERN = re.compile(r"\s+")


def clean_web_text(
    text: str,
    *,
    max_length: int,
    placeholder: str = "[REDACTED]",
) -> str:
    """Normalize untrusted web text before storage or display."""
    value = html.unescape(str(text or ""))
    value = html.unescape(value)
    value = _HTML_BLOCK_PATTERN.sub(" ", value)
    value = _HTML_TAG_PATTERN.sub(" ", value)
    # Firecrawl descriptions may contain Markdown generated from page content.
    # Convert images/links to visible text before storage.
    value = _MARKDOWN_IMAGE_PATTERN.sub(lambda m: m.group(1), value)
    value = _MARKDOWN_LINK_PATTERN.sub(lambda m: m.group(1), value)
    value = _MARKDOWN_DECORATION_PATTERN.sub(" ", value)
    value = EMAIL_PATTERN.sub(lambda m: mask_email(m.group(0)), value)
    value = redact_loose_phones(value, placeholder)
    value = NUMERIC_CODE_PATTERN.sub(placeholder, value)
    value = _CREDENTIAL_PATTERN.sub(placeholder, value)
    value = _WHITESPACE_PATTERN.sub(" ", value).strip()
    return value[:max(0, int(max_length))].rstrip()


def clean_web_title(text: str, *, max_length: int = 512) -> str:
    """Clean a web result title for safe storage/display."""
    return clean_web_text(text, max_length=max_length)


def clean_web_snippet(text: str, *, max_length: int = 2000) -> str:
    """Clean a web result snippet/description for safe storage/display."""
    return clean_web_text(text, max_length=max_length)

