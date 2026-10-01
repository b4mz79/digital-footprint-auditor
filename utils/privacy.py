"""Shared redaction helpers."""
from __future__ import annotations

import re

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
