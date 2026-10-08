"""Shared low-level cache identity primitives.

Cache semantics remain owned by each module. This module only provides the
cryptographic identity primitive so cache modules do not depend on one another.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re

_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")


def _pepper() -> str:
    value = os.getenv("PII_PEPPER_KEY", "").strip()
    if len(value) < 32:
        raise RuntimeError("PII_PEPPER_KEY must be at least 32 characters.")
    return value


def hmac_identity(value: str) -> str:
    return hmac.new(
        _pepper().encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def tenant_identity(tenant_id: str) -> str:
    if not isinstance(tenant_id, str):
        raise TypeError("tenant_id must be a string")
    value = tenant_id.strip()
    if not value or not _TENANT_ID_RE.fullmatch(value):
        raise ValueError("Invalid tenant_id.")
    return hmac_identity(value)
