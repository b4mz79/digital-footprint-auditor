"""Canonical risk levels shared by the AI service and the UI.

The language of a risk *label* must never decide behaviour (colour, ordering, floors).
Everything keys off the canonical values in RISK_KEYS; labels come from translations.
"unknown" means the available evidence or analysis is insufficient to determine a risk level.
"""
from __future__ import annotations

import re

from utils.translations import TRANSLATIONS

RISK_KEYS = ("high", "medium", "low", "unknown")
RISK_RANK = {"unknown": -1, "low": 0, "medium": 1, "high": 2}
RISK_ICONS = {"high": "🔴", "medium": "🟡", "low": "🟢", "unknown": "🔘"}


def _build_label_map() -> dict[str, str]:
    mapping = {key: key for key in RISK_KEYS}
    for table in TRANSLATIONS.values():
        for key in RISK_KEYS:
            label = table.get(f"risk_{key}")
            if label:
                mapping[label.strip().casefold()] = key
    return mapping


_LABEL_TO_KEY = _build_label_map()
_ENGLISH_WORD_RE = re.compile(r"\b(high|medium|low|unknown)\b")


def normalize_risk(value: object) -> str | None:
    """Map a canonical key or label in any supported language to a canonical risk key."""
    text = str(value or "").strip().casefold()
    if not text:
        return None
    if text in _LABEL_TO_KEY:
        return _LABEL_TO_KEY[text]
    match = _ENGLISH_WORD_RE.search(text)
    return match.group(1) if match else None


def higher_risk(a: str, b: str) -> str:
    return a if RISK_RANK.get(a, -1) >= RISK_RANK.get(b, -1) else b


def risk_icon(risk_key: object) -> str:
    """Unknown or invalid values render with the neutral/gray icon."""
    return RISK_ICONS.get(str(risk_key), RISK_ICONS["unknown"])
