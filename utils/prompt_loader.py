"""
External system prompt loader.

System prompts are security policy artifacts used by the AI audit engine.
They are stored outside Python source code to allow policy review, versioning,
and contributor changes without modifying execution logic.

Prompt files remain local repository artifacts.
They are never loaded from remote sources.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from utils.paths import resolve_data_path


# Maximum size guard to prevent accidental oversized prompt loading.
MAX_PROMPT_FILE_SIZE = 100_000


# Default repository location:
# <project_root>/prompts/
#
# Can later be overridden if required without changing loader logic.
PROMPT_DIR = resolve_data_path(
    None,
    "prompts",
)


@lru_cache(maxsize=32)
def load_system_prompt(lang: str = "en") -> str:
    """
    Load AI auditor system prompt from external local file.

    Lookup order:
    1. prompts/system_prompt_<lang>.txt
    2. prompts/system_prompt_en.txt (fallback)

    Args:
        lang:
            Language code, e.g. id, en, de, ja.

    Returns:
        System prompt text.

    Raises:
        FileNotFoundError:
            If no prompt file exists.
        ValueError:
            If prompt file exceeds safety limit.
    """

    lang = str(lang or "en").strip().lower()

    candidates = [
        PROMPT_DIR / f"system_prompt_{lang}.txt",
        PROMPT_DIR / "system_prompt_en.txt",
    ]

    for prompt_file in candidates:
        if not prompt_file.is_file():
            continue

        content = prompt_file.read_text(
            encoding="utf-8",
            errors="strict",
        )

        content = content.strip()

        if not content:
            continue

        if len(content) > MAX_PROMPT_FILE_SIZE:
            raise ValueError(
                f"System prompt exceeds the size limit: {prompt_file.name}"
            )

        return content

    raise FileNotFoundError(
        f"System prompt not found for language '{lang}'. "
        f"Expected directory: {PROMPT_DIR}"
    )