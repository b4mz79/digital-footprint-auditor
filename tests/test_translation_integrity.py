from __future__ import annotations

import ast
import re
from pathlib import Path

from utils import translations
from utils.translations import TRANSLATIONS
from utils import prompt_loader


ROOT = Path(__file__).resolve().parents[1]
LANGUAGES = ("id", "en", "de", "ru", "es", "ar", "fr", "zh", "it", "nl", "ja")
EXPECTED_DSR_FIELDS = {"email", "phone_str", "services_str"}


def _placeholders(value: str) -> set[str]:
    return set(re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", value))


def _static_translation_keys(source: str) -> set[str]:
    """Return literal keys passed to t(), ignoring comments and string contents."""
    tree = ast.parse(source)
    keys: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "t":
            continue
        if not node.args:
            continue

        first_arg = node.args[0]
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            keys.add(first_arg.value)

    return keys


def test_translation_import() -> None:
    assert translations is not None


def test_default_translation_language_is_english() -> None:
    assert translations.t("title") == TRANSLATIONS["en"]["title"]


def test_unknown_translation_language_falls_back_to_english() -> None:
    assert translations.t("title", lang="unsupported") == TRANSLATIONS["en"]["title"]


def test_system_prompt_loader_defaults_to_english(monkeypatch, tmp_path) -> None:
    (tmp_path / "system_prompt_en.txt").write_text(
        "English system prompt", encoding="utf-8"
    )
    (tmp_path / "system_prompt_id.txt").write_text(
        "Prompt sistem Bahasa Indonesia", encoding="utf-8"
    )
    monkeypatch.setattr(prompt_loader, "PROMPT_DIR", tmp_path)
    prompt_loader.load_system_prompt.cache_clear()
    try:
        assert prompt_loader.load_system_prompt() == "English system prompt"
    finally:
        prompt_loader.load_system_prompt.cache_clear()


def test_system_prompt_loader_falls_back_to_english(monkeypatch, tmp_path) -> None:
    (tmp_path / "system_prompt_en.txt").write_text(
        "English fallback prompt", encoding="utf-8"
    )
    monkeypatch.setattr(prompt_loader, "PROMPT_DIR", tmp_path)
    prompt_loader.load_system_prompt.cache_clear()
    try:
        assert prompt_loader.load_system_prompt("unsupported") == "English fallback prompt"
    finally:
        prompt_loader.load_system_prompt.cache_clear()


def test_ui_translation_keys_are_aligned_across_all_languages() -> None:
    assert set(TRANSLATIONS) == set(LANGUAGES)
    reference_keys = set(TRANSLATIONS["en"])
    assert reference_keys

    for lang in LANGUAGES:
        assert set(TRANSLATIONS[lang]) == reference_keys, (
            f"Translation key mismatch for language {lang}"
        )


def test_ui_translation_placeholders_are_aligned() -> None:
    reference = TRANSLATIONS["en"]

    for lang in LANGUAGES:
        for key, english_value in reference.items():
            assert _placeholders(TRANSLATIONS[lang][key]) == _placeholders(
                english_value
            ), f"Placeholder mismatch: lang={lang}, key={key}"


def test_static_translation_key_extraction_ignores_non_code_text() -> None:
    source = '''
# t("comment_key")
example = 't("string_key")'
def render():
    """Example: t("docstring_key")"""
    t("actual_key")
    t(key_from_runtime)
'''
    assert _static_translation_keys(source) == {"actual_key"}


def test_python_translation_calls_resolve_to_known_keys() -> None:
    static_keys: set[str] = set()
    ignored_dirs = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "build",
        "dist",
    }
    for source_path in ROOT.rglob("*.py"):
        # Only inspect first-party source; virtual environments and generated
        # build/test directories may contain unrelated functions named t().
        if any(part in ignored_dirs for part in source_path.relative_to(ROOT).parts[:-1]):
            continue
        source = source_path.read_text(encoding="utf-8")
        static_keys.update(_static_translation_keys(source))

    dynamic_key_families = {
        "engine_status_ok",
        "engine_status_partial",
        "engine_status_error",
        "engine_status_skipped",
        "risk_high",
        "risk_medium",
        "risk_low",
        "risk_unknown",
    }
    pipeline_event_keys = {
        "error_addon_event",
        "addon_event_finished",
        "error_imap",
        "error_osint",
        "breach_scan_complete",
        "error_breach_scan",
        "evidence_enrichment_start",
        "evidence_enrichment_skipped",
        "evidence_enrichment_complete",
        "spinner_ai",
        "ai_completed",
        "ai_failed",
    }
    referenced = static_keys | dynamic_key_families | pipeline_event_keys

    for lang in LANGUAGES:
        missing = referenced - set(TRANSLATIONS[lang])
        assert not missing, f"Unknown UI translation keys for {lang}: {sorted(missing)}"


def test_all_system_prompts_have_the_complete_evidence_checklist() -> None:
    required_contract_fields = ('"service"', '"risk_level"', '"reason"', '"delete_url"')

    for lang in LANGUAGES:
        path = ROOT / "prompts" / f"system_prompt_{lang}.txt"
        prompt = path.read_text(encoding="utf-8").strip()
        assert prompt, f"Empty system prompt: {lang}"
        assert all(field in prompt for field in required_contract_fields), (
            f"Output contract field missing from prompt: {lang}"
        )
        assert "breach_evidence" in prompt, f"Breach evidence rule missing: {lang}"

        numbered_lines = [
            (index, int(match.group(1)))
            for index, line in enumerate(prompt.splitlines())
            if (match := re.match(r"^\s*(\d+)[.)]\s+", line))
        ]
        checklist_start = max(
            index for index, number in numbered_lines if number == 1
        )
        checklist_numbers = [
            number for index, number in numbered_lines if index >= checklist_start
        ]
        assert checklist_numbers == list(range(1, 19)), (
            f"Evidence checklist must contain each item 1–18 exactly once: {lang}; "
            f"found {checklist_numbers}"
        )


def test_all_dsr_templates_have_matching_runtime_placeholders_and_requests() -> None:
    for lang in LANGUAGES:
        path = ROOT / "utils" / f"dsr_{lang}.txt"
        template = path.read_text(encoding="utf-8").strip()
        assert template, f"Empty DSR template: {lang}"
        assert _placeholders(template) == EXPECTED_DSR_FIELDS, (
            f"DSR placeholder mismatch for language {lang}: "
            f"{_placeholders(template)}"
        )
        requests = re.findall(r"^\s*\d+[.)]\s+", template, flags=re.MULTILINE)
        assert len(requests) == 3, (
            f"DSR template must contain three request clauses: {lang}"
        )

        reference_line = next(
            (
                line for line in template.splitlines()
                if any(
                    marker in line.lower()
                    for marker in ("rujukan:", "reference:", "referenz:", "ссылка:", "основание:", "referencia:", "المرجع:", "参考依据", "référence", "riferimento:", "referentie:", "参照:")
                )
            ),
            "",
        )
        assert "27/2022" in reference_line or "27 Tahun 2022" in reference_line, (
            f"Indonesia PDP Law reference missing from DSR template: {lang}"
        )
        assert any(token in reference_line.upper() for token in ("GDPR", "RGPD", "AVG", "DSGVO")), (
            f"GDPR reference scope missing from DSR template: {lang}"
        )
