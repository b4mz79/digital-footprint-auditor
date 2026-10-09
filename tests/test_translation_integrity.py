from __future__ import annotations

import re
from pathlib import Path

from utils import translations
from utils.translations import TRANSLATIONS


ROOT = Path(__file__).resolve().parents[1]
LANGUAGES = ("id", "en", "de", "ru", "es", "ar", "zh", "fr", "it", "nl", "ja")
EXPECTED_DSR_FIELDS = {"email", "phone_str", "services_str"}


def _placeholders(value: str) -> set[str]:
    return set(re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", value))


def test_translation_import() -> None:
    assert translations is not None


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


def test_python_translation_calls_resolve_to_known_keys() -> None:
    static_keys: set[str] = set()
    for source_path in ROOT.rglob("*.py"):
        source = source_path.read_text(encoding="utf-8")
        static_keys.update(
            re.findall(r"""\bt\(\s*["']([^"']+)["']""", source)
        )
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
