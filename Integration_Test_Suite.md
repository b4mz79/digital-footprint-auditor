# 🧪 Integration Test Suite

The project uses pytest tests to check core behavior and reduce regressions across scanning, evidence handling, AI analysis, caching, add-ons, and application integration.

## Test Coverage

The suite includes tests for:

- **Breach scanner:** engine execution, status handling, queue behavior, and search-result redirect policy.
- **AI analysis:** response/schema validation, evidence-based risk safeguards, prompt/evidence size limits, and provider fallback behavior.
- **Evidence pipeline:** evidence normalization and provenance, contextual enrichment, temporal semantics, URL verification, and verification failure/unknown states.
- **Pipeline integration:** scan-stage orchestration, evidence output, add-on lifecycle integration, and tenant ID validation.
- **Cache behavior:** cache identity, cache lifecycle, module-specific cache controls, and successful-result reuse.
- **Add-On security and lifecycle:** package structure, authority validation, filesystem policy, security validation, installation, activation/invocation behavior, and sample Add-On packaging.
- **OSINT transport and launchers:** transport policy and launcher-related security/regression checks.
- **Translations:** translation key and language integrity.

Tests use mocks and controlled fixtures where appropriate; they are not a substitute for optional live-provider smoke tests or a real scan using credentials.

## Install Test Dependencies

From the repository root, activate your virtual environment and install the test dependencies:

```bash
pip install -r requirements.txt
pip install -r requirements-test.txt
```

## Run the Suite

Run the full suite:

```bash
python -m pytest
```

Run a focused test module when debugging a specific area, for example:

```bash
python -m pytest tests/test_evidence_enrichment.py
python -m pytest tests/test_provider_fallback.py
python -m pytest tests/addons/
```

Do not rely on a fixed example test count in this document: the number of tests changes as coverage evolves. Treat the actual pytest summary from your current checkout as the source of truth.

## Contributor Checklist

Before opening a Pull Request:

1. Add or update tests for changed behavior, including relevant failure paths.
2. Run the full suite with `python -m pytest`.
3. Review failures and warnings; do not report a run as passing if collection or execution was interrupted.
4. If the change affects external providers, supplement mocked tests with a controlled smoke test when credentials and provider terms allow it.
5. Include the command and actual result in the Pull Request description.

The suite is intended to catch regressions in security-sensitive behavior. A passing test run does not prove that external providers are always available, that every breach can be found, or that the application is free of vulnerabilities.
