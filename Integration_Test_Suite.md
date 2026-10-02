# 🧪 Integration Test Suite

This project includes an automated integration test suite to verify core functionality and prevent regressions during development.

## Test Coverage

The test suite validates:

- Risk classification pipeline (`HIGH`, `MEDIUM`, `LOW`, `UNKNOWN/Gray`)
- Evidence-based risk floor enforcement
- AI response validation and JSON integrity checks
- Provider fallback flow (for example Gemini → Groq)
- Translation layer integrity
- Application integration behavior

## Running Tests

Install test dependencies:

```bash
pip install -r requirements-test.txt
```

Run the complete test suite:

```bash
pytest
```

Example successful output:

```text
5 passed
```

## For Contributors

Before submitting a Pull Request, contributors are encouraged to run the integration tests locally:

1. Create and activate a virtual environment.
2. Install application and test dependencies.
3. Run `pytest`.
4. Ensure all tests pass before submitting changes.

The test suite is intended to detect regressions in security-sensitive components, especially AI validation, privacy risk analysis, and fallback handling.
