# Custom Breach Engine Extension

**Language / Bahasa:** [English](Custom_Breach_Engine_Extension.md) | [Bahasa Indonesia](Custom_Breach_Engine_Extension_ID.md)

This guide explains how to add a provider to the built-in breach scanner. It describes the current core integration contract, not a dynamically loadable breach-engine plugin API.

> **Important distinction:** breach engines are registered in `services/breach_scanner.py`. They are not ZIP-installed Add-Ons managed by the Add-On runtime. Adding a built-in breach engine currently requires a code change to the scanner plan and corresponding tests.

## 1. Current Scanner Architecture

The scanner uses a bounded worker queue and a shared execution wrapper:

```text
Input Target
    |
    v
Input Validation / Phone Normalization
    |
    v
build_plan() in scan_data_breaches()
    |
    v
run_engine_queue_v2()
    |
    v
execute_engine_v2()
    |
    v
EngineResult + normalized findings
    |
    v
Cache / merged scan result / UI
```

The shared execution layer provides per-engine rate limiting, circuit-breaker and health tracking, cooldown handling, timeouts, and standardized status reporting. The scanner distinguishes an empty successful result from an engine that did not complete successfully.

### Engine status contract

The current `EngineStatus` values are:

| Status | Meaning |
|---|---|
| `success` | The request completed and its findings list may be empty. |
| `skipped` | The engine is not configured or is not applicable to the target. |
| `rate_limited` | The provider or local limiter rejected the attempt because of rate limits. |
| `timeout` | The execution exceeded its allowed time. |
| `circuit_open` | The circuit breaker is preventing a call while the engine is unhealthy. |
| `failed` | The execution failed or the provider response could not be processed. |

Do not translate a failed, skipped, timed-out, or rate-limited engine into “no breach found.”

## 2. Provider Integration Checklist

Before implementing a provider:

1. Confirm that its terms and API permit the intended defensive use.
2. Define the exact target types it supports (email, phone, or both).
3. Identify its credential and configuration variables.
4. Define response-size, timeout, retry, and rate-limit behavior.
5. Normalize provider data into the existing finding format.
6. Add the engine to the scanner's enabled/skipped configuration and `build_plan()`.
7. Add mocked tests for successful findings, a valid empty result, missing credentials, malformed responses, rate limits, timeouts, and failure isolation.
8. Verify that caching only stores valid successful results and that engine status remains visible.

## 3. Registering a Built-in Engine

The current scanner's `engine_enabled` mapping and `build_plan()` are defined inside `scan_data_breaches()`. Add a stable internal engine identifier using the existing naming conventions, then add the appropriate environment-variable check.

Illustrative pattern (adapt names and function signatures to the actual scanner code):

```python
ENGINE_CUSTOM = "Custom Provider"

custom_api_key = os.getenv("CUSTOM_API_KEY", "").strip()
engine_enabled[ENGINE_CUSTOM] = bool(custom_api_key)

# Inside build_plan(), only append the engine when it is configured
# and applicable to this target.
if engine_enabled[ENGINE_CUSTOM] and custom_target_is_supported(target):
    plan.append((
        ENGINE_CUSTOM,
        lambda: scan_custom_async(client, target, custom_api_key, lang=lang),
    ))
```

This is an integration sketch, not a standalone drop-in patch. Keep identifiers, signatures, and registration consistent with the existing implementation. Do not introduce a second queue or call an engine outside the shared execution wrapper.

If a provider supports email only, register it only for the normalized email target. Do not send phone variants to it unless the provider explicitly supports them.

## 4. Finding Normalization

Engine functions return a `list[dict]` of sanitized findings. Use the current schema and normalization helpers in `services/breach_scanner.py` as the source of truth; do not expose provider payloads directly to the UI.

A normalized finding may contain fields such as:

```json
{
  "source": "Custom Provider",
  "kind": "breach_db",
  "dataset": "Dataset name",
  "title": "Readable, sanitized title",
  "url": "https://provider.example/report",
  "breach_date": "2025-01-01",
  "has_password": false,
  "snippet": "Short sanitized summary"
}
```

Include only fields that are actually supported by the provider response. Do not infer password exposure from a dataset name or from a generic search result. Optional metadata may be retained when it is useful and does not contain raw personal data, credentials, or leaked records.

## 5. Have I Been Pwned (HIBP) Example

HIBP is already integrated as a built-in provider when `HIBP_API_KEY` is configured. Use its implementation as a reference before adding a similar provider.

Breach metadata can include `Name`, `Title`, `Domain`, `BreachDate`, `AddedDate`, `ModifiedDate`, `PwnCount`, `DataClasses`, and verification flags. Normalize only the fields needed by the application's finding schema. For example, `has_password` should be derived from the provider's data-class metadata when available, not hard-coded to `true`.

Never store or emit raw breach records, passwords, password hashes, authentication tokens, or credential dumps. Retain only the minimum sanitized metadata needed to describe the exposure.

## 6. Security Requirements

### Credentials

- Read credentials from environment variables.
- Never log credentials or include them in findings.
- Do not write credentials into cache files or exception messages.
- Keep `.env` out of version control.

### Untrusted provider responses

- Enforce request timeouts and response-size limits.
- Validate response shape and field types before processing.
- Normalize URLs and sanitize titles/snippets using existing helpers.
- Do not render provider HTML as trusted markup.
- Bound the number and length of retained findings.
- Avoid storing raw breach records or unnecessary personal information.

### Resilience and cache behavior

- Reuse the shared execution wrapper, limiter, circuit breaker, and health tracking.
- Let the wrapper classify rate limits, timeouts, and failures.
- Cache only successful normalized results, including a successful empty list.
- Do not treat a failed or incomplete scan as proof that no exposure exists.
- Add regression tests for provider failure isolation and cache behavior.

## 7. Deduplication and Tests

Use the existing global finding merge/deduplication behavior rather than creating an independent cache or result pipeline. For breach database records, a normalized tuple such as `(url, dataset, breach_date)` may help identify duplicates, but verify it against the actual merge logic before relying on it.

At minimum, add tests covering:

- configured and unconfigured provider states;
- email/phone target applicability;
- valid findings and valid empty responses;
- malformed or oversized provider responses;
- timeout, rate limit, and provider errors;
- secret and raw-record redaction;
- cache reuse only for successful results;
- no regression to other engines when this provider fails.

Run the complete suite with:

```bash
python -m pytest
```

## Contributor Notes

A new built-in breach engine typically requires an async provider function (or a bounded thread wrapper for a blocking library), response mapping, environment configuration, scanner-plan registration, and regression tests. Changes to the shared queue, status model, cache pipeline, or UI should be avoided unless the provider requirement genuinely needs them.
