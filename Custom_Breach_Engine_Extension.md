# Breach Scanner v2 Architecture

Breach Scanner v2 introduces a controlled execution layer
for external breach intelligence providers.

Features:

- Worker queue based execution
- Per-engine rate limiter
- Circuit breaker
- Engine health tracking
- 429 recovery handling
- Provider isolation


## Why Worker Queue?

Previous implementation executed engines directly using
`asyncio.gather()`.

This could create burst traffic.

---

# Custom Breach Engine Extension

Breach Scanner v2 is designed with a modular architecture that allows additional breach intelligence providers to be integrated without modifying the core scanner pipeline.

A new breach engine only needs to follow the existing **engine contract** used by the built-in scanners.

---

## Engine Lifecycle

Every breach engine follows this execution flow:

```text
Input Target
      |
      v
build_plan()
      |
      v
execute_engine_v2()
      |
      v
EngineResult
      |
      v
Unified Findings Pipeline
      |
      v
Cache / UI / Reporting
```

A custom engine must not:

* implement its own cache mechanism
* modify the global result schema
* bypass `execute_engine_v2()`
* expose raw provider responses directly to the UI

---

# Engine Registration

A custom engine must first define a stable identifier:

```python
ENGINE_CUSTOM = "Custom Breach Engine"
```

Add its configuration:

```python
CUSTOM_API_KEY = os.getenv(
    "CUSTOM_API_KEY",
    ""
).strip()
```

Register engine availability:

```python
engine_enabled = {
    ENGINE_CUSTOM: bool(CUSTOM_API_KEY),
}
```

If the required API credential is unavailable, the engine must be treated as:

```text
SKIPPED
```

and must not cause the complete breach scan to fail.

---

# Engine Integration

The engine is registered through `build_plan()`:

```python
if engine_enabled[ENGINE_CUSTOM]:
    plan.append(
        (
            ENGINE_CUSTOM,
            lambda: scan_custom_async(
                client,
                target,
                CUSTOM_API_KEY,
            ),
        )
    )
```

The engine function must return:

```python
list[dict]
```

using the internal finding schema.

---

# Finding Schema

Every engine must normalize its provider response into the internal finding format.

Required fields:

```json
{
  "source": "Engine Name",
  "kind": "breach_db",
  "dataset": "Dataset Name",
  "title": "Human readable title",
  "url": "Provider URL",
  "has_password": true,
  "snippet": "Short sanitized summary"
}
```

Additional fields are allowed if:

* they do not contain raw PII
* they do not contain credentials
* they do not contain raw breach records

---

# Have I Been Pwned (HIBP) Integration Example

HIBP returns breach metadata through a JSON API response.

Example response:

```json
{
  "Name": "Adobe",
  "Title": "Adobe",
  "Domain": "adobe.com",
  "BreachDate": "2013-10-04",
  "PwnCount": 152445165,
  "DataClasses": [
    "Email addresses",
    "Passwords",
    "Usernames"
  ],
  "IsVerified": true
}
```

The response should be mapped into the internal finding schema:

```json
{
  "source": "HaveIBeenPwned API",
  "kind": "breach_db",
  "dataset": "Adobe",
  "title": "Breach dataset: Adobe",
  "url": "https://haveibeenpwned.com",
  "breach_date": "2013-10-04",
  "has_password": true,
  "data_classes": [
    "Email addresses",
    "Passwords",
    "Usernames"
  ],
  "verified": true
}
```

The scanner pipeline will then process it exactly like other breach database engines.

---

# Security Requirements

Custom engines must follow these security requirements.

## 1. API Key Handling

API credentials:

* must only be loaded from environment variables
* must never appear in logs
* must never be stored in cache
* must never be included in findings

Example:

```python
CUSTOM_API_KEY = os.getenv("CUSTOM_API_KEY")
```

---

## 2. Response Sanitization

All external provider responses must be treated as **untrusted data**.

The engine must:

* enforce response size limits
* validate JSON structure
* remove unsafe HTML content
* avoid storing raw breach records

Example:

```python
title = clean_title(item.get("Title"))
```

---

## 3. Password Exposure Mapping

An engine may indicate password exposure using metadata:

```python
has_password = True
```

based on the provider response.

The engine must never store:

* leaked passwords
* password hashes
* credential dumps
* raw breach records

Only metadata describing exposure should be retained.

---

# Engine Status Handling

Custom engines must use the standard engine status model:

| Condition               | Status       |
| ----------------------- | ------------ |
| API request successful  | SUCCESS      |
| API key unavailable     | SKIPPED      |
| Provider rate limit     | RATE_LIMITED |
| Request timeout         | TIMEOUT      |
| Provider schema changed | FAILED       |

---

# Deduplication

All findings are processed through the global deduplication pipeline.

For breach database findings, the recommended identifier is:

```python
(
    url,
    dataset,
    breach_date
)
```

Custom engines do not need to implement their own deduplication logic.

---

# Contributor Guidelines

A contributor adding a new breach engine only needs to provide:

1. Async engine implementation

```python
async def scan_custom_async(...):
    ...
    return findings
```

2. Provider response mapping into the internal schema

3. Environment configuration

4. Engine identifier registration

No modification is required for:

* queue system
* circuit breaker
* rate limiter
* cache layer
* reporting pipeline
* UI layer

With this architecture, new breach intelligence providers can be integrated as independent engines without affecting existing scanners.
