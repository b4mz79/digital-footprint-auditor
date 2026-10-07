# Add-On Tech Guide

## 1. Purpose

This guide documents the public Add-On architecture of Privacy Auditor.

The Add-On system allows independently packaged extensions to be installed, discovered, activated, invoked, deactivated, and uninstalled without turning every optional capability into a built-in service.

The guide describes the host contract and the reference Add-On `just-sample`.

> This is an architecture and integration guide. It does not document private or commercial Add-On implementations.

## 2. Add-On Concept

An Add-On is an external extension package whose implementation is owned by the Add-On while the host owns the runtime contract.

The basic workflow is:

```
ZIP
 ↓
INSTALL
 ↓
DISCOVER
 ↓
REGISTER
 ↓
ENABLE
 ↓
CALL
```

The host is responsible for:

- package installation and validation
- manifest parsing
- registration
- lifecycle handling
- activation state
- invocation routing
- event dispatch
- result validation
- UI invocation
- error isolation

The Add-On is responsible for:

- its own implementation
- its declared input contract
- its declared result contract
- its UI implementation, when applicable
- its internal domain logic

## 3. Built-in Service vs Add-On

Built-in services are part of the Privacy Auditor core.

Examples include:

- IMAP scanning
- OSINT scanning
- breach scanning
- evidence enrichment
- evidence verification
- AI analysis

Add-Ons are optional extensions loaded by the Add-On Manager.

The distinction is intentional:

```
Privacy Auditor Core
    ├── Built-in Service Modules
    │   ├── IMAP
    │   ├── OSINT
    │   ├── Breach
    │   ├── Evidence
    │   └── AI
    │
    └── Add-On Runtime
        └── External Add-Ons
```

An Add-On must not require the host to convert its implementation into a built-in service.

## 4. Public Add-On Reference

The public/community distribution uses `just-sample` as the reference Add-On.

It demonstrates:

- a hybrid Add-On
- manifest declaration
- event-driven invocation
- input validation
- result generation
- UI rendering
- host-to-Add-On data flow

The reference Add-On is intentionally simple.

## 5. Package Structure

A minimal hybrid Add-On can use:

```
addons/
└── just-sample/
    ├── __init__.py
    ├── manifest.json
    ├── plugin.py
    └── ui.py
```

A larger Add-On may add private implementation modules, configuration, resources, and tests inside its own package.

The host should treat the Add-On directory as an isolated package boundary.

## 6. manifest.json

The manifest is the Add-On's host-facing contract.

Reference structure:

```json
{
  "id": "just-sample",
  "name": "just-sample",
  "caption": "Hello World",
  "version": "1.0.0",
  "entrypoint": "plugin.py",
  "type": "hybrid",
  "invocation": {
    "function": "run",
    "mode": "on_event",
    "input": {
      "required": true
    },
    "return": {
      "type": "result",
      "required": true
    }
  },
  "ui": {
    "entrypoint": "ui.py",
    "function": "render"
  },
  "events": [
    {
      "name": "discovery.imap.completed",
      "input": {
        "required": true
      },
      "return": {
        "type": "result",
        "required": true
      }
    }
  ],
  "result_key": null,
  "ai_context": false,
  "default_active": true
}
```

### 6.1 Manifest fields

| Field | Meaning |
|---|---|
| `id` | Stable Add-On identifier |
| `name` | Display/name identity |
| `caption` | Human-readable description |
| `version` | Add-On version |
| `entrypoint` | Backend entrypoint file |
| `type` | `backend`, `ui`, or `hybrid` |
| `invocation.function` | Backend function exposed to the host |
| `invocation.mode` | `on_demand` or `on_event` |
| `invocation.input.required` | Whether invocation input is required |
| `invocation.return.type` | `result` or `none` |
| `invocation.return.required` | Whether a result is required |
| `ui.entrypoint` | Optional UI entrypoint |
| `ui.function` | Optional UI function |
| `events` | Events consumed by an event-driven Add-On |
| `result_key` | Optional key used by the host to select a UI result |
| `ai_context` | Whether the result may be supplied to AI context |
| `default_active` | Initial activation state |

The current backend invocation function is `run`. This is a contract, not an arbitrary function name selected at runtime.

## 7. Add-On Types

Three types are supported:

### backend

Backend logic only.

### ui

UI extension only.

### hybrid

Backend logic plus UI.

The `just-sample` reference is hybrid.

## 8. Invocation Modes

### on_demand

The host invokes the Add-On explicitly:

```
Host
 ↓
AddonManager.invoke(addon_id, context)
 ↓
Add-On run(context)
 ↓
result
```

### on_event

The host emits a canonical event:

```
Built-in Service
 ↓
Canonical Event
 ↓
AddonManager.dispatch_event(...)
 ↓
Matching Add-On
 ↓
result
```

An `on_event` Add-On must declare the events it consumes.

An `on_demand` Add-On must not declare event subscriptions.

## 9. Event Contract

Events are named host-level runtime contracts.

Examples:

```
discovery.imap.completed
discovery.osint.completed
breach.scan.completed
evidence.enriched
evidence.verified
```

The exact event payload is part of the host contract.

For example:

```python
context = {
    "event": "discovery.imap.completed",
    "data": <IMAP result>
}
```

An Add-On should consume the declared contract rather than depending on unrelated internal pipeline state.

## 10. Backend Contract

The host calls the manifest-declared backend function.

Reference:

```python
from typing import Any, Mapping

def run(context: Mapping[str, Any]) -> dict[str, Any]:
    data = context.get("data")
    if not isinstance(data, Mapping):
        raise TypeError("just-sample requires context['data'] as a mapping")

    services = data.get("services", [])
    if not isinstance(services, list):
        raise TypeError("just-sample requires data['services'] as a list")

    return {"jumlah_email": len(services)}
```

The Add-On must validate its own expected input.

Do not assume that an event exists merely because the Add-On was installed.

## 11. Result Contract

A result-producing Add-On must return a mapping compatible with the manifest contract.

For `just-sample`:

```python
{
    "jumlah_email": 3
}
```

The host validates whether a required result was returned.

A result should contain data owned by the Add-On rather than mutating host state directly.

## 12. UI Contract

A UI-capable Add-On declares its UI entrypoint and function.

Reference:

```python
import streamlit as st

def render(context):
    result = context.get("result")
    if not isinstance(result, Mapping):
        return

    jumlah_email = result.get("jumlah_email")
    if not isinstance(jumlah_email, int):
        return

    st.info(
        f"{jumlah_email} hasil scan email ditemukan sesuai kriteria"
    )
```

The UI should fail safely when the expected result is absent or malformed.

The host controls when and where the UI is rendered.

## 13. result_key Routing

`result_key` is an optional host-side routing mechanism.

When it is declared, the host can select a specific value from the Add-On output before passing the result to the UI.

Conceptually:

```
Add-On output
{
    "wrapper": ...,
    "result": ...
}

          ↓ result_key

UI context["result"]
    = selected result
```

An Add-On UI must therefore follow its manifest's result routing contract.

For simple Add-Ons such as `just-sample`, `result_key` is `null`.

## 14. Lifecycle

The lifecycle is intentionally small and fixed.

Only these hooks exist:

```
after_install
before_activate
after_activate
before_deactivate
after_deactivate
before_uninstall
```

### Install

```
INSTALL
  install
  after_install
```

### Activate

```
ACTIVATE
  before_activate
  activate
  after_activate
```

### Deactivate

```
DEACTIVATE
  before_deactivate
  deactivate
  after_deactivate
```

### Uninstall

```
UNINSTALL
  before_uninstall
```

There is deliberately no `before_install` and no `after_uninstall` hook in the current contract.

## 15. AddonManager Responsibilities

The Add-On Manager is the host boundary.

Its responsibilities include:

1. discovering installed packages
2. validating manifests
3. registering Add-Ons
4. tracking activation state
5. executing lifecycle hooks
6. invoking on-demand Add-Ons
7. dispatching events
8. loading the declared entrypoint
9. validating inputs and results
10. invoking UI entrypoints
11. isolating Add-On failures

The Add-On should not bypass the manager to alter host registration or lifecycle state.

## 16. Registration and State

The manager maintains Add-On registration and activation state separately from the Add-On implementation.

Conceptually:

```
Installed
   ↓
Registered
   ↓
Active / Inactive
```

Installation does not mean that an Add-On must execute.

Activation controls whether an Add-On is eligible for invocation or event dispatch.

## 17. ZIP Installation and Security

Add-Ons are installed from ZIP packages.

The installer validates package contents before extraction.

Current safeguards include:

- maximum 500 files
- maximum 50 MB uncompressed content
- path traversal rejection
- symlink rejection
- safe extraction paths
- manifest validation

The Add-On package must remain within its own installation boundary.

The ZIP installer must never allow an Add-On archive to write outside the intended Add-On directory.

## 18. Error Isolation

An Add-On is an optional extension and must not make the core pipeline fragile.

Therefore:

```
Core Service
   ↓
Event
   ↓
Add-On
   ↓
Add-On failure
   ↓
Core pipeline continues
```

Errors should be observable through host logging and state/result reporting.

A broken optional Add-On must not silently convert a successful built-in service execution into a failed core pipeline execution.

## 19. Event Dispatch Flow

The canonical runtime flow is:

```
Built-in Service completes
        ↓
Host emits canonical event
        ↓
AddonManager.dispatch_event()
        ↓
Find active Add-Ons subscribed to event
        ↓
Validate input
        ↓
Load Add-On entrypoint
        ↓
Call run(context)
        ↓
Validate result
        ↓
Store Add-On result
        ↓
Make result available to UI / optional consumers
```

For example:

```
IMAP Scanner
    ↓
discovery.imap.completed
    ↓
just-sample
    ↓
{"jumlah_email": ...}
```

## 20. UI Rendering Flow

Backend execution and UI rendering are separate steps.

```
Event
 ↓
Backend Add-On execution
 ↓
Result storage
 ↓
Live UI payload
 ↓
UI invocation
 ↓
render(context)
```

This separation allows the host to preserve runtime state independently from presentation.

The Add-On UI should not execute the backend operation again merely to obtain data for rendering.

## 21. Reference Add-On: just-sample

### Purpose

`just-sample` is the reference/demo Add-On for the public Add-On architecture.

Its contract is:

- Name: `just-sample`
- Caption: `Hello World`
- Type: `hybrid`
- Invocation: `run`
- Mode: `on_event`
- Event: `discovery.imap.completed`
- Input: IMAP scanner result
- Return: result
- UI: Streamlit renderer

### Backend behavior

It reads the IMAP result's `services` list and returns:

```json
{
  "jumlah_email": 3
}
```

### UI behavior

It renders:

```
3 hasil scan email ditemukan sesuai kriteria
```

The implementation is intentionally small so that developers can understand the host contract without needing to understand the entire Privacy Auditor core.

## 22. Testing

An Add-On should be tested independently from the full application whenever possible.

At minimum test:

### Installation

- ZIP installs successfully
- malformed manifest is rejected
- unsafe paths are rejected
- oversized packages are rejected

### Registration

- Add-On is discovered
- manifest fields are parsed
- activation state is correct

### Invocation

- valid input reaches `run`
- invalid input is rejected safely
- required result is returned
- invalid result is isolated

### Events

- matching event invokes the Add-On
- unrelated event does not invoke it
- inactive Add-On does not execute
- event failure does not break the host

### UI

- UI entrypoint loads
- expected result is rendered
- missing/malformed result is handled safely
- UI routing respects `result_key`

### Reference integration

For `just-sample`, a real integration test should:

1. package the Add-On
2. install it into an isolated Add-On Manager
3. activate it
4. dispatch `discovery.imap.completed`
5. provide a valid IMAP-like result
6. assert the returned `jumlah_email`
7. verify an unrelated event does not execute it

## 23. Pipeline Integration

The Add-On system is integrated with the existing pipeline through host contracts and canonical events.

The preferred model is:

```
Privacy Auditor
    ↓
Built-in Service
    ↓
Canonical Event
    ↓
AddonManager
    ↓
Optional Add-On
```

The Add-On should not require direct ownership of the pipeline.

The core pipeline must remain functional when:

- no Add-On is installed
- an Add-On is inactive
- an Add-On fails
- an Add-On is uninstalled

## 24. AI Context

An Add-On may declare:

```json
"ai_context": true
```

This means the host may expose its result to the AI analysis context after applying the host's normal sanitization and context rules.

It does **not** mean that an Add-On can:

- override deterministic risk policy
- directly change the final risk
- bypass evidence rules
- force an AI conclusion

The Add-On provides structured context; the host remains responsible for how that context enters the AI layer.

## 25. What an Add-On Must Not Do

An Add-On should not:

- modify core source files at runtime
- bypass AddonManager registration
- invent undeclared lifecycle hooks
- consume undeclared events
- assume every event payload has arbitrary internal fields
- mutate unrelated pipeline state without a host contract
- silently execute when inactive
- make the core pipeline dependent on optional Add-On success
- use UI code as a replacement for backend processing
- claim risk authority merely because its result is available to AI

## 26. Compatibility Principles

An Add-On should remain compatible with the host by depending on stable contracts rather than implementation details.

Prefer:

```
Manifest
 + Event Contract
 + Input Contract
 + Result Contract
 + UI Contract
```

Avoid:

```
Add-On
 ↓
Private host function
 ↓
Private pipeline variable
 ↓
Internal implementation detail
```

When the host evolves, compatibility should be evaluated against the declared contract.

## 27. Future Extension Points

The current Add-On architecture leaves room for future capabilities without requiring them today.

Potential extension points include:

- additional canonical events
- richer manifest metadata
- Add-On configuration
- permissions/capabilities
- host-version compatibility declarations
- dependency declarations
- persistent Add-On storage
- API exposure
- packaging/distribution metadata
- controlled Add-On-to-Add-On interaction

These are extension points, not requirements of the current contract.

Do not implement them merely because the architecture leaves room for them.

## 28. Definition of Done

An Add-On is not considered complete merely because its ZIP installs.

A production-quality Add-On should have:

- implementation
- valid manifest
- real host call path
- lifecycle behavior where applicable
- event/input/result contract validation
- UI integration where applicable
- failure isolation
- automated integration tests
- real local validation
- observable failure behavior
- documentation

The preferred engineering order is:

```
PATCH
 ↓
REAL TEST
 ↓
DOCUMENT
```

## 29. Developer Checklist

Before distributing an Add-On:

- [ ] Add-On has a stable unique ID
- [ ] `manifest.json` is valid
- [ ] entrypoint exists
- [ ] `run(context)` follows the declared contract
- [ ] invocation mode is correct
- [ ] events are declared when using `on_event`
- [ ] no events are declared for `on_demand`
- [ ] result contract is correct
- [ ] UI contract is correct when applicable
- [ ] `result_key` semantics are understood
- [ ] lifecycle hooks, if used, are from the supported set
- [ ] package passes ZIP security validation
- [ ] inactive state prevents execution
- [ ] failures are isolated
- [ ] integration tests pass
- [ ] real local execution has been validated
- [ ] documentation is included

---

**Reference implementation:** `addons/just-sample/`

**Host boundary:** `services/addon_manager.py`

**Public scope:** Add-On mechanism, Add-On Manager, contracts, lifecycle, event system, and `just-sample`.
