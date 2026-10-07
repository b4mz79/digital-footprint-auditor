# Engineering Conventions

**Project:** Digital Footprint & Privacy Auditor  
**Canonical working branch:** feat/evidence-enrichment-foundation

This document is the engineering convention for this repository. It exists to prevent changes from unintentionally changing established behavior, call paths, UI lifecycle, module boundaries, or test semantics.

Before changing code, read this document and inspect the complete affected call-chain.

---

## 1. Working Agreement

### 1.1 Branch

The active development branch for this project is:

    feat/evidence-enrichment-foundation

Do not make project changes on main unless explicitly requested.

### 1.2 Change discipline

A change is not complete merely because the edited function looks correct.

For a non-trivial change, inspect:

    entry point
      ↓
    caller
      ↓
    target function
      ↓
    related functions
      ↓
    callbacks / event handlers
      ↓
    state transitions
      ↓
    error / fallback paths
      ↓
    integration boundary
      ↓
    tests

Do not use search-and-replace as a substitute for call-chain analysis.

When a function signature, callback, state field, event contract, or serialized structure changes, inspect every producer and consumer.

### 1.3 Preserve existing behavior

Prefer the smallest architectural change that satisfies the requirement.

Do not refactor an established subsystem merely because a new feature touches it.

Especially preserve:

- existing scanner behavior;
- existing AI call contracts;
- existing cache semantics;
- existing evidence semantics;
- existing UI rendering conventions;
- compatibility with existing helpers and utilities;
- contributor changes that are unrelated to the current task.

### 1.4 Patch workflow

Preferred workflow:

    AUDIT
      ↓
    PATCH
      ↓
    USER RUNS LOCAL TESTS / REAL CASE
      ↓
    FEEDBACK
      ↓
    CALL-CHAIN AUDIT AGAIN
      ↓
    PATCH

For a related feature, patch the affected call-chain as one coherent batch rather than fixing isolated symptoms one at a time.

---

## 2. Repository Structure

Current repository convention:

    privacy-auditor/
    ├── app.py
    ├── services/
    │   ├── imap_scanner.py
    │   ├── osint_scanner.py
    │   ├── breach_scanner.py
    │   ├── evidence_enrichment.py
    │   ├── evidence_verification.py
    │   ├── pipeline.py
    │   ├── evidence/
    │   │   ├── __init__.py
    │   │   ├── models.py
    │   │   ├── normalizer.py
    │   │   ├── security_publications.py
    │   │   └── url_verifier.py
    │   └── scorecard/
    │       ├── __init__.py
    │       ├── models.py
    │       ├── storage.py
    │       ├── sqlite_store.py
    │       ├── calculation.py
    │       ├── policy.py
    │       ├── result.py
    │       ├── engine.py
    │       └── integration.py
    ├── utils/
    ├── prompts/
    ├── tests/
    ├── docs/
    ├── requirements.txt
    └── ...

### 2.1 app.py

Application/UI composition layer.

Responsibilities include:

- Streamlit page configuration;
- user input;
- UI state;
- rendering;
- pipeline invocation;
- progressive event presentation;
- final result presentation.

Do not move domain calculation, scanner logic, evidence enrichment logic, or Scorecard semantics into app.py.

### 2.2 services/

Application/domain service layer.

Examples:

- imap_scanner.py: Gmail/IMAP discovery;
- osint_scanner.py: OSINT discovery;
- breach_scanner.py: breach discovery;
- evidence_enrichment.py: evidence enrichment orchestration;
- evidence_verification.py: scoped URL accessibility verification;
- pipeline.py: orchestration of the existing Privacy Auditor flow.

### 2.3 services/evidence/

Evidence domain model and evidence-specific providers/adapters.

Boundary:

    external/provider data
            ↓
    Evidence normalization
            ↓
    EvidenceRecord

Providers do not own Privacy Auditor risk semantics.

### 2.4 services/scorecard/

The Scorecard Add-on is an independent domain module.

Its repository location is under services/ because that is the project's service/module convention. Architectural independence is defined by its API and dependency direction, not by being a top-level directory.

The add-on contains the layers required to turn canonical Scorecard Input into a final Scorecard Result:

    Scorecard Input
        ↓
    Measurement
        ↓
    Definition
        ↓
    Calculation
        ↓
    Risk Policy
        ↓
    Scorecard Result
        ↓
    Replay / persistence

The existing Privacy Auditor pipeline is an optional adapter/source of assessment data. Scorecard core must not require the scanner pipeline to be invoked.

When Scorecard is disabled, the existing pipeline must remain functional without executing Scorecard code.

### 2.5 utils/

Shared low-level/application utilities.

Examples include:

- environment/config helpers;
- logging;
- translations;
- canonical risk labels/helpers.

Do not duplicate an existing utility merely to avoid importing it.

### 2.6 prompts/

Externalized AI system prompts.

Prompt content is configuration/data, not Python logic.

Do not silently duplicate prompt text inside ai_agent.py when the existing prompt-loader mechanism is applicable.

### 2.7 tests/

Tests follow the subsystem they validate.

Examples:

- general application/service tests under tests/;
- Scorecard semantic/core tests under tests/scorecard_core/;
- Scorecard engine/OSS evaluation tests under tests/scorecard/.

Tests are part of the behavioral contract. Do not weaken a test merely to make a new implementation pass.

### 2.8 docs/

Project engineering and task documentation belongs here.

Use task/checkpoint documents for significant implementation milestones.

Use stable convention documents for rules that future changes must follow.

---

## 3. Dependency Direction

Preferred direction:

    UI
     ↓
    Pipeline / application orchestration
     ↓
    Domain services
     ↓
    Domain models / adapters
     ↓
    low-level utilities / providers

Evidence:

    Discovery
     ↓
    Evidence normalization
     ↓
    Evidence enrichment
     ↓
    Evidence verification
     ↓
    Evidence consumers

Scorecard:

    Assessment Input
     ↓
    Measurement
     ↓
    Calculation
     ↓
    Policy
     ↓
    Result

AI is an explanation/analysis consumer. It must not become the owner of deterministic Scorecard calculation semantics.

Avoid reverse dependencies such as:

- scanner importing Streamlit;
- domain services depending on UI rendering;
- Scorecard calculation depending on app.py;
- EvidenceRecord depending on a specific provider;
- storage calculating risk;
- AI being required to calculate the authoritative score.

---

## 4. Python Coding Conventions

### 4.1 Typing

Use explicit type annotations for public functions and important internal boundaries.

Prefer modern typing already used by the project:

    dict[str, Any]
    list[EvidenceRecord]
    Mapping[str, Any]
    Callable[[...], ...]

Use Mapping when a function consumes a read-only mapping contract rather than requiring a mutable dict.

Do not introduce unnecessary generic abstractions.

### 4.2 Dataclasses / models

Use dataclasses for stable domain records where the project already uses them.

Existing conventions include:

- frozen=True for immutable Scorecard snapshots;
- slots=True where appropriate;
- validation in __post_init__;
- defensive copying of JSON-like payloads for immutable records.

Do not make immutable historical records mutable merely for convenience.

### 4.3 JSON contracts

When serializing canonical JSON payloads:

- preserve explicit schema/version fields;
- do not silently change field meaning;
- preserve UNKNOWN semantics;
- avoid NaN/Infinity in persisted JSON;
- keep serialization deterministic where replay/comparison depends on it.

For Scorecard persistence, JSON is the payload format and SQLite is the reference storage adapter.

### 4.4 Error handling

Errors must be isolated at the correct boundary.

Optional providers should not normally make the complete Privacy Auditor pipeline fail.

When an error is intentionally isolated:

1. preserve valid upstream data;
2. expose the failure through logs/status/state where appropriate;
3. do not fabricate a successful result;
4. do not convert an unavailable measurement into a false zero.

Distinguish:

    NO RESULT
    ≠
    UNKNOWN
    ≠
    PROVIDER ERROR
    ≠
    RATE LIMITED
    ≠
    INCOMPLETE

unless the domain contract explicitly defines an equivalence.

### 4.5 Logging

Logs should describe observable state and failure boundaries.

Prefer facts such as:

- stage;
- provider;
- count;
- cache HIT/MISS;
- duration;
- rate-limit/cooldown state;
- error type.

Do not log secrets, API keys, passwords, or unnecessary PII.

### 4.6 Configuration

Configuration belongs in the environment/configuration mechanisms already used by the project.

Do not hard-code credentials, provider keys, or environment-specific endpoints.

Use existing environment helper functions where available.

---

## 5. Discovery Conventions

Discovery answers:

> What might exist?

Discovery output is a candidate finding, not automatically final evidence.

Conceptual path:

    Scanner
     ↓
    candidate finding
     ↓
    normalization
     ↓
    EvidenceRecord

A scanner finding must not directly imply:

- active account state;
- sensitive activity;
- meaningful privacy risk;
- breach compromise;

unless the evidence contract explicitly supports that conclusion.

Welcome, registration, verification, OTP, or similar generic messages must not automatically be treated as high-impact activity or meaningful privacy risk.

---

## 6. Evidence Conventions

### 6.1 EvidenceRecord is the provider boundary

External providers produce source data.

Privacy Auditor converts that data into the stable EvidenceRecord model.

Do not expose provider-specific response structures as the long-term domain contract when an EvidenceRecord exists.

### 6.2 Direct vs contextual

Evidence must retain its semantic strength.

At minimum distinguish:

- direct evidence;
- indirect/contextual evidence;
- unknown relationship.

A trusted publication can still be only contextual evidence for an individual's exposure.

Do not upgrade contextual evidence into direct evidence merely because the source is reputable.

### 6.3 Provenance

Evidence should preserve enough provenance to answer:

> Where did this come from, what relationship does it have to the finding, and when was it observed?

Do not remove provenance fields for presentation convenience.

### 6.4 Verification

Current verification scope is deliberately narrow:

    url_accessibility

Verification means URL accessibility only.

It does not mean:

- source trust verified;
- claim verified;
- target exposure verified;
- vulnerability verified;
- website security verified.

Redirects may be observed but are not automatically followed by the current verifier.

Do not broaden verification semantics without an explicit domain decision.

### 6.5 Temporal semantics

Established meanings:

- observed_at: acquisition/observation time generated by Privacy Auditor and timezone-aware;
- published_at: source-reported publication time, optional; never infer it;
- verification_observed_at: URL verification observation time.

Do not invent an event/exposure timestamp from an unrelated publication or observation timestamp.

Date-only source dates may remain date-only where the contract allows them.

### 6.6 Unknown semantics

    UNKNOWN ≠ FALSE
    UNKNOWN ≠ SAFE
    NO EVIDENCE ≠ NO RISK

If the system does not know something, represent that lack of knowledge rather than inventing a negative observation.

---

## 7. Evidence Enrichment Conventions

Evidence enrichment augments existing normalized evidence.

It does not:

- replace scanner findings;
- calculate authoritative risk;
- invent target exposure;
- turn contextual information into direct evidence.

Current conceptual flow:

    existing finding
     ↓
    normalized EvidenceRecord
     ↓
    optional enrichment provider
     ↓
    additional EvidenceRecord(s)
     ↓
    verification / quality signals

Provider failure should leave valid base evidence intact.

### Contextual filter dump

cache/evidence/contextual_filter_dump.md is a test/diagnostic artifact.

It is not a runtime product dependency.

Runtime enrichment must not generate or persist this dump unless explicitly reintroduced as a diagnostic feature.

---

## 8. Breach Scanner Conventions

Breach scanning is multi-engine and failure-aware.

The system must distinguish:

    complete scan + zero findings
            ↓
    no breach finding observed

    incomplete / failed / rate-limited engine
            ↓
    coverage is incomplete

Do not render or calculate:

> no breach exists

from an incomplete scan.

Cache rules must preserve completeness semantics. An incomplete breach scan must not be cached as if it were a complete authoritative scan.

---

## 9. Scorecard Conventions

The Scorecard is an independent add-on.

### 9.1 Domain boundary

The add-on owns:

- Scorecard Input contract;
- measurement representation;
- measurement derivation;
- versioned definition;
- deterministic calculation;
- risk policy;
- calculation lineage;
- final ScorecardResult;
- replay semantics;
- persistence adapter contracts.

The existing Privacy Auditor pipeline may provide an adapter:

    Privacy Auditor state
            ↓
    PipelineAssessmentAdapter
            ↓
    ScorecardInput
            ↓
    Scorecard Add-on

Do not make ScorecardInput synonymous with the entire pipeline state.

### 9.2 Deterministic authority

The Scorecard engine is authoritative for its deterministic calculation and policy result.

AI may explain the supplied result.

AI must not silently recalculate or invent:

- score;
- risk band;
- contribution;
- measurement;
- lineage.

### 9.3 Definitions are data

Weights, formulas, aggregation configuration, normalization parameters, and risk-policy thresholds belong to versioned definitions/policies rather than being hidden business constants inside the engine.

The engine executes configuration.

It does not secretly define the product's final business score.

### 9.4 UNKNOWN and partial values

Do not impute unknown measurements as zero unless a future explicit contract says so.

Do not silently renormalize partial weights.

Preserve:

- state;
- coverage;
- known weight;
- unknown weight;
- lineage;
- known contributions.

### 9.5 Contributions

A contribution represents the mathematical contribution of a component to the relevant calculation stage.

Do not describe a contribution as a percentage unless the contract explicitly defines it as such.

### 9.6 Normalization

Normalization must be explicit.

The source range must be known.

Clamping must be explicitly requested if used.

Do not silently clamp out-of-range values.

### 9.7 Replay

Replay must use explicit stored inputs/configuration and a fixed calculation timestamp when reproducibility is required.

A historical result must not change merely because:

- the current clock changed;
- the current definition changed;
- the current policy changed;
- current pipeline state changed.

---

## 10. Scorecard Persistence Conventions

SQLite is the current reference persistence adapter.

Storage responsibility:

    storage adapter
        ↓
    persist / retrieve snapshots

Storage does not:

- calculate scores;
- evaluate policy;
- interpret evidence;
- mutate domain semantics.

Current Scorecard snapshots are immutable/append-oriented.

Persisted records include versioned definitions/policies, assessments, and final results.

Do not add an ORM or external database dependency unless explicitly required by the architecture.

The storage interface remains abstract so another adapter can be added later without changing Scorecard semantics.

---

## 11. AI Conventions

The AI layer consumes evidence and deterministic analytical context.

AI output is subject to deterministic guardrails already established by the project.

When ScorecardResult is supplied:

    Scorecard Engine
     ↓
    ScorecardResult
     ↓
    AI explanation

not:

    Scorecard Engine
     ↓
    AI recalculation
     ↓
    new authoritative score

Provider failures, parse failures, rate limits, and timeouts should remain distinguishable where the provider chain depends on those distinctions.

Local Ollama is an optional provider/fallback, not a reason to change domain semantics.

---

## 12. Streamlit UI / UX Conventions

**This section is normative.**

The UI has an established rendering convention. Backend changes must adapt to it rather than casually replacing it.

### 12.1 Canonical result order

Persistent result order:

    SERVICES
      ↓
    BREACH
      ↓
    EVIDENCE
      ↓
    SCORECARD
      ↓
    AI

A new backend stage must not cause an earlier result to appear below a later result.

### 12.2 Progressive rendering

Progressive UI has two categories.

Persistent results:

- discovered services;
- breach result;
- evidence result;
- scorecard result;
- final AI result.

Transient progress/status:

- scanning;
- enrichment in progress;
- Scorecard calculation in progress;
- AI starting.

Transient status must have its own lifecycle.

When a stage reaches a terminal state, its temporary status must be cleared/reconciled.

Do not leave a scanning status visible after that stage has completed.

### 12.3 Main rendering convention

The established application style uses a shared live rendering area with append-style/progressive presentation.

Do not replace this with a fundamentally different multi-placeholder rendering architecture merely because a new stage is added.

If ordering requires an anchor, use the smallest change that preserves the existing UX rather than redesigning the whole rendering lifecycle.

### 12.4 Pipeline event contract

Pipeline events have this general shape:

    {
        "level": "...",
        "key": "...",
        "text": "...",
        "stage": "...",
        "args": {...},
    }

Live result payloads are attached separately through _live.

Examples include:

    _live.services
    _live.breach
    _live.evidence
    _live.scorecard
    _live.ai
    _live.ai_item
    _live.ai_reset

A UI change must inspect both event metadata and the live payload.

Do not assume level=success is the only indication that a result is ready.

For example, the current breach completion event is an info event carrying completed breach data in _live.breach.

### 12.5 AI callbacks

AI intermediate callbacks are provisional.

The final AI event/result is authoritative.

If provider failover invalidates previously emitted provisional analysis items, the UI must honor the existing reset event contract rather than retaining stale provisional output.

### 12.6 Cache HIT/MISS

A cache HIT may skip the scanning-progress event and emit the completed result directly.

Therefore:

    MISS:
    progress → result

    HIT:
    result

Do not require an earlier progress event to render a completed stage.

### 12.7 Rerun behavior

Streamlit reruns must reconstruct the UI from stored state without duplicating results or leaving stale progress indicators.

Do not solve rerun problems by introducing client-side JavaScript unless explicitly required.

---

## 13. Testing Conventions

### 13.1 Tests are behavioral contracts

Tests should validate semantics, not implementation trivia.

Prefer tests that prove:

- deterministic behavior;
- correct state transitions;
- failure isolation;
- UNKNOWN semantics;
- version isolation;
- replayability;
- serialization round-trip;
- integration behavior.

### 13.2 Unit vs integration

Use unit tests for isolated domain primitives.

Use integration tests for real call-chain behavior.

A feature touching multiple layers should have an integration path test where appropriate.

### 13.3 Real local runtime

Automated tests do not replace real local validation.

For significant pipeline changes:

    unit/integration tests
            +
    real local execution
            +
    observable failure states

The user performs the local runtime test and reports the result.

### 13.4 Scorecard test structure

The Scorecard reference/native engine is the semantic baseline.

External OSS calculation libraries remain behind adapters.

Compatibility path:

    same canonical input
       ├── native reference
       └── candidate adapter
                 ↓
           canonical output
                 ↓
           semantic comparison

Do not let an external library redefine the Scorecard domain contract.

---

## 14. Documentation Conventions

### Stable engineering rules

Durable rules belong in:

    docs/ENGINEERING_CONVENTIONS.md

### Task/checkpoint documents

Use task-specific documents for:

- implementation checkpoints;
- completed phases;
- evaluation results;
- real-case observations;
- decisions tied to a particular task.

Do not turn every temporary debugging observation into a permanent convention.

### Documentation accuracy

Documentation must describe behavior that actually exists.

If a convention changes, update this document in the same change or immediately after the behavioral decision is finalized.

Do not document speculative future behavior as current behavior.

---

## 15. Change Review Checklist

### Architecture

- [ ] Correct module/layer?
- [ ] Existing boundary preserved?
- [ ] No unnecessary new package/file?
- [ ] Optional add-on remains optional?
- [ ] Dependency direction remains correct?

### Call-chain

- [ ] Entry point inspected?
- [ ] All callers inspected?
- [ ] Related callees inspected?
- [ ] Callback/event consumers inspected?
- [ ] State transitions inspected?
- [ ] Error/fallback paths inspected?
- [ ] Serialization/deserialization consumers inspected?

### Semantics

- [ ] UNKNOWN preserved?
- [ ] No false zero/imputation?
- [ ] Historical/current meaning preserved?
- [ ] Provider failure distinguished from valid negative result?
- [ ] Deterministic calculation remains deterministic?
- [ ] Version/replay semantics preserved?

### UI

- [ ] Existing rendering convention preserved?
- [ ] Result order preserved?
- [ ] Persistent result separated from transient status?
- [ ] Terminal status cleared?
- [ ] Cache HIT path handled?
- [ ] Live event payload handled?
- [ ] AI provisional/reset behavior preserved?
- [ ] Rerun behavior preserved?

### Testing

- [ ] Existing tests still valid?
- [ ] New behavior has appropriate unit/integration coverage?
- [ ] Failure path covered where relevant?
- [ ] Real local test performed by user?
- [ ] No test weakened merely to accommodate implementation?

### Documentation

- [ ] Stable convention updated if behavior changed?
- [ ] Task/checkpoint documentation updated when appropriate?
- [ ] No speculative feature presented as current behavior?

---

## 16. Anti-Patterns

Avoid these patterns unless explicitly justified.

### 16.1 Search-and-replace development

    find symbol
    → replace symbol
    → assume done

This is wrong for cross-layer changes.

### 16.2 UI redesign during backend feature work

Do not rewrite the established UI lifecycle merely because a new backend stage needs rendering.

### 16.3 AI as business-rule authority

Do not move deterministic score/policy semantics into an LLM prompt.

### 16.4 Provider-specific domain model

Do not make EvidenceRecord or Scorecard semantics depend on one external provider.

### 16.5 False certainty

Do not convert:

    unknown

into:

    safe / zero / false

without an explicit domain rule.

### 16.6 Scope creep

Do not add a new scanner, provider, database, OSS library, or UI abstraction simply because it is technically interesting.

First establish that it is required by the current architectural task.

---

## 17. Source of Truth

When there is a conflict between an old comment, an isolated code fragment, and actual integrated behavior:

1. inspect the complete call-chain;
2. inspect tests;
3. inspect current branch behavior;
4. reconcile the documentation with verified behavior.

Do not infer a new convention from one isolated function.

For unresolved architectural/product decisions, do not invent an answer. Mark the decision as unresolved and obtain/reconstruct the intended decision before encoding it into code.

---

**End of Engineering Conventions**
