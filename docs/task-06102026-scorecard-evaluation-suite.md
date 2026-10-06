# Checkpoint — Scorecard Engine Evaluation Suite Foundation

Date: 06-10-2026
Branch: `feat/evidence-enrichment-foundation`

## Purpose

Build a neutral evaluation harness before selecting or embedding an OSS scorecard/rules engine.

The suite is **not a ZEN test suite**. ZEN is only one candidate backend.

## Boundary

```text
REAL APPLICATION OUTPUT
        ↓
fixture importer / normalization
        ↓
canonical scorecard measurement dataset
        ↓
native reference semantics ───── candidate OSS engine
        ↓                                  ↓
        └──────────── differential comparison
```

`contextual_filter_dump.md` remains an evidence-layer artifact. The suite parses its `BEFORE`/`AFTER` structure and derives only measurements supported by the accepted evidence records.

The real dump is deliberately not copied into public repository fixtures. The importer accepts the application's actual dump path locally; repository fixtures use sanitized representative data.

## Initial Contract Under Test

A KPI measurement carries:

- `id`
- `unit`
- `value`
- `state`
- `source`
- optional `evidence_ids`

The suite explicitly verifies that formula and weight are **not KPI measurement fields**.

## Neutral Reference Semantics

A tiny reference evaluator is included only for compatibility testing:

- deterministic weighted aggregation
- dependency/interlink propagation
- explicit lineage
- `UNKNOWN` propagation

Its formula is synthetic and is **not a Privacy Auditor scorecard formula**.

## Candidate Engine Policy

Candidate OSS engines remain optional dependencies. The first adapter smoke check is ZEN.

No production dependency, scorecard module, AI integration, or risk formula has been introduced.

## Next

Run the suite locally, then add the first real ZEN calculation adapter and a second candidate (for example JSONLogic) only after the neutral contract tests are stable.

The decision matrix will compare:

- semantic fit
- UNKNOWN handling
- dependency/interlink support
- determinism/reproducibility
- version isolation
- lineage/trace support
- adapter complexity
- runtime/dependency cost
- whether the candidate forces domain-model compromise
