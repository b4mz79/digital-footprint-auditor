# Checkpoint — Measurement / Scorecard Foundation: KPI Inventory Audit

Date: 06-10-2026
Branch: feat/evidence-enrichment-foundation

## Status

Measurement / Scorecard Foundation audit has entered the KPI inventory stage.

No production code, scoring formula, weights, thresholds, or measurement implementation has been changed.

## Current working tree

PRIVACY ASSESSMENT

- DIGITAL FOOTPRINT
  - Service Presence
    - Service Discovery Count — KEEP
    - Evidence-backed Service Count — candidate, under semantic review
    - Discovery Validity / Traceability — separate candidate concept

## Agreed process

TREE → KPI INVENTORY → KPI COVERAGE CHECK → KPI DEFINITION → MEASUREMENT DESIGN → UNIT / TARGET / THRESHOLD → WEIGHT / CONTRIBUTION → SCORECARD FORMULA → RISK CLASS → COLOR.

The project is currently only at KPI inventory. Do not prematurely introduce formulas, weights, thresholds, numeric scores, risk classes, or colors.

## KPI #1 — Service Discovery Count

Measures how many services/platforms are discovered by the application's discovery capability. It measures discovered digital-footprint presence, not risk by itself. It is deterministic and already covered by the current application flow. A successful discovery yielding zero findings is distinct from an unavailable/incomplete discovery result.

Decision: KEEP.

## KPI #2 — Evidence-backed Service Count

Measures how many discovered services have supporting evidence represented in the application's evidence flow.

The discussion established two distinct aspects of Evidence-backed Presence:
1. Evidence-backed Service Count — how many discovered services have supporting evidence.
2. Discovery Validity / Traceability — how valid and traceable the discovery basis is.

Do not collapse these prematurely. KPI #2 remains under inventory/semantic review until the service-to-evidence relationship is fully understood.

## Next step

Continue KPI inventory from the Scorecard Tree, one candidate at a time. For each candidate determine what is actually being measured, whether it is covered by the current application, whether it is a distinct measurement target, and KEEP or PARK.

No coding until the KPI inventory is sufficiently mature.

## Guardrails

The scorecard remains evidence-first, deterministic, and traceable. AI explains assessment results; it is not the authoritative source of score/risk decisions. UNKNOWN is not FALSE/SAFE, and absence of evidence must not be treated as absence of risk.
