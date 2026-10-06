# Checkpoint — Measurement / Scorecard Foundation: Beta Framework Direction

Date: 06-10-2026
Branch: feat/evidence-enrichment-foundation

## Status

Measurement / Scorecard Foundation is in beta framework design.

The KPI inventory/definition work is intentionally NOT final. The scorecard is being designed as a dynamic, iterative framework for beta testing and future refinement.

No production scorecard implementation, scoring formula, weights, thresholds, or hard-coded risk mapping has been introduced.

## Core Architectural Decision — Scorecard as Add-on Module

Scorecard is an independent add-on capability/module, comparable in architectural position to:

- IMAP Scanner
- OSINT Scanner
- Breach Scanner
- Evidence Enrichment
- Evidence Verification

Scorecard MUST NOT be embedded into Evidence Enrichment.

Evidence Enrichment remains responsible for producing/enriching structured evidence. Scorecard consumes the resulting evidence/application signals and performs measurement and assessment according to a configurable scorecard definition.

Conceptual boundary:

DISCOVERY
→ EVIDENCE ENRICHMENT
→ EVIDENCE / VERIFICATION
→ SCORECARD ADD-ON
→ MEASUREMENT / SCORING / RISK
→ AI EXPLANATION

Evidence semantics remain the stable foundation. Scorecard interpretation is configurable and independently evolvable.

## Why Scorecard Must Be Dynamic

The scorecard is not a fixed application feature.

It is a configurable measurement framework that must support iterative:

MAP → MEASURE → ANALYSIS → FEEDBACK → MAP ADJUSTMENT → MAP ...

Therefore the application must not hard-code:

- KPI membership
- dimension/branch structure
- weights
- formulas
- thresholds
- aggregation rules
- score-to-risk mapping

These belong to a scorecard definition/configuration layer that can evolve and be versioned.

The goal is to build the Scorecard Engine/framework, not to permanently encode one specific Privacy Auditor Scorecard.

## Product / Strategic Rationale

For B2C/personal use, a scorecard is useful but not necessarily central.

For B2B, a configurable scorecard can become a key product/business capability because organizations may require different assessment models, KPI structures, weights, thresholds, terminology, policies, and feedback-driven adjustments.

Therefore the Scorecard add-on is both:

1. a technical modularity decision; and
2. a future B2B product architecture decision.

B2C and B2B remain strategic horizons; this does not create a separate B2B product at this stage.

## Current Beta KPI Tree

PRIVACY ASSESSMENT

- A. DIGITAL FOOTPRINT
  - Service Presence
    - Service Discovery Count — KEEP
    - Evidence-backed Service Count — KEEP
    - Discovery Validity / Traceability — KEEP
  - Activity Exposure
    - Generic Activity Signals — KEEP
    - Higher-impact Activity Signals — KEEP

- B. SECURITY EXPOSURE
  - Breach Exposure
    - Breach Finding Count — KEEP
    - Credential / Password Exposure — KEEP
  - Security Context
    - Relevant Security Evidence — KEEP

- C. EVIDENCE SUFFICIENCY
  - Evidence Coverage
    - Evidence Record Coverage — KEEP
    - Evidence Lineage Coverage — KEEP
  - Evidence Verification
    - URL Accessibility State — KEEP
    - Verification Coverage — KEEP

Current beta inventory: 12 candidate KPIs, 0 parked.

KEEP at this stage means covered and sufficiently distinct as a candidate measurement target. It does NOT mean final KPI specification.

## KPI Definition Scope

KPI Definition is intentionally limited to:

1. What exactly is measured?
2. Is the capability/value covered by the current application?
3. Is it a distinct measurement target?
4. KEEP or PARK?

Units, formulas, normalization, targets, thresholds, weights, contributions, aggregation, scoring, and risk mapping belong to later stages.

## Agreed Future Lifecycle

TREE
→ KPI INVENTORY
→ KPI COVERAGE CHECK
→ KPI DEFINITION
→ MEASUREMENT DESIGN
→ UNIT / TARGET / THRESHOLD
→ WEIGHT / CONTRIBUTION
→ SCORECARD FORMULA
→ RISK CLASS
→ COLOR
→ BETA TEST
→ ANALYSIS
→ FEEDBACK
→ MAP ADJUSTMENT
→ repeat

## Architectural Guardrails

- Evidence Enrichment ≠ Scorecard.
- Scorecard ≠ AI.
- AI may explain/reason over results but is not the authoritative scoring/risk engine.
- Scorecard configuration must be dynamic and versionable.
- EvidenceRecord semantics must not be altered merely to accommodate a scorecard.
- UNKNOWN ≠ FALSE/SAFE.
- No evidence ≠ no risk.
- Historical breach ≠ current compromise.
- URL accessibility/verification must not drift into website security scanning.
- Do not invent formulas, weights, thresholds, or scorecard dimensions before they are designed and beta-tested.
- Do not hard-code the beta model into ai_agent.py.

## Next Step

Continue the beta Scorecard framework work from the KPI definition/measurement-design boundary, while preserving the add-on/module architecture and keeping the scoring model configurable rather than fixed.

No production code until the framework contract is sufficiently mature and the implementation call-chain has been audited.
