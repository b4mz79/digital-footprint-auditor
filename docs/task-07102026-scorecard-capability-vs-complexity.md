# Checkpoint — Scorecard OSS Capability vs Complexity Evaluation

Date: 2026-10-07
Branch: feat/evidence-enrichment-foundation

## Status

The Scorecard semantic/compatibility evaluation phase is CLOSED/FROZEN for the next decision task.

The three OSS candidates evaluated so far are:
- GoRules ZEN 2.1.2
- python-jsonlogic 0.2.0
- simpleeval 1.0.8

All three currently occupy the same architectural verdict:
- conditional calculation primitive
- compatible with the frozen reference semantics on the evaluated path
- none selected as the Scorecard Engine

The existing evaluation successfully established compatibility, but it does **not** yet answer the actual architecture-selection question:

> What capability does each OSS candidate provide, and what technical complexity must Privacy Auditor pay to obtain and maintain that capability?

## Why the next task exists

The current three-way result is effectively a tie at the compatibility level.

The next task must therefore compare:

CAPABILITY PROVIDED
+
COMPLEXITY / COST WE MUST PAY
+
CAPABILITY GAP WE STILL HAVE TO BUILD
→ ARCHITECTURAL TRADE-OFF
→ OSS SHORTLIST / SELECTION DECISION

This is a separate evaluation task. Do not expand the frozen generic semantic test suite unless a concrete blocking gap is discovered.

## Next task — Capability vs Complexity

Evaluate each candidate against the actual Scorecard Add-on domain/roadmap, not generic library marketing.

Capability areas to investigate include, as applicable:
1. arithmetic/calculation
2. formula composition
3. conditional calculation
4. nested calculation
5. aggregation
6. dependency/interlink
7. expression validation
8. rule/policy execution
9. definition/version isolation
10. deterministic replay
11. error/failure semantics
12. serialization/persistence
13. execution lifecycle
14. extensibility
15. performance/scalability

For each capability, distinguish whether it is:
- NATIVE
- SUPPORTED
- SUPPORTED WITH ADAPTER
- SUPPORTED WITH SIGNIFICANT ADAPTER
- MUST BUILD OURSELVES
- NOT SUITABLE

Complexity/cost dimensions should include:
- adapter/domain translation
- dependency footprint
- runtime footprint
- lifecycle complexity
- error mapping
- upgrade risk
- library/vendor coupling
- testing burden
- operational burden
- maintenance burden

Do not assign arbitrary numerical weights merely to manufacture a winner. First produce a qualitative capability-vs-complexity trade-off. A formal weighted decision model should only be introduced if the qualitative comparison still leaves candidates genuinely close.

## Architectural boundary

The Scorecard remains an independent, self-contained add-on module.

The OSS candidate, if selected, is a calculation/rule primitive inside our architecture. It does not own Privacy Auditor domain semantics.

Our architecture remains responsible for:
- UNKNOWN / partial semantics
- measurement semantics
- scorecard definitions
- weights and aggregation semantics
- contribution semantics
- calculation lineage/provenance
- version isolation and reproducibility
- risk policy semantics
- final ScorecardResult contract

Existing Privacy Auditor providers remain adapters/sources. Scorecard must remain independently invokable from canonical Scorecard Input.

## Current evidence baseline

The frozen semantic compatibility harness and native reference engine remain the oracle.

Candidate-specific evaluations completed:
- ZEN: conditional calculation primitive
- python-jsonlogic: conditional calculation primitive
- simpleeval: conditional calculation primitive

Current candidate evaluation artifacts:
- tests/scorecard/engines/zen.py
- tests/scorecard/engines/python_jsonlogic.py
- tests/scorecard/engines/simpleeval.py
- tests/scorecard/test_zen_evaluation.py
- tests/scorecard/test_python_jsonlogic_evaluation.py
- tests/scorecard/test_simpleeval_evaluation.py
- tests/scorecard/compatibility.py
- tests/scorecard/oss_evaluation_matrix.json
- tests/scorecard/OSS_EVALUATION_REPORT.md
- tests/scorecard/requirements-scorecard-oss.txt

The Scorecard test suite was reported by the user as 100% PASS before this checkpoint.

## Freeze rule

Do not continue expanding tests merely because more dimensions can be imagined.

Only add/modify tests if the capability-vs-complexity investigation identifies a concrete semantic or architectural gap that blocks a defensible candidate decision.

## Next deliverable

Produce an internal evaluation artifact that makes the following directly answerable:

1. What capability do ZEN, python-jsonlogic, and simpleeval actually buy us?
2. What would we still have to build ourselves with each?
3. What complexity does each introduce?
4. Which candidate gives the best capability/complexity trade-off for the current Scorecard Add-on architecture?
5. Is an OSS primitive actually worth adopting, or is native implementation simpler overall?

No final engine selection is implied by this checkpoint.
