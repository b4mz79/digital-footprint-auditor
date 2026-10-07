# Scorecard OSS Selection Decision

Status: TECHNICAL SELECTION — PRE-PRODUCTION

Branch: feat/evidence-enrichment-foundation

Candidates evaluated:
- GoRules ZEN 2.1.2
- python-jsonlogic 0.2.0
- simpleeval 1.0.8
- Native reference engine

## Executive decision

**Preferred OSS calculation primitive: python-jsonlogic.**

The reason is not that it has the largest feature set. ZEN has the larger capability surface. The decision is based on the current Scorecard boundary: the project needs a serializable, deterministic calculation-definition primitive while retaining ownership of UNKNOWN/partial semantics, contribution semantics, lineage, version binding, risk policy, and final ScorecardResult.

python-jsonlogic supplies useful infrastructure around:
- serializable JSON expression representation
- operator-tree construction
- operator registry
- JSON-Schema-based typechecking
- diagnostics
- extensible/custom operators
- deterministic expression evaluation

Those capabilities reduce infrastructure that Scorecard would otherwise need to build, without forcing the Scorecard domain model into a full business-rules/decision-engine architecture. Its public documentation explicitly separates parsing, operator-tree construction, typechecking, diagnostics, and evaluation. citeturn0search4turn0search0turn0search2

**ZEN is the strategic second choice**, not a failed candidate. It becomes preferable if the Scorecard roadmap materially expands into a general decision/rule engine with native graph orchestration, decision tables, switches, reusable sub-decisions, policy documents, precompiled decisions, loaders, and batch execution. ZEN's Python binding is backed by a Rust engine and its public project documents these capabilities. citeturn1search0turn1search1

**simpleeval is not the preferred current choice.** It is attractive when minimum dependency and formula-only scope dominate, but it leaves too much of the surrounding Scorecard calculation infrastructure to be built by us. Its current PyPI release is 1.0.8 under MIT and targets Python >=3.9. citeturn1search9

**Native-only remains a valid fallback.** The OSS dependency is justified only if the selected primitive continues to remove more engineering burden than it introduces.

This is a technical selection decision, not production dependency approval. Production adoption remains gated by integration, security, packaging, reproducibility, and real representative Scorecard workloads.

## Final comparison matrix

Legend:
- NATIVE = directly supplied by candidate
- ADAPTER = candidate can execute it but Scorecard translation/domain code is required
- OURS = intentionally remains Scorecard-owned
- GAP = substantial infrastructure remains outside candidate
- CONDITIONAL = useful only under a stated roadmap condition

| Capability / cost | ZEN 2.1.2 | python-jsonlogic 0.2.0 | simpleeval 1.0.8 | Native |
|---|---|---|---|---|
| Arithmetic | NATIVE | NATIVE | NATIVE | NATIVE |
| Formula composition | NATIVE | NATIVE | NATIVE | NATIVE |
| Conditional calculation | NATIVE | NATIVE | NATIVE | NATIVE |
| Nested calculation | NATIVE | NATIVE | NATIVE | NATIVE |
| Aggregation | NATIVE/SUPPORTED | SUPPORTED/ADAPTER | ADAPTER/OURS | NATIVE |
| Dependency/interlink | NATIVE graph | ADAPTER | ADAPTER/OURS | OURS |
| Expression parsing | NATIVE | NATIVE | NATIVE | OURS |
| Expression validation | NATIVE | NATIVE | ADAPTER | OURS |
| Static/type checking | NATIVE | NATIVE | GAP | OURS |
| Rule/decision graph | NATIVE | GAP/ADAPTER | GAP | OURS |
| Reusable sub-decisions | NATIVE | ADAPTER | OURS | OURS |
| Portable definition representation | NATIVE | NATIVE | ADAPTER | OURS |
| Precompiled/reusable execution | NATIVE | ADAPTER/OURS | SUPPORTED | OURS |
| Batch execution | NATIVE | ADAPTER/OURS | OURS | OURS |
| Structured diagnostics | NATIVE | NATIVE | ADAPTER | OURS |
| Execution/error envelope | SUPPORTED | ADAPTER | ADAPTER | OURS |
| UNKNOWN semantics | OURS | OURS | OURS | NATIVE |
| Partial semantics | OURS | OURS | OURS | NATIVE |
| Contribution semantics | OURS | OURS | OURS | NATIVE |
| Calculation lineage | OURS + adapter | OURS + adapter | OURS + adapter | NATIVE |
| Version isolation | OURS | OURS | OURS | NATIVE |
| Risk policy | OURS | OURS | OURS | NATIVE |
| Final ScorecardResult | OURS | OURS | OURS | NATIVE |
| Adapter surface | Medium-High | Low-Medium | Low | None |
| Dependency/runtime footprint | Medium-High | Low-Medium | Low | Lowest |
| Domain coupling risk | Medium | Low | Low | Lowest |
| Future rule-engine headroom | High | Medium | Low | Depends on ours |
| Infrastructure still to build | Medium | Medium-High | High | High, but controlled |
| Overall capability | High | Medium | Low-Medium | Exact fit only |
| Overall complexity | Medium-High | Low-Medium | Low | Medium |
| Current trade-off | CONDITIONAL | **PREFERRED** | CONDITIONAL | **BASELINE/FALLBACK** |

## Eight-pass decision

### Pass 1 — Arithmetic correctness

All three OSS candidates can serve the basic calculation primitive.

**Result:** tie.

### Pass 2 — Formula vocabulary

The current reference semantics include sum/difference/ratio, normalization, aggregation, and dependency primitives.

ZEN has the broadest native expression environment. python-jsonlogic has a structured expression/operator model and can be extended through custom operators. simpleeval handles expression evaluation but does not supply the surrounding domain model.

**Result:** ZEN capability winner; python-jsonlogic sufficient for current direction.

### Pass 3 — Conditional calculation

Conditional calculation is required as soon as scorecard definitions contain conditional transformations or policy-adjacent calculation logic.

ZEN has first-class switches and decision tables. python-jsonlogic can express conditional logic but does not provide a decision graph. simpleeval can evaluate conditional expressions but leaves orchestration to us.

**Result:** ZEN capability winner; python-jsonlogic remains sufficient if conditional calculation is not confused with rule orchestration.

### Pass 4 — Aggregation and interlink

Aggregation is a calculation primitive. Interlink is more than arithmetic: it introduces dependency structure and calculation ordering.

ZEN is strongest because graph topology is native. python-jsonlogic can represent nested expression dependencies, but graph semantics must remain ours. simpleeval can calculate expressions but the dependency model must remain ours.

**Result:** ZEN wins capability; python-jsonlogic wins current boundary fit.

### Pass 5 — Validation and definition quality

This is where python-jsonlogic becomes materially stronger than a minimal evaluator. Its documented typechecking is JSON-Schema-based and produces diagnostics before evaluation. Custom operators can define syntax, typechecking, and evaluation behavior. citeturn0search0turn0search1

ZEN also has static analysis/type checking and diagnostics across policies/graphs. citeturn1search0

simpleeval does not provide an equivalent domain-oriented static typechecking layer.

**Result:** ZEN and python-jsonlogic lead; python-jsonlogic has the smaller fit-for-purpose surface.

### Pass 6 — Domain ownership

This is decisive for the Privacy Auditor Scorecard architecture.

The following must not migrate into an OSS engine:
- UNKNOWN vs FALSE semantics
- partial coverage semantics
- contribution semantics
- calculation lineage
- scorecard version binding
- risk policy
- final ScorecardResult
- historical reproducibility contract

All three candidates can be placed below that boundary, but ZEN's breadth creates a stronger temptation to let graph/rule semantics become engine semantics.

**Result:** python-jsonlogic has the cleanest current boundary fit.

### Pass 7 — Complexity paid vs infrastructure avoided

**ZEN:** pay a larger adapter/runtime/model surface, but receive substantial graph, rule, branching, reusable-decision and execution infrastructure.

**python-jsonlogic:** pay for expression translation, operator registration and domain error mapping, while receiving parsing, operator-tree construction, typechecking and diagnostics. citeturn0search4turn0search0

**simpleeval:** pay very little, but receive very little beyond expression evaluation; dependency/interlink, validation, definition lifecycle and structured semantics remain ours.

**Result:** python-jsonlogic has the best current capability/complexity ratio.

### Pass 8 — Strategic headroom

ZEN is the clear winner if the Scorecard becomes a general decision/rule platform. Its public Python SDK supports portable JSON decision definitions, reusable loaders, graph decisions and batch evaluation. citeturn1search0

That capability is valuable, but capability that is not currently required is also architectural surface.

**Result:** keep ZEN as the strategic alternative, not the current default.

## Why python-jsonlogic wins now

The selection is based on **capability purchased per unit of architectural complexity**, not feature count.

python-jsonlogic occupies the useful middle:

- more infrastructure than a bare expression evaluator
- less architectural commitment than a full rules/decision engine
- serializable definitions
- extensible operator model
- static typechecking and diagnostics
- deterministic evaluation
- easy placement below our domain semantics

The Scorecard remains the owner of meaning. python-jsonlogic becomes a calculation primitive, not the Scorecard engine itself.

## Why ZEN does not win now

ZEN is technically more capable.

It loses the current selection only because the extra capability is largely **decision-engine capability**, while the present architectural requirement is a **Scorecard calculation primitive**.

Adopting ZEN now would be justified if the project explicitly decides that graph-native decision orchestration is part of the Scorecard engine's near-term responsibility.

That decision has not been made.

## Why simpleeval does not win now

simpleeval wins the minimalism test.

It loses because the engineering saved at the expression-evaluation layer is not enough to offset the infrastructure still required for:
- definition validation
- dependency/interlink representation
- structured diagnostics
- calculation lifecycle
- portable definition semantics
- future calculation composition.

It remains useful as a fallback benchmark/reference primitive.

## Final shortlist

| Rank | Candidate | Decision |
|---|---|---|
| 1 | **python-jsonlogic** | **Preferred current OSS calculation primitive** |
| 2 | **GoRules ZEN** | Strategic alternative if decision/rule graph capability becomes required |
| 3 | **simpleeval** | Minimalist fallback for formula-centric scope |
| Baseline | **Native** | Always-retained reference and fallback |

## Adoption gate

The selection is **not yet a production dependency decision**.

Before production adoption, the preferred candidate must pass a focused implementation gate covering the real Scorecard vocabulary:

1. formula composition
2. aggregation
3. dependency/interlink
4. conditional calculation
5. normalization
6. version-isolated definition loading
7. deterministic replay
8. error/diagnostic mapping
9. representative UNKNOWN/partial inputs
10. calculation lineage reconstruction

The existing native reference engine remains the semantic oracle.

No new generic compatibility-suite expansion is justified unless this focused gate exposes a semantic or architectural blocker.

## Explicit non-decisions

This document does not decide:
- scorecard weights
- score thresholds
- risk bands or risk-policy thresholds
- evidence decay
- corroboration scoring
- B2C/B2B product strategy
- OSS/commercial product boundary
- production packaging approval
- final Scorecard UI/API design

Those remain outside the OSS calculation-primitive selection.

## Source basis

Public upstream documentation was used for candidate capability claims:
- GoRules ZEN Python SDK / engine documentation. citeturn1search0turn1search1
- python-jsonlogic usage, typechecking, evaluation, and custom-operator documentation. citeturn0search4turn0search0turn0search2turn0search1
- simpleeval current PyPI metadata. citeturn1search9

Repository-side evidence comes from the candidate adapters, frozen reference engine, compatibility harness, and candidate evaluation tests in `tests/scorecard/`.
