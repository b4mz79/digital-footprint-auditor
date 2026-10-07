# Scorecard OSS Capability vs Complexity Evaluation

Status: TECHNICAL TRADE-OFF EVALUATION — PRE-SELECTION

Candidates: GoRules ZEN 2.1.2; python-jsonlogic 0.2.0; simpleeval 1.0.8.

## Decision question

The previous evaluation proved compatibility on the frozen weighted-sum path. It did not answer which candidate removes the most implementation burden for acceptable complexity.

No numerical suitability percentage is used. The comparison is qualitative.

## Executive result

| Candidate | What it primarily buys | Capability | Complexity | Domain work remaining |
|---|---|---|---|---|
| GoRules ZEN | Decision/rule engine, graph model, expressions, tables, functions, reusable sub-decisions, execution lifecycle | High | Medium-High | Medium |
| python-jsonlogic | Serializable expression model, operator registry, typechecking, diagnostics, evaluation | Medium | Low-Medium | Medium-High |
| simpleeval | Lightweight AST expression evaluation, operators, functions, names | Low-Medium | Low | High |

### Preliminary technical conclusion

python-jsonlogic currently has the strongest capability/complexity balance for the current Scorecard calculation direction.

This is a shortlist signal, not final adoption.

ZEN remains the strongest capability candidate if the roadmap expands toward a genuine decision/rule engine. simpleeval remains the minimalist option if the scope stays limited to formulas.

## Capability matrix

Status: NATIVE = candidate provides it; ADAPTER = translation/domain code required; OURS = must remain domain-owned.

| Capability | ZEN | python-jsonlogic | simpleeval |
|---|---|---|---|
| Arithmetic | NATIVE | NATIVE | NATIVE |
| Formula composition | NATIVE | NATIVE | NATIVE |
| Conditional calculation | NATIVE | NATIVE | NATIVE |
| Nested calculation | NATIVE | NATIVE | NATIVE |
| Aggregation | SUPPORTED | SUPPORTED/ADAPTER | ADAPTER |
| Dependency/interlink graph | NATIVE | ADAPTER | ADAPTER |
| Expression validation | NATIVE | NATIVE | ADAPTER |
| Static/type checking | NATIVE | NATIVE | NOT CORE |
| Rule/decision graph | NATIVE | ADAPTER | NOT CORE |
| Reusable sub-decisions | NATIVE | ADAPTER | OURS |
| Portable definition representation | NATIVE | NATIVE | ADAPTER |
| Precompiled/reusable execution | NATIVE | ADAPTER | SUPPORTED |
| Batch execution | NATIVE | ADAPTER | OURS |
| Error/execution lifecycle | SUPPORTED | ADAPTER | ADAPTER |
| UNKNOWN/partial semantics | OURS | OURS | OURS |
| Contribution semantics | OURS | OURS | OURS |
| Calculation lineage | OURS + adapter | OURS + adapter | OURS + adapter |
| Version binding | OURS | OURS | OURS |
| Risk policy | OURS | OURS | OURS |
| Final ScorecardResult | OURS | OURS | OURS |

## What ZEN buys

ZEN is materially more than an arithmetic evaluator. Its public project describes decision tables, switches, expressions, functions, reusable sub-decisions, policy documents, static analysis/type checking, pre-compilation, loaders and batch evaluation. Python has native bindings and published platform wheels.

That can eliminate meaningful future infrastructure around graph execution, branching, reusable decisions and execution lifecycle. The price is a larger architectural dependency and a richer translation boundary between Scorecard semantics and the ZEN decision model.

Assessment: highest capability, highest integration surface.

## What python-jsonlogic buys

python-jsonlogic provides a serialized expression model, operator registry, operator-tree construction, JSON-Schema-based typechecking, diagnostics, custom operators and evaluation.

This is a strong fit for a versioned calculation-definition layer without forcing the whole Scorecard architecture to become a business-rules engine. Domain semantics still remain ours.

Assessment: strongest current balance of useful capability versus integration complexity.

## What simpleeval buys

simpleeval provides a deliberately small AST expression evaluator with arithmetic/comparison operators, conditional expressions, custom operators/functions, variable/name resolution and reusable parsed expressions.

It is excellent as a formula primitive but leaves more infrastructure to Scorecard: expression schema/versioning, dependency model, validation policy, lifecycle, structured error semantics and any future rule/graph layer.

The project documents resource-exhaustion concerns for expensive expressions; it must therefore remain behind controlled expression generation and must not be treated as an arbitrary-code or public-input sandbox.

Assessment: lowest complexity, largest capability gap.

## Complexity trade-off

### ZEN
- Adds native runtime/binding and a larger decision-model surface.
- Requires JDM graph translation and candidate-specific error/lifecycle mapping.
- Can remove substantial future graph, branching, reusable-decision and batch infrastructure.

### python-jsonlogic
- Adds expression translation, operator-registry management and candidate-specific type/error mapping.
- Avoids building an expression parser, operator tree, typechecking foundation and diagnostics from scratch.
- Remains relatively small and platform-independent.

### simpleeval
- Very small adapter and dependency footprint.
- Avoids only the basic expression-evaluation plumbing.
- Leaves most higher-level calculation/dependency/lifecycle infrastructure to Scorecard.

## Five-pass assessment

### Pass 1 — Raw capability
Winner: ZEN.

### Pass 2 — Capability relevant to current Scorecard scope
Winner: python-jsonlogic.

### Pass 3 — Lowest complexity
Winner: simpleeval.

### Pass 4 — Infrastructure we avoid building if the roadmap expands
Winner: ZEN.

### Pass 5 — Overall architecture balance
Current leader: python-jsonlogic.

## Preliminary ranking

1. python-jsonlogic — preferred candidate for the current calculation direction.
2. GoRules ZEN — strategic alternative if graph/rule/execution capabilities become materially valuable.
3. simpleeval — minimalist fallback if the scope remains formula-centric.
4. Native-only — retained as the baseline and valid fallback if OSS adapter complexity stops paying for itself.

## What could change the ranking

ZEN moves ahead if graph-native orchestration, reusable sub-decisions, policy/rule execution, compiled reuse or batch execution become first-class requirements.

simpleeval moves ahead if Scorecard deliberately remains a narrow formula engine and dependency minimization dominates.

Native-only moves ahead if the required calculation vocabulary remains small enough that an OSS adapter saves less engineering than it adds.

## Next technical validation

Do not expand the generic semantic suite merely for coverage volume.

Use the existing frozen reference semantics and run one focused representative calculation-vocabulary evaluation covering:
- formula composition
- aggregation
- dependency/interlink
- conditional calculation.

The purpose is to verify whether the preliminary ranking survives real Scorecard operations, not to create another large compatibility framework.

## Evidence basis

Candidate capability claims are based on the public upstream documentation/repositories for ZEN, python-jsonlogic and simpleeval, plus the existing candidate adapters/tests in this repository.

Scope guard: this document evaluates technical capability and complexity only. It does not decide product strategy, OSS/commercial boundary, production dependency approval, scorecard weights, risk thresholds or rollout.