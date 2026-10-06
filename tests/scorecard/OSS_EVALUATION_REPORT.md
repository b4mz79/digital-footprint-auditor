# Scorecard OSS Evaluation — GoRules ZEN + python-jsonlogic

Status: **EVALUATION IN PROGRESS — TWO CONDITIONAL CALCULATION PRIMITIVES**

Candidates evaluated:
- **GoRules ZEN / `zen-engine==2.1.2`**
- **python-jsonlogic / `python-jsonlogic==0.2.0`**

## Executive summary

This report is the decision record for the OSS calculation-primitive evaluation. The same criteria are applied to each candidate. The native reference engine remains the semantic oracle.

Neither evaluated candidate is selected as the Scorecard Engine.

### Executive decision table

| Area | GoRules ZEN | python-jsonlogic | Decision meaning |
|---|---|---|---|
| Arithmetic / calculation compatibility | **PASS** | **PASS** | Both match the frozen Native Reference for the evaluated weighted-sum path. |
| UNKNOWN / partial semantics | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | Domain semantics are preserved; neither candidate is allowed to coerce UNKNOWN to zero. |
| Determinism | **PASS** | **PASS** | Repeated equivalent evaluation produces the same semantic result. |
| Lineage ownership | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | Scorecard lineage remains domain-owned. |
| Contribution semantics | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | Canonical contribution semantics remain domain-owned. |
| Definition / version isolation | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | Calculation definitions remain isolated; authoritative Scorecard version binding remains domain-owned. |
| Adapter complexity | **ACCEPTABLE WITH CAVEAT** | **ACCEPTABLE WITH CAVEAT** | Both require an explicit translation boundary rather than leaking candidate semantics into the domain. |
| Dependency cost | **ACCEPTABLE FOR EVALUATION** | **ACCEPTABLE FOR EVALUATION** | Both are pinned candidate-only dependencies; python-jsonlogic is substantially smaller and platform-independent. |
| Operational cost | **ACCEPTABLE FOR EVALUATION** | **ACCEPTABLE FOR EVALUATION** | ZEN uses native bindings/prebuilt wheels; python-jsonlogic is pure Python. |
| Policy resolution | **NOT EVALUATED** | **NOT EVALUATED** | Policy semantics remain domain-owned and are not delegated by these candidate adapters. |
| Production readiness | **NOT EVALUATED** | **NOT EVALUATED** | No production adoption or packaging decision has been made. |
| Overall candidate status | **CONDITIONAL CALCULATION PRIMITIVE** | **CONDITIONAL CALCULATION PRIMITIVE** | Both remain candidates; neither is selected. |

### Current decision

> **Keep both GoRules ZEN and python-jsonlogic as conditional calculation-primitive candidates. Do not select the Scorecard Engine yet.**

The current evidence is deliberately narrower than engine adoption.

## What this evaluation actually proves

For the evaluated weighted-sum path, both candidates can reproduce the frozen Native Reference arithmetic while the Scorecard domain retains ownership of:

- UNKNOWN / partial semantics
- lineage
- contribution semantics
- Scorecard version binding
- policy semantics
- final domain contracts

This is a compatibility result, not proof that either candidate natively implements the Scorecard domain model.

## What this evaluation does not prove

It does **not** establish:

- full Scorecard calculation coverage
- full formula/operator coverage
- production workload performance
- production packaging impact
- compiled-decision lifecycle/reuse suitability
- failure/error mapping completeness
- policy-engine compatibility
- historical/reproducibility behavior under a production result lifecycle
- final OSS engine selection
- production dependency approval

## Percentage / scoring policy

**No official percentage is assigned.**

A percentage such as “85% suitable” would be misleading unless a formal weighted evaluation rubric had first been defined. The current evaluation therefore uses explicit status gates instead of invented percentages.

The comparison remains:

1. **Compatibility gate** — candidate must preserve frozen Scorecard domain semantics.
2. **Operational/adoption gate** — dependency, adapter, lifecycle, packaging, and operational trade-offs must be acceptable.
3. **Coverage gate** — evaluated capabilities must be sufficient for the intended calculation/policy scope.
4. **Production gate** — production readiness must be separately evidenced.

A candidate that passes only the evaluated compatibility path is **not** a selected engine.

# Candidate comparison record

| Candidate | Version | Calculation | UNKNOWN/Partial | Determinism | Lineage | Contribution | Version Isolation | Adapter | Dependency | Operations | Policy | Verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **GoRules ZEN** | 2.1.2 | PASS | PASS + adapter | PASS | PASS + adapter | PASS + adapter | PASS + adapter | Acceptable + caveat | Acceptable for evaluation | Acceptable for evaluation | Not evaluated | **Conditional calculation primitive** |
| **python-jsonlogic** | 0.2.0 | PASS | PASS + adapter | PASS | PASS + adapter | PASS + adapter | PASS + adapter | Acceptable + caveat | Acceptable for evaluation | Acceptable for evaluation | Not evaluated | **Conditional calculation primitive** |
| simpleeval | — | Not evaluated | Not evaluated | Not evaluated | Not evaluated | Not evaluated | Not evaluated | Not evaluated | Not evaluated | Not evaluated | Not evaluated | **Not evaluated** |

**Rule:** each candidate gets its own adapter/evaluation tests. The frozen semantic contracts remain the oracle.

# Candidate 1 — GoRules ZEN

## Result

**Conditional calculation primitive**

### Evaluated evidence

- Calculation semantics — **PASS**
- UNKNOWN / partial — **PASS WITH DOMAIN ADAPTER**
- Determinism — **PASS**
- Lineage — **PASS WITH DOMAIN ADAPTER**
- Contribution — **PASS WITH DOMAIN ADAPTER**
- Definition isolation — **PASS WITH DOMAIN ADAPTER**
- Adapter complexity — **ACCEPTABLE WITH CAVEAT**
- Dependency cost — **ACCEPTABLE FOR EVALUATION**
- Operational cost — **ACCEPTABLE FOR EVALUATION**
- Policy resolution — **NOT EVALUATED**

### Current interpretation

ZEN is useful as an embedded calculation primitive for the evaluated path, but the adapter must keep domain semantics outside ZEN. The current implementation constructs a ZEN decision graph for the calculation and reconstructs domain metadata around it.

The evidence does not establish full Scorecard-engine compatibility or production readiness.

### Evidence

- `tests/scorecard/engines/zen.py`
- `tests/scorecard/test_zen_evaluation.py`
- `requirements-scorecard-oss.txt`

# Candidate 2 — python-jsonlogic

## Result

**Conditional calculation primitive**

### 1. Calculation semantics — PASS

The adapter translates the Scorecard weighted-sum operation into a JsonLogic expression and evaluates it through python-jsonlogic.

The evaluated case is:

```
a = 10, weight = 0.6
b = 4,  weight = 0.4

10 × 0.6 + 4 × 0.4 = 7.6
```

The candidate result matches the frozen Native Reference through the existing compatibility comparator.

Evidence:

- `tests/scorecard/engines/python_jsonlogic.py`
- `tests/scorecard/test_python_jsonlogic_evaluation.py::test_python_jsonlogic_weighted_sum_matches_native_reference`

The candidate's published 0.2.0 documentation describes parsing a JSON Logic expression into an operator tree and evaluating it against data; the package also supports JSON-Schema-based typechecking. citeturn0search1turn0search6

### 2. UNKNOWN / partial semantics — PASS WITH DOMAIN ADAPTER

UNKNOWN is handled before candidate evaluation.

If one measurement is UNKNOWN, the adapter returns the domain UNKNOWN result instead of passing a fabricated numeric zero into python-jsonlogic.

Therefore:

- UNKNOWN ≠ 0
- UNKNOWN ≠ FALSE
- no implicit imputation occurs

Evidence:

`tests/scorecard/test_python_jsonlogic_evaluation.py::test_python_jsonlogic_preserves_domain_unknown_semantics`

This is a domain compatibility result, not evidence that python-jsonlogic natively implements the Scorecard UNKNOWN/partial model.

### 3. Determinism — PASS

Repeated evaluation with the same measurements and weights produces compatible semantic results.

Evidence:

`tests/scorecard/test_python_jsonlogic_evaluation.py::test_python_jsonlogic_weighted_sum_is_deterministic_for_repeated_evaluation`

### 4. Lineage — PASS WITH DOMAIN ADAPTER

The adapter retains KPI IDs as canonical lineage.

The candidate expression engine is therefore not allowed to define the Scorecard lineage contract.

Evidence:

`tests/scorecard/test_python_jsonlogic_evaluation.py::test_python_jsonlogic_weighted_sum_matches_native_reference`

### 5. Contribution — PASS WITH DOMAIN ADAPTER

Contribution details are reconstructed from canonical domain inputs:

```
a: 10 × 0.6 = 6.0
b:  4 × 0.4 = 1.6
total = 7.6
```

The candidate is used for arithmetic evaluation; contribution semantics remain domain-owned.

Evidence:

`tests/scorecard/test_python_jsonlogic_evaluation.py::test_python_jsonlogic_reconstructs_domain_contribution_semantics`

### 6. Definition / version isolation — PASS WITH DOMAIN ADAPTER

The same adapter is evaluated against two different calculation definitions:

```
0.6 / 0.4 → 7.6
0.2 / 0.8 → 5.2
```

The second evaluation does not inherit the first definition.

Evidence:

`tests/scorecard/test_python_jsonlogic_evaluation.py::test_python_jsonlogic_keeps_definition_inputs_isolated_between_evaluations`

This demonstrates calculation-definition isolation. Authoritative Scorecard version binding remains outside the candidate.

### 7. Adapter complexity — ACCEPTABLE WITH CAVEAT

The adapter is isolated under:

`tests/scorecard/engines/python_jsonlogic.py`

The translation path is:

```
Scorecard weighted-sum semantics
        ↓
candidate adapter
        ↓
JsonLogic expression
        ↓
python-jsonlogic operator tree
        ↓
candidate result
        ↓
candidate adapter
        ↓
Scorecard EvalResult
```

The adapter is small and does not modify Scorecard contracts or production pipeline behavior.

A specific integration detail was required for this candidate: KPI references are emitted using JSON Pointer form such as `/a`. The python-jsonlogic documentation defines JSON Pointer variable references as an alternative to its dot-like notation, including support for keys containing dots or slashes. citeturn0search2

This is an adapter concern, not a reason to change the Scorecard domain contract.

### 8. Dependency cost — ACCEPTABLE FOR EVALUATION

The candidate is pinned separately in:

`requirements-scorecard-oss.txt`

with:

```
python-jsonlogic==0.2.0
```

Published PyPI metadata for 0.2.0 reports:

- MIT license
- Python >=3.10
- OS-independent distribution
- 26.5 kB wheel
- 107.2 kB source distribution
- 133.7 kB total release size

citeturn0search0

This is attractive from a dependency-size and platform-neutrality perspective.

It is still **candidate evaluation evidence**, not production dependency approval.

### 9. Operational cost — ACCEPTABLE FOR EVALUATION

The published package is a `py3-none-any` wheel, so the candidate does not introduce a native platform wheel or Rust toolchain requirement for normal installation. citeturn0search0

The library also exposes an operator registry and extensible operator model, which may be relevant if future Scorecard expression coverage requires controlled domain-specific operators. citeturn0search3turn0search5

However, that capability has **not** been evaluated as a production extension strategy yet.

Operational questions still open:

- expression compilation/reuse lifecycle
- larger expression graphs
- failure/error mapping into Scorecard contracts
- performance under expected Scorecard workloads
- typechecking policy and whether it should be mandatory
- production packaging and upgrade policy

These are adoption questions and do not justify changing the frozen semantic suite.

# Policy resolution boundary

The Scorecard policy contract defines semantics for:

- rule priority
- MATCH
- NO_MATCH
- CONDITION_UNKNOWN
- applied rule identity
- evaluated rule identity
- deterministic resolution

Neither current candidate adapter delegates those semantics to the OSS library.

Therefore:

> **Policy resolution = not yet candidate-evaluated.**

This is intentional. A candidate's expression/rules capability must not silently become the Scorecard domain contract.

# Current combined verdict

| Candidate | Current verdict | Keep evaluating? | Selected? |
|---|---|---:|---:|
| GoRules ZEN 2.1.2 | **Conditional calculation primitive** | Yes | **No** |
| python-jsonlogic 0.2.0 | **Conditional calculation primitive** | Yes | **No** |
| Native Reference | **Baseline / semantic oracle** | N/A | **Not an adoption candidate** |
| simpleeval | Not evaluated | Pending | No |

## Important comparison observation

At this stage, python-jsonlogic has a potentially attractive **dependency/operational profile** relative to ZEN:

- python-jsonlogic: pure Python, `py3-none-any`, 26.5 kB wheel
- ZEN: native Rust core with platform-specific prebuilt wheels

But this is **not yet an engine-selection argument**.

The decisive missing evidence is calculation coverage beyond the single evaluated weighted-sum path, plus lifecycle/error behavior and any future policy/expression requirements.

Therefore the correct conclusion is:

> **python-jsonlogic has passed the same first compatibility gate as ZEN for the evaluated calculation primitive, but neither candidate has earned engine-selection status.**

# Scope guard

This evaluation does not decide:

- production scorecard thresholds
- risk-band threshold values
- decay policy
- corroboration policy
- parked KPIs
- B2B/B2C product strategy
- OSS/commercial product boundary
- production adoption of either candidate

Those remain outside this evaluation artifact.

# Current evaluation state

The generic `tests/scorecard` semantic suite remains **frozen**.

No new generic semantic layer was added for python-jsonlogic. Candidate-specific evidence remains isolated in:

- `tests/scorecard/engines/python_jsonlogic.py`
- `tests/scorecard/test_python_jsonlogic_evaluation.py`

The next OSS work should continue with the same frozen oracle and the same matrix, rather than expanding the generic suite simply because another candidate was added.
