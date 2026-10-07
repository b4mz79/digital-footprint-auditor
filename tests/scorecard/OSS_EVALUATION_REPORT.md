# Scorecard OSS Evaluation — GoRules ZEN + python-jsonlogic + simpleeval

Status: **EVALUATED — THREE CONDITIONAL CALCULATION PRIMITIVES**

Candidates evaluated:
- **GoRules ZEN / zen-engine==2.1.2**
- **python-jsonlogic / python-jsonlogic==0.2.0**
- **simpleeval / simpleeval==1.0.8**

## Executive summary

This report is the decision record for the OSS calculation-primitive evaluation. The same frozen semantic contracts are applied to each candidate. The native reference engine remains the semantic oracle. User-run full Scorecard tests are 100% PASS.

**None of the three candidates is selected as the Scorecard Engine.**

### Executive decision table

| Area | GoRules ZEN | python-jsonlogic | simpleeval | Decision meaning |
|---|---|---|---|---|
| Arithmetic / calculation compatibility | **PASS** | **PASS** | **PASS** | All three match the frozen Native Reference for the evaluated weighted-sum path. |
| UNKNOWN / partial semantics | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | Domain semantics are preserved; no candidate is allowed to coerce UNKNOWN to zero. |
| Determinism | **PASS** | **PASS** | **PASS** | Repeated equivalent evaluation produces the same semantic result. |
| Lineage ownership | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | Scorecard lineage remains domain-owned. |
| Contribution semantics | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | Canonical contribution semantics remain domain-owned. |
| Definition / version isolation | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | **PASS WITH DOMAIN ADAPTER** | Calculation definitions remain isolated; authoritative Scorecard version binding remains domain-owned. |
| Adapter complexity | **ACCEPTABLE WITH CAVEAT** | **ACCEPTABLE WITH CAVEAT** | **ACCEPTABLE WITH CAVEAT** | All require an explicit translation boundary rather than leaking candidate semantics into the domain. |
| Dependency cost | **ACCEPTABLE FOR EVALUATION** | **ACCEPTABLE FOR EVALUATION** | **ACCEPTABLE FOR EVALUATION** | All are pinned candidate-only dependencies; simpleeval has the lightest pure-Python profile. |
| Operational cost | **ACCEPTABLE FOR EVALUATION** | **ACCEPTABLE FOR EVALUATION** | **ACCEPTABLE FOR EVALUATION** | ZEN uses native bindings; python-jsonlogic and simpleeval are pure Python. |
| Policy resolution | **NOT EVALUATED** | **NOT EVALUATED** | **NOT EVALUATED** | Policy semantics remain domain-owned and are not delegated by these adapters. |
| Production readiness | **NOT EVALUATED** | **NOT EVALUATED** | **NOT EVALUATED** | No production adoption or packaging decision has been made. |
| Overall candidate status | **CONDITIONAL CALCULATION PRIMITIVE** | **CONDITIONAL CALCULATION PRIMITIVE** | **CONDITIONAL CALCULATION PRIMITIVE** | All three remain candidates; none is selected. |

### Current decision

> **Keep GoRules ZEN, python-jsonlogic, and simpleeval as conditional calculation-primitive candidates. Do not select the Scorecard Engine yet.**

## What this evaluation actually proves

Across the focused calculation vocabulary, all three candidates reproduce the frozen Native Reference semantics while the Scorecard domain retains ownership of:
- UNKNOWN / partial semantics
- lineage
- contribution semantics
- Scorecard version binding
- policy semantics
- final domain contracts.

This is a compatibility result, not proof that any candidate natively implements the Scorecard domain model.

## What this evaluation does not prove

It does not establish:
- full Scorecard calculation coverage
- full formula/operator coverage
- production workload performance
- production packaging impact
- compiled-decision lifecycle/reuse suitability
- failure/error mapping completeness
- policy-engine compatibility
- historical/reproducibility behavior under a production result lifecycle
- final OSS engine selection
- production dependency approval.

## Percentage / scoring policy

**No official percentage is assigned.**

A percentage such as “85% suitable” would be misleading unless a formal weighted evaluation rubric had first been defined. The evaluation therefore uses explicit status gates instead of invented percentages.

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
| **simpleeval** | 1.0.8 | PASS | PASS + adapter | PASS | PASS + adapter | PASS + adapter | PASS + adapter | Acceptable + caveat | Acceptable for evaluation | Acceptable for evaluation | Not evaluated | **Conditional calculation primitive** |

**Rule:** each candidate gets its own adapter/evaluation tests. The frozen semantic contracts remain the oracle.

# Candidate 1 — GoRules ZEN

## Result

**Conditional calculation primitive**

Evaluated evidence:
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

ZEN is useful as an embedded calculation primitive for the evaluated path, but the adapter must keep domain semantics outside ZEN. The current implementation constructs a ZEN decision graph for the calculation and reconstructs domain metadata around it.

Evidence:
- tests/scorecard/engines/zen.py
- tests/scorecard/test_zen_evaluation.py
- requirements-scorecard-oss.txt

# Candidate 2 — python-jsonlogic

## Result

**Conditional calculation primitive**

Evaluated evidence:
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

The adapter translates weighted-sum semantics into a JsonLogic expression and evaluates it through python-jsonlogic. Canonical KPI IDs are emitted using JSON Pointer variable references where required by the candidate.

UNKNOWN is intercepted before candidate evaluation, so missing measurements are not converted into numeric zero.

Evidence:
- tests/scorecard/engines/python_jsonlogic.py
- tests/scorecard/test_python_jsonlogic_evaluation.py
- requirements-scorecard-oss.txt

# Candidate 3 — simpleeval

## Result

**Conditional calculation primitive**

Evaluated evidence:
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

### 1. Calculation semantics — PASS

The adapter translates the weighted-sum operation into a simpleeval expression and the result matches the frozen Native Reference.

Evaluated case:

    a = 10, weight = 0.6
    b = 4,  weight = 0.4
    10 × 0.6 + 4 × 0.4 = 7.6

Evidence:
- tests/scorecard/engines/simpleeval.py
- tests/scorecard/test_simpleeval_evaluation.py::test_simpleeval_weighted_sum_matches_native_reference

### 2. UNKNOWN / partial semantics — PASS WITH DOMAIN ADAPTER

UNKNOWN is handled before candidate evaluation. The adapter does not pass a fabricated numeric zero into simpleeval when a required measurement is UNKNOWN.

Therefore the evaluated path preserves:
- UNKNOWN ≠ 0
- UNKNOWN ≠ FALSE
- no implicit imputation.

Evidence: tests/scorecard/test_simpleeval_evaluation.py::test_simpleeval_preserves_domain_unknown_semantics

This is a domain compatibility result, not evidence that simpleeval natively implements the Scorecard UNKNOWN/partial model.

### 3. Determinism — PASS

Repeated evaluation with the same measurements and weights produces compatible semantic results.

Evidence: tests/scorecard/test_simpleeval_evaluation.py::test_simpleeval_weighted_sum_is_deterministic_for_repeated_evaluation

### 4. Lineage — PASS WITH DOMAIN ADAPTER

Canonical KPI IDs remain the Scorecard lineage. simpleeval is used only as the calculation primitive.

### 5. Contribution — PASS WITH DOMAIN ADAPTER

Contribution details are reconstructed from canonical inputs and weights:

    a: 10 × 0.6 = 6.0
    b: 4 × 0.4 = 1.6

The candidate arithmetic result is therefore not allowed to redefine Scorecard contribution semantics.

Evidence: tests/scorecard/test_simpleeval_evaluation.py::test_simpleeval_reconstructs_domain_contribution_semantics

### 6. Definition / version isolation — PASS WITH DOMAIN ADAPTER

The same adapter was evaluated with two calculation definitions:

    0.6 / 0.4 → 7.6
    0.2 / 0.8 → 5.2

The second evaluation does not inherit the first definition. Authoritative Scorecard version binding remains domain-owned.

Evidence: tests/scorecard/test_simpleeval_evaluation.py::test_simpleeval_keeps_definition_inputs_isolated_between_evaluations

### 7. Adapter complexity — ACCEPTABLE WITH CAVEAT

The adapter is isolated under tests/scorecard/engines/simpleeval.py. It is small, but it requires canonical KPI IDs used in the generated expression to be valid Python identifiers. The evaluated IDs satisfy that constraint.

This is a candidate translation constraint; it must not become a new Scorecard domain restriction without an explicit domain decision.

### 8. Dependency cost — ACCEPTABLE FOR EVALUATION

The candidate is pinned separately in requirements-scorecard-oss.txt as simpleeval==1.0.8.

The evaluated dependency is a small pure-Python package with an MIT license. Its package profile is materially lighter than the native ZEN dependency and avoids the platform-specific wheel profile of ZEN.

This remains candidate evaluation evidence, not production dependency approval.

### 9. Operational cost — ACCEPTABLE FOR EVALUATION

The candidate is pure Python and does not require a native build toolchain for normal installation.

The library's own published documentation warns that arbitrary or long-running expressions can have denial-of-service implications and that sandboxing cannot guarantee safety against all unsafe interpreter/object behavior. Therefore this evaluation does **not** treat simpleeval as a security sandbox. It is evaluated only as a calculation primitive over controlled expressions generated by the adapter.

Open adoption questions remain:
- broader formula/operator coverage
- expression lifecycle/reuse
- failure/error mapping
- performance under expected Scorecard workloads
- production packaging and upgrade policy
- whether controlled-expression generation remains sufficient as Scorecard semantics expand.

These are adoption questions and do not justify changing the frozen generic semantic suite.

# Policy resolution boundary

The Scorecard policy contract defines semantics for:
- rule priority
- MATCH
- NO_MATCH
- CONDITION_UNKNOWN
- applied rule identity
- evaluated rule identity
- deterministic resolution.

None of the current candidate adapters delegates those semantics to the OSS library.

Therefore:

> **Policy resolution = not yet candidate-evaluated.**

This is intentional. A candidate's expression/rules capability must not silently become the Scorecard domain contract.

# Current combined verdict

| Candidate | Current verdict | Keep evaluating? | Selected? |
|---|---|---:|---:|
| GoRules ZEN 2.1.2 | **Conditional calculation primitive** | Yes | **No** |
| python-jsonlogic 0.2.0 | **Preferred current OSS calculation primitive** | Yes — adoption/production gate | **Preferred** |
| simpleeval 1.0.8 | **Conditional calculation primitive** | Yes | **No** |
| Native Reference | **Baseline / semantic oracle** | N/A | **Not an adoption candidate** |

## Important comparison observation

At this stage, simpleeval has the lightest dependency/operational profile among the evaluated candidates, while python-jsonlogic also has a small platform-independent profile. ZEN provides a more structured native decision-engine model but introduces native bindings and platform-specific wheels.

These observations are **not** an engine-selection argument.

The focused calculation-vocabulary gate is complete. Remaining evidence is production/adoption-specific: workload performance, packaging, lifecycle/error mapping, security review, and future policy/expression requirements.

Therefore the current technical conclusion is:

> **All three candidates passed the focused compatibility gate. python-jsonlogic is the preferred current OSS calculation primitive; ZEN is the higher-capability strategic alternative; simpleeval is the minimalist fallback.**

# Scope guard

This evaluation does not decide:
- production scorecard thresholds
- risk-band threshold values
- decay policy
- corroboration policy
- parked KPIs
- B2B/B2C product strategy
- OSS/commercial product boundary
- production adoption of any candidate.

Those remain outside this evaluation artifact.

# Current evaluation state

The generic tests/scorecard semantic suite remains **frozen**.

No new generic semantic layer was added for simpleeval. Candidate-specific evidence remains isolated in:
- tests/scorecard/engines/simpleeval.py
- tests/scorecard/test_simpleeval_evaluation.py.

The three candidate adapters were evaluated against the same frozen oracle. Further OSS work should only add another candidate or address a blocking adoption gap, rather than expanding the generic suite simply because evaluation coverage has completed.
