# Scorecard OSS Evaluation — GoRules ZEN

Status: **EVALUATED — CONDITIONAL CALCULATION PRIMITIVE**

Candidate: **GoRules ZEN / `zen-engine==2.1.2`**

## Purpose

This report records the first concrete OSS candidate evaluation against the frozen Scorecard semantic contracts.

The evaluation is **not** a production Scorecard Add-on implementation and is **not** an adoption decision.

The native reference engine remains the semantic oracle. GoRules ZEN is evaluated only through a candidate-specific adapter.

## Evaluation result

The current evidence supports:

> **ZEN is compatible as a calculation primitive for the evaluated weighted-sum path, with acceptable dependency/operational characteristics for further consideration.**

It does **not** support:

> "ZEN is the selected Scorecard Engine."

The distinction is intentional.

The current adapter evaluates calculation semantics. Policy rule-resolution semantics remain domain-owned and are not delegated to ZEN by this candidate artifact.

## Evidence matrix

| Dimension | Result | Evidence / interpretation |
|---|---|---|
| Calculation semantics | **PASS** | ZEN weighted-sum output matches the frozen Native Reference result. |
| UNKNOWN / partial semantics | **PASS WITH DOMAIN ADAPTER** | UNKNOWN is intercepted before engine evaluation; no implicit zero/imputation is introduced. |
| Determinism | **PASS** | Repeated evaluation with identical input/configuration returns identical semantic output. |
| Lineage | **PASS WITH DOMAIN ADAPTER** | Canonical lineage is reconstructed from declared KPI inputs; lineage remains a Scorecard-domain concern. |
| Contribution | **PASS WITH DOMAIN ADAPTER** | Weighted contribution details are reconstructed from canonical inputs/weights and match the reference result. |
| Version isolation | **PASS WITH DOMAIN ADAPTER** | Different calculation definitions remain isolated between evaluations; scorecard version binding remains domain-owned. |
| Adapter complexity | **ACCEPTABLE WITH CAVEAT** | Adapter is small, but it must construct a JDM graph and reconstruct domain metadata. |
| Dependency cost | **ACCEPTABLE FOR EVALUATION** | Candidate-only pinned dependency; published 2.1.2 wheels are available for Windows/Linux/macOS. |
| Operational cost | **ACCEPTABLE FOR EVALUATION** | Rust core/native Python binding with prebuilt wheels; no Rust toolchain required for normal wheel installation. |
| Policy resolution | **NOT EVALUATED AS CANDIDATE-OWNED SEMANTICS** | Current adapter does not delegate rule ordering or MATCH/NO_MATCH/UNKNOWN policy semantics to ZEN. |

## Detailed evidence

### 1. Calculation semantics — PASS

The candidate adapter translates the Scorecard weighted-sum operation into a ZEN expression graph.

The differential test compares:

```
Native Reference → EvalResult
ZEN Adapter     → EvalResult
                  ↓
             compatibility comparator
```

The evaluated case:

- `a = 10`, weight `0.6`
- `b = 4`, weight `0.4`
- expected result = `7.6`
- contributions = `6.0 + 1.6`

The candidate matches the frozen reference contract.

Evidence:

- `tests/scorecard/engines/zen.py`
- `tests/scorecard/test_zen_evaluation.py::test_zen_weighted_sum_matches_native_reference`

### 2. UNKNOWN / partial semantics — PASS WITH DOMAIN ADAPTER

This is deliberately **not** delegated to the OSS engine.

When a canonical measurement is UNKNOWN, the adapter does not pass a fabricated numeric zero to ZEN. It preserves the domain UNKNOWN result and the declared lineage.

This is important because:

- UNKNOWN ≠ FALSE
- UNKNOWN ≠ 0
- UNKNOWN must not silently become observed data

The test proves candidate output remains compatible with the frozen reference semantics.

Evidence:

`tests/scorecard/test_zen_evaluation.py::test_zen_weighted_sum_preserves_domain_unknown_semantics`

The distinction matters: this is a **domain compatibility result**, not evidence that ZEN natively implements our UNKNOWN/partial model.

### 3. Determinism — PASS

The same candidate adapter instance is evaluated twice with the same measurements and weights.

The semantic results are identical.

Evidence:

`tests/scorecard/test_zen_evaluation.py::test_zen_weighted_sum_is_deterministic_for_repeated_evaluation`

This satisfies the current deterministic calculation requirement for the evaluated primitive.

### 4. Lineage — PASS WITH DOMAIN ADAPTER

The Scorecard domain owns lineage.

ZEN returns the arithmetic result; the adapter reconstructs:

```
declared KPI IDs
      ↓
Scorecard EvalResult.lineage
```

This is preferable to allowing an engine-specific trace format to become the Scorecard contract.

Evidence:

- frozen `engine_contract.py`
- frozen `compatibility.py`
- `tests/scorecard/test_zen_evaluation.py`

### 5. Contribution — PASS WITH DOMAIN ADAPTER

Contribution semantics are also domain-owned.

For the evaluated case:

```
a: 10 × 0.6 = 6.0
b:  4 × 0.4 = 1.6
total = 7.6
```

The adapter reconstructs the canonical `ContributionDetail` objects and the differential contract accepts them.

Evidence:

`tests/scorecard/test_zen_evaluation.py::test_zen_adapter_reconstructs_contribution_semantics_from_domain_inputs`

This avoids coupling Scorecard contribution semantics to an engine-specific explanation/trace format.

### 6. Version isolation — PASS WITH DOMAIN ADAPTER

The candidate is evaluated with two different weight definitions using the same adapter instance:

- definition A → `0.6 / 0.4` → `7.6`
- definition B → `0.2 / 0.8` → `5.2`

The second evaluation does not inherit the first definition.

Evidence:

`tests/scorecard/test_zen_evaluation.py::test_zen_adapter_keeps_definition_inputs_isolated_between_evaluations`

This is evidence of calculation-definition isolation. The authoritative Scorecard `scorecard_version` binding remains outside ZEN.

### 7. Adapter complexity — ACCEPTABLE WITH CAVEAT

The candidate adapter is intentionally isolated under:

`tests/scorecard/engines/zen.py`

It does not modify:

- Scorecard contracts
- reference semantics
- production pipeline
- production dependencies
- domain risk policy

The main cost is translation:

```
Scorecard semantic operation
        ↓
candidate adapter
        ↓
ZEN JDM graph / expression
        ↓
ZEN result
        ↓
candidate adapter
        ↓
Scorecard EvalResult
```

The adapter therefore remains a real integration boundary rather than allowing ZEN's internal model to leak into the domain.

Caveat: the current implementation constructs the candidate decision graph for the evaluated calculation path. A production implementation would need to assess decision compilation/reuse and configuration lifecycle before adoption.

### 8. Dependency cost — ACCEPTABLE FOR EVALUATION

The candidate is pinned separately in:

`requirements-scorecard-oss.txt`

with:

```
zen-engine==2.1.2
```

Current PyPI metadata for 2.1.2 reports:

- MIT license
- Rust core with native Python bindings
- Python >= 3.7
- prebuilt wheels for Windows x86-64, Linux x86-64/ARM64, and macOS architectures
- Windows x86-64 wheel: approximately 11.0 MB
- Linux x86-64 wheel: approximately 10.7 MB

This is acceptable for candidate evaluation.

It is **not** yet a production dependency decision.

### 9. Operational cost — ACCEPTABLE FOR EVALUATION

ZEN is an embeddable native rules engine with prebuilt wheels, which reduces installation friction compared with requiring a local Rust build toolchain.

The current evaluation also keeps the dependency outside the normal Privacy Auditor runtime dependency set.

Operational questions intentionally left for a later adoption review include:

- compiled-decision lifecycle/reuse strategy
- process/resource behavior under expected Scorecard workloads
- packaging impact
- production upgrade policy
- failure/error mapping into Scorecard contracts

These are adoption concerns, not reasons to alter the frozen semantic suite.

## Policy resolution boundary

The Scorecard policy contract defines semantics for:

- rule priority
- MATCH
- NO_MATCH
- CONDITION_UNKNOWN
- applied rule identity
- evaluated rule identity
- deterministic resolution

Those semantics are currently implemented by the domain-neutral reference policy engine.

The current ZEN candidate adapter **does not claim to replace that policy engine**.

Therefore:

**Policy resolution = not yet candidate-evaluated.**

This is deliberate. We do not turn a candidate's rule language into the Scorecard domain contract merely because the candidate is a business rules engine.

## Current verdict

### ZEN

**Conditional calculation primitive**

Meaning:

- ✅ passes the evaluated arithmetic compatibility gate
- ✅ preserves UNKNOWN at the domain adapter boundary
- ✅ deterministic for the evaluated path
- ✅ contribution and lineage can remain domain-owned
- ✅ calculation-definition isolation demonstrated
- ✅ dependency characteristics acceptable for further evaluation
- ⚠️ current evidence does not establish full Scorecard-engine compatibility
- ⚠️ policy-resolution execution is not delegated/evaluated
- ⚠️ no production adoption decision

## Candidate matrix

See:

`tests/scorecard/oss_evaluation_matrix.json`

Current candidates:

- Native Reference — baseline
- GoRules ZEN 2.1.2 — conditional calculation primitive
- python-jsonlogic — not evaluated
- simpleeval — not evaluated

## External candidate facts

Current package facts are based on the published `zen-engine 2.1.2` package metadata: MIT licensing, native Rust/Python implementation, prebuilt platform wheels, and the published wheel sizes.

These facts are external evaluation evidence, not project-domain semantics.

## Scope guard

This evaluation does not decide:

- production scorecard thresholds
- risk-band threshold values
- decay policy
- corroboration policy
- parked KPIs
- B2B/B2C product strategy
- OSS/commercial product boundary
- production adoption of ZEN

Those remain outside this evaluation artifact.

## Next candidate-evaluation step

The generic `tests/scorecard` semantic suite remains **frozen**.

No new generic semantic test layer is required merely because ZEN has been evaluated.

The next OSS work should use the same frozen oracle and evaluate another candidate through a separate adapter, with the same compatibility/operational matrix.
