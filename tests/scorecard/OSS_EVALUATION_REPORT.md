# Scorecard OSS Evaluation — Readiness Report

Status: **EVALUATION READY**

## Purpose

This suite is the semantic oracle for evaluating an external OSS calculation/policy engine against the Privacy Auditor Scorecard domain contract.

It is **not** an implementation of the production Scorecard Add-on and it does not select an OSS engine in advance.

## What is already locked

- Scorecard data/assessment contract
- Measurement contract
- UNKNOWN semantics
- Partial aggregation semantics
- Calculation primitives
- Contribution semantics
- Normalization semantics
- Lineage/replayability
- Version isolation
- Scorecard result contract
- Risk policy contract
- Condition outcome semantics
- Policy rule-resolution semantics
- Engine-neutral calculation adapter contract
- Engine-neutral policy adapter contract
- Differential compatibility comparator
- Negative tests proving semantic divergence is rejected

## Evaluation flow

```
Canonical input / fixture
        |
        +--------------------+
        |                    |
        v                    v
Native Reference       OSS Candidate Adapter
        |                    |
        +---------+----------+
                  v
       Canonical semantic output
                  |
                  v
       Differential compatibility
             PASS / FAIL
                  |
                  v
       Candidate evaluation matrix
```

The native reference implementation is the baseline oracle. An OSS engine is evaluated through an adapter; its native API or internal semantics must not become the domain contract.

## Compatibility gate

A candidate is compatible only if it preserves the domain semantics represented by the suite, including:

| Dimension | Required evaluation |
|---|---|
| Calculation | Same supported operation semantics |
| UNKNOWN / partial | No silent coercion or implicit imputation |
| Determinism | Same input/configuration produces reproducible output |
| Lineage | Required semantic lineage remains replayable |
| Contribution | Additive contribution semantics are preserved where applicable |
| Version isolation | Result can be tied to the exact scorecard definition/policy version |
| Policy resolution | Match/no-match/condition-unknown semantics remain distinct |
| Adapter complexity | Mapping does not leak candidate semantics into the domain |
| Dependency cost | Dependency footprint is acceptable |
| Operational cost | Runtime/deployment behavior is acceptable |

## Candidate matrix

See `oss_evaluation_matrix.json` for the machine-readable matrix.

Current state:

- **Native Reference** — baseline
- **GoRules ZEN** — not evaluated
- **python-jsonlogic** — not evaluated
- **simpleeval** — not evaluated

No candidate receives a positive adoption verdict before differential tests and operational review are completed.

## Evaluation evidence

For every candidate, record:

1. adapter implementation
2. fixtures/scenarios executed
3. compatibility result
4. semantic diffs, if any
5. determinism result
6. lineage/contribution result
7. dependency and operational observations
8. final recommendation

## Scope guard

This evaluation does not decide:

- production scorecard thresholds
- risk-band threshold values
- decay policy
- corroboration policy
- parked KPIs
- B2B/B2C product strategy
- OSS/commercial product boundary

Those remain outside this evaluation harness.

## Exit criterion

The test suite is considered ready for OSS evaluation when:

1. the full `tests/scorecard` suite passes;
2. the differential comparator can accept an equivalent candidate;
3. the differential comparator demonstrably rejects semantic divergence;
4. candidate-specific evaluation can be added through adapters without changing the domain contracts.

Once those conditions hold, the next work is **candidate evaluation**, not further expansion of the semantic test suite.
