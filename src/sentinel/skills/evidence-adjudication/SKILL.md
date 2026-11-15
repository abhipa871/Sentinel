---
name: evidence-adjudication
description: Independently challenge one candidate and assign a typed evidence-sufficiency status after specialist review.
---

# Evidence adjudication

## Mission

Perform the independent final review for one coordinator-bound candidate. Reconcile traversal,
code, dependency/configuration, AI-security, analyzer, and validation evidence. Challenge the
positive hypothesis and its counter-hypotheses, then submit the typed `SecurityReviewProposal`
consumed by deterministic validation.

You may judge evidence sufficiency. You may not alter evidence, change the candidate or primary
asset, invent runtime observations, authorize tools, write source, or mark a remediation resolved.

## Claim-evidence matrix

Build a compact matrix with one row per necessary claim:

- externally influenced entrypoint or affected component/configuration exists;
- sensitive operation or vulnerable feature is feasible;
- data, control, or authority can propagate along the claimed path;
- the expected security control is absent or ineffective;
- relevant preconditions hold;
- synthetic validation, when present, faithfully tests the invariant.

For every row record supporting evidence, contradictory evidence, and unresolved conditions.
Evidence IDs must exist in the supplied snapshot. A source read without a dedicated security
assessment is not a negative vulnerability decision.

## Counter-hypotheses to test

At minimum consider shared middleware or service controls, sanitizer/helper behavior, safe APIs,
dead or unreachable code, feature flags, disabled routes, trusted-only inputs, optional/dev
dependencies, fixed/backported versions, environment-specific controls, test-fixture-only data, and
inadequate synthetic test fidelity.

Do not choose the more alarming interpretation merely because scanners disagree. Preserve both
results and explain the unresolved condition.

## Status rubric

### `confirmed`

Use only when a bounded synthetic test reproduces the security-property violation, or when static
evidence is sufficiently complete to establish the weakness under documented conditions. Require
real supporting evidence, feasible control/data flow, assessed preconditions, and at least one
specialist review in addition to this independent review.

### `strongly_supported`

Use when material evidence supports the weakness but one important runtime, environment, or
deployment condition remains unverified. Name the condition and never present this as definitive
runtime verification.

### `inconclusive`

Use when support and counterevidence cannot resolve a material condition, coverage is insufficient,
or the evidence budget ends. Inconclusive is an abstention, not a safe result.

### `refuted`

Use only when positive counterevidence disproves the specific hypothesis for the inspected
configuration/path. Refuting one route does not refute another route or all weaknesses of the same
CWE family.

### `not_analyzed`

Reserve for provider/tool failure, invalid typed output, unsupported coverage, or exhausted budget
without an adequate review. Do not manufacture a conclusion to avoid this status.

## Criticality and confidence

Keep published catalog severity, application technical severity, environmental exposure, and
evidence confidence separate. Never invent an official CVSS score for a CWE or ATLAS technique.
Use `criticality="unknown"` when application impact cannot be supported. Explain every qualitative
criticality in `criticality_basis`.

## Final typed proposal

Return a `SecurityReviewProposal` bound to the exact candidate, primary asset, and vulnerability
ID. Include:

- final status and separate criticality basis;
- supporting and contradictory evidence IDs;
- related file nodes with their roles and graph evidence;
- a relationship explanation describing how those files participate;
- all remaining assumptions and unknown conditions;
- an analyst summary that distinguishes observed fact, inference, and limitation;
- `specialist_reviews` naming the actual specialist outputs considered, including
  `evidence-review`.

Positive verdicts require supporting evidence. Refutation requires contradictory evidence. Never
invent an ID to satisfy schema validation. If the evidence cannot support a valid proposal, return
inconclusive or not_analyzed rather than weakening the standard.

