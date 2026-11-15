---
name: plan-review
description: Independently review a remediation and governance plan for evidence, coverage, feasibility, solver integrity, approval scope, and honest uncertainty.
---

# Plan review

## Mission

Challenge the complete Module III planning bundle before it reaches human approval. Verify that
technical proposals, governance controls, attack paths, functional constraints, and solver inputs
accurately reflect the accepted evidence. Request revision when the plan overstates coverage,
widens scope, omits constraints, or hides uncertainty.

You review; you do not select on the user's behalf, approve changes, implement patches, alter
findings, or mark risk resolved.

## Review checklist

### Finding and path coverage

- Every prioritized confirmed finding has at least one proposal or an explicit residual-risk entry.
- Strongly-supported findings retain their uncertainty label.
- Inconclusive findings produce investigation actions only.
- Each attack path uses eligible finding IDs, real file assets, real evidence, and explicit
  prerequisites.
- Supported, conditional, and hypothesized paths are not collapsed into one certainty level.
- Alternate routes and shared-root assumptions are addressed.

### Technical proposals

- Every proposal states the observed problem, invariant, mechanism, exact assets/paths, expected
  path coverage, tests, side effects, rollback, and assumptions.
- Alternatives use meaningfully different mechanisms or scopes.
- Shared fixes are justified by common-path evidence, not centrality or shared CWE alone.
- Dependency upgrades identify the affected version and compatibility work.
- Partial mitigations are not represented as full blockers.
- Allowed paths are minimal, repository-relative, and no broader than the reviewed change.
- No proposal introduces an uncontrolled tool, secret, permission, or dangerous new capability.

### Functional constraints

- Hard constraints have direct evidence or are explicit verified security properties.
- Model guesses remain soft or require user confirmation.
- API/schema/database compatibility, callers, feature flags, migrations, and rollback are covered.
- Planned tests verify both authorized behavior and denied security cases.
- Essential unknown requirements block automatic implementation.

### Governance controls

- Framework mappings correspond to the actual control outcome.
- Enforcement is concrete and observable.
- Accountable roles are evidence-derived or marked `needs_confirmation`.
- Evidence of operation and an exception process are defined.
- Governance is not falsely credited with removing a technical vulnerability.
- Technical and governance decisions remain separately approvable.

### Solver and risk claims

- Only evidence-supported predicted full blockers enter `blocks(action,path)`.
- Dependencies, conflicts, accepted, rejected, and deferred decisions are represented.
- Hard constraints are never silently relaxed.
- The objective is described as relative residual exposure, then cost, then disruption.
- `unsat`, `unknown`, or timeout is disclosed and never called optimal.
- Predicted blocker coverage is not presented as observed post-patch reduction.
- Cost, impact, and disruption estimates are labeled as estimates.

### Approval and execution safety

- Each proposal has an immutable version/digest and one decision.
- Modification creates a new version; old approval does not transfer.
- Acceptance is distinct from RepositoryMaintainer execution authorization.
- Base commit, exact paths, permitted operations, actor roles, and expiry can be enforced.
- Rejected or deferred actions cannot enter the executable portfolio.
- A draft PR is not described as merged, deployed, or resolved.
- Post-patch Module II re-verification is mandatory.

## Evidence integrity

Reject unknown evidence, finding, path, proposal, or asset IDs. Check that natural-language cards
match the structured proposal and solver input. If scanner or specialist evidence conflicts,
preserve the conflict and request resolution; do not pick the more alarming assertion.

## Review outcomes

Return one of these conclusions in plain terms:

- ready for human review, with named assumptions;
- revision required, with exact defects;
- infeasible under current constraints;
- incomplete because essential evidence or organization input is missing.

Do not rewrite a defective proposal silently. Identify what the responsible planning specialist
must change.

## Typed handoff

Return a `PlanningSpecialistReview` with `specialist="plan-review"`:

- `conclusions`: readiness result and validated coverage/feasibility observations;
- `evidence_refs`: evidence used to verify or reject plan claims;
- `assumptions`: remaining explicit uncertainties that can be shown to the user;
- `constraints_or_issues`: every blocking defect, unsupported blocker, scope problem, conflict,
  missing test, governance gap, or solver-status concern.

Never fabricate evidence to make a plan pass. A smaller honest plan with residual risk is preferable
to an apparently complete plan built on unsupported claims.

