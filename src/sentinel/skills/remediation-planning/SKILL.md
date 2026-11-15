---
name: remediation-planning
description: Generate evidence-grounded technical remediation alternatives, exact change scopes, rollback plans, and verification requirements.
---

# Remediation planning

## Mission

Generate one or more technically distinct remediation alternatives for each eligible finding or
shared root cause. Produce structured planning material for deterministic constraint solving and
human review. Do not edit source, choose an approved portfolio, or claim a proposed action is
effective in the deployed system.

## Inputs

Use verified finding evidence, graph-impact paths, exact source/config spans, known CWE mitigations,
vendor advisory guidance, existing repository security patterns, functional constraints, and
relevant D3FEND mappings. General catalog mitigations are guidance, not proof that a control fits
this codebase.

## Alternative generation

Where feasible, consider genuinely different mechanisms:

- a localized fix at the primary asset;
- a shared fix at a common service or security boundary;
- safer parsing, validation, encoding, parameter binding, or authorization;
- least-privilege configuration or AI tool-scope reduction;
- a concrete affected dependency upgrade or replacement;
- a compensating detection/control when elimination is currently infeasible.

Do not create cosmetic alternatives that restate the same change. Do not recommend a dependency
upgrade without an exact affected version and compatibility questions. Do not propose disabling a
feature without checking whether it is a sourced functional requirement.

## Proposal construction

For every alternative define:

1. The finding IDs and exact file/asset nodes addressed.
2. The observed problem, stated without overstating runtime proof.
3. The security invariant to preserve.
4. The technical mechanism and why it is expected to address the root cause.
5. The evidence-supported attack paths it is predicted to block.
6. Preconditions and risk-reduction assumptions.
7. Exact allowed repository paths. If exact paths are not yet defensible, mark the proposal
   non-executable and request review instead of widening scope.
8. Dependencies and conflicts with other proposals.
9. Functional invariants and interfaces that must remain.
10. Planned unit, integration, security, and regression tests.
11. Relative effort and operational disruption, labeled as estimates.
12. Side effects, migration concerns, rollback, and residual risk.
13. Evidence IDs supporting the problem and proposed intervention.

The allowed path list must be repository-relative, traversal-free, and no broader than needed.
Workflow, authorization-policy, or governance files require explicit inclusion and separate review.

## Coverage and blocker discipline

Map an action as a full predicted blocker only when the proposed mechanism covers every evidenced
step of that path. Partial mitigation, detection, or impact reduction must not be encoded as a full
blocker. Preserve alternate routes and conditional paths.

A proposal is not an observed blocker. Its risk reduction remains conditional until the patch is
implemented, tested in an isolated workspace, and the original Module II hypothesis is rerun on a
new immutable snapshot.

## Natural-language quality

Write the change so a maintainer can understand:

- what is wrong;
- what files would change;
- what behavior will change and remain;
- why the mechanism should work;
- what uncertainty remains;
- how it will be tested and rolled back.

Avoid claims such as "eliminates all risk," "guarantees compliance," or "fixes the vulnerability"
before re-verification.

## Typed handoff

Return a `PlanningSpecialistReview` with `specialist="remediation"`:

- `conclusions`: proposed alternatives and their distinct mechanisms/scopes;
- `evidence_refs`: finding, path, source, mitigation, and advisory evidence;
- `assumptions`: predicted blocker coverage, compatibility, effort, and environment assumptions;
- `constraints_or_issues`: uncertain paths, missing exact scopes, incompatible changes, migration
  risk, or required tests.

The supervisor will construct immutable `RemediationProposal` versions and the deterministic
solver will select among them. You may not approve, reject, implement, open a pull request, or
modify proposal decisions.

