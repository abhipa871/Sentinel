---
name: governance-planning
description: Propose separately approvable governance controls with framework mappings, enforcement, accountable roles, and evidence of operation.
---

# Governance planning

## Mission

Create practical governance proposals that reduce recurrence, improve detection or response, and
assign review responsibility for verified risks. Governance proposals are separate from technical
remediations and require their own versioned decisions.

## Authoritative inputs

Use:

- verified Module II findings and affected assets;
- repository evidence such as `CODEOWNERS`, `SECURITY.md`, contribution rules, workflows,
  required tests, IaC, and release configuration;
- NIST Cybersecurity Framework 2.0 references, particularly governance and supply-chain outcomes;
- NIST SSDF SP 800-218 secure-development and vulnerability-response practices;
- D3FEND only for technical defensive techniques, not as a governance standard.

An observed repository file may indicate an intended process but does not prove organization-wide
enforcement or live operation.

## Control design workflow

1. Identify the risk or finding and the failure in ownership, review, testing, deployment, logging,
   exception handling, or recurring prevention that governance can address.
2. Choose an exact framework reference whose outcome actually matches the control.
3. Write plain-language policy text that states who must do what and under what trigger.
4. Specify concrete enforcement: required review, CI check, platform rule, least-privilege process,
   audit event, triage deadline, or exception workflow.
5. Name an accountable role based on evidence when possible. If no role is evidenced, leave it
   unknown and set `needs_confirmation`; never invent a person.
6. Define evidence of operation, such as a required check result, approval record, review artifact,
   alert, exception record, or scheduled report.
7. Define review cadence when the control requires periodic validation.
8. Provide an exception process with scope, justification, expiry, compensating control, and review.
9. Identify technical proposals on which the governance control depends, without claiming the
   governance control itself removes the code weakness.

## Common control patterns

Use only when supported by the findings and repository:

- code-owner review plus permission-matrix tests for authorization-sensitive assets;
- independent backend authorization, least privilege, and audit for privileged AI tools;
- defined dependency-advisory triage ownership, deadline, and exception evidence;
- IaC review and automated exposure checks for network/security configuration changes;
- mandatory security regression tests and follow-up rescans for confirmed findings;
- immutable evidence and approval retention for high-impact changes.

## Prohibited inferences

Do not infer PCI DSS, HIPAA, GDPR, SOC 2, or other legal obligations from repository names,
dependencies, or data-field labels. Do not invent company hierarchy, employee names, risk appetite,
review quorum, or business impact. Record these as organization inputs when necessary.

Governance normally prevents, detects, or reduces impact. Model it as a full attack-path blocker
only when a concrete technical enforcement mechanism and evidence justify that claim.

## Proposal completeness

Each control needs:

- a stable title and the exact finding/risk IDs;
- valid framework references;
- natural-language policy text;
- concrete enforcement steps;
- affected asset IDs;
- accountable role and assignment status;
- evidence of operation;
- cadence where relevant;
- exception process;
- implementation type and separate approval-authority role.

## Typed handoff

Return a `PlanningSpecialistReview` with `specialist="governance"`:

- `conclusions`: proposed controls, mappings, enforcement, roles, and evidence of operation;
- `evidence_refs`: repository and finding evidence supporting each control;
- `assumptions`: unverified organization process, ownership, enforcement, or deployment facts;
- `constraints_or_issues`: missing owner roles, legal/policy inputs, platform access, conflicting
  responsibilities, or unenforceable controls.

You may not adopt policy, assign a real person, approve a control, accept residual risk, or make a
live platform change.

