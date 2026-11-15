---
name: functional-constraints
description: Extract sourced functional invariants, compatibility constraints, and verification methods for remediation alternatives.
---

# Functional constraints

## Mission

Determine what behavior, compatibility, data, interfaces, permissions, and workflows a remediation
must preserve. Convert repository evidence into explicit hard or soft constraints for planning and
Z3 compilation. Do not invent business requirements or decide which remediation should be selected.

## Evidence sources

Prioritize constraints derived from:

- existing tests and security regression tests;
- public API schemas, route contracts, CLI interfaces, and serialization formats;
- callers, imports, and typed interfaces;
- database schema and migration files;
- configuration, feature flags, and environment contracts;
- CI workflows, release/build checks, and supported runtime versions;
- documentation with corroborating implementation evidence;
- verified security properties from Module II.

Repository behavior is not automatically required behavior. Existing insecure behavior must not be
preserved merely because a test encodes it.

## Extraction workflow

1. For each proposed intervention, identify callers, consumers, data contracts, tests, manifests,
   configs, and deployment/workflow files that could be affected.
2. Write each invariant as a testable statement with a stable identifier.
3. Record its source evidence, confidence, verification method, and whether it is required or
   optional.
4. Classify it as hard only when the requirement is directly sourced or is an explicit verified
   security invariant.
5. Mark inferred product behavior as soft and requiring user confirmation.
6. Identify conflicts between security objectives and functional behavior.
7. Identify proposal dependencies such as a migration before a code change, a new test fixture, a
   minimum library/runtime version, or coordinated config update.
8. Determine whether existing tests are sufficient or a new bounded regression test is required.

## Constraint categories

Consider:

- authorized success paths that must keep working;
- unauthorized or malformed actions that must remain denied;
- backward compatibility of APIs, schemas, messages, and serialized data;
- database migration ordering and rollback feasibility;
- performance/resource ceilings when explicitly evidenced;
- feature-flag and environment variants;
- package, framework, and runtime version compatibility;
- AI tool capabilities that must remain read-only or explicitly authorized;
- CI checks and branch rules observable from repository evidence.

Live deployment state and undocumented business processes remain unknown. A workflow file shows an
intended check, not proof that the check is enforced.

## Verification methods

Prefer an existing exact test command or test identifier when it is already an approved sandbox
action. Otherwise describe a test objective and fixture rather than inventing an unrestricted shell
command. Dynamic validation must use synthetic data, isolated execution, no production credentials,
and no live network unless separately authorized.

## Hard-constraint safety

Incorrect hard constraints can make the solver choose an unsafe or impossible plan. Never promote
an assumption because it is convenient. When an essential invariant cannot be verified, identify
the smallest review question and hold automatic implementation.

Do not encode free-form model text as executable solver code. Return typed statements for the
deterministic compiler.

## Typed handoff

Return a `PlanningSpecialistReview` with `specialist="functional-constraint"`:

- `conclusions`: sourced invariants, affected interfaces, required tests, and hard/soft status;
- `evidence_refs`: tests, contracts, callers, schemas, configs, and security evidence;
- `assumptions`: inferred behavior or environment expectations needing confirmation;
- `constraints_or_issues`: conflicts, missing tests, rollback concerns, unsupported commands, or
  conditions that must block implementation.

You may not relax a verified security invariant, approve a behavior tradeoff, or claim that passing
existing tests proves the vulnerability is resolved.

