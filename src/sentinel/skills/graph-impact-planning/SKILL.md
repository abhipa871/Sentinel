---
name: graph-impact-planning
description: Build evidence-supported attack-path overlays, affected corridors, and shared intervention points from verified findings.
---

# Graph impact planning

## Mission

Translate eligible Module II findings and the canonical file/asset graph into a bounded attack and
impact overlay for Module III planning. Identify shared root causes, affected paths, and candidate
intervention points. Do not modify the repository graph or claim that a proposed change actually
blocks a path.

Only `confirmed` and explicitly labeled `strongly_supported` findings are eligible for
remediation planning. Inconclusive findings may support investigation proposals, not prescriptive
patches.

## Graph and evidence boundaries

The repository graph contains file/asset nodes only. Attack steps, prerequisites, findings,
identities, business impacts, and remediation actions live in the planning overlay. File adjacency
is not a causal attack step. Use Module II source/sink, authorization, validation, and related-node
evidence to justify every corridor.

## Impact workflow

1. Load the primary and related assets for each eligible finding, including their typed roles and
   evidence IDs.
2. Reconstruct bounded entrypoint-to-sensitive-operation corridors from verified evidence and
   strong graph edges.
3. Attach explicit prerequisites such as attacker influence, actor identity, feature enablement,
   affected package version, missing control, or tool privilege.
4. Classify each path:
   - `supported`: material steps and prerequisites have evidence;
   - `conditional`: a specific environment or deployment condition remains unknown;
   - `hypothesized`: included only for sensitivity analysis because essential links are inferred.
5. Identify common implementation roots or sensitive operations shared by findings. Do not group
   findings merely because they share a CWE or severity.
6. Identify intervention points such as a shared service authorization boundary, common parser,
   centralized input validation, least-privilege tool registration, or dependency upgrade.
7. Trace dependents, callers, tests, manifests, and configs that constrain each intervention.
8. Flag missing edges, unsupported causal steps, and alternative routes that could bypass a local
   fix.

Cap path expansion and avoid all-path enumeration in cyclic graphs. Prefer a small set of distinct,
evidence-supported paths over many variations of the same corridor.

## AttackPath requirements

Each proposed path must contain:

- a stable `path_id`;
- the exact finding IDs it represents;
- ordered canonical asset IDs and referenced graph edges;
- explicit prerequisites and evidence IDs for those prerequisites;
- `supported`, `conditional`, or `hypothesized` exposure status;
- an ordinal impact weight only when its basis is documented.

Ordinal impact weights compare modeled paths; they are not probabilities, CVSS scores, or measured
business loss. Leave impact unknown or request review when evidence is absent.

## Shared intervention rules

A shared intervention is justified only when evidence shows that the same implementation boundary
is traversed by the relevant paths. Confirm that alternate routes do not bypass it. A central file
or high PageRank score alone is not a shared security control.

Mark blocker mappings as predicted planning assumptions. They become observed blockers only after
implementation and a new Module II run.

## Typed handoff

Return a `PlanningSpecialistReview` with `specialist="graph-impact"`:

- `conclusions`: candidate paths, asset roles, shared roots, intervention points, and bypasses;
- `evidence_refs`: exact finding, edge, and prerequisite evidence;
- `assumptions`: deployment, reachability, impact, and full-blocker assumptions;
- `constraints_or_issues`: missing links, conflicting paths, excessive graph breadth, or required
  clarification.

Do not write remediation text, approve actions, alter finding status, or claim real-world
exploitability beyond the evidence-supported conditions.

