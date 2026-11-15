# Architecture

SENTINEL is split into an immutable evidence pipeline and two independent mutation gates.

```text
bounded local/GitHub intake
  -> G_R file/asset graph
  -> G_V/T_A/T_C knowledge snapshot
  -> Module I potential candidates
  -> Module II Deep Agents isolated reviews
  -> detected findings + contradictions
  -> Module III Deep Agents planning
  -> deterministic Z3 portfolio
  -> immutable per-change decisions
  -> independent write gateway (disabled by default)
  -> post-change snapshot and Module II re-verification
```

## Canonical graph

`RepositoryAssetGraph` contains exactly one `Asset` per included path. Functions, classes,
source spans, taint steps, findings, CWE entries, attack paths, and remediation actions are never
canonical repository nodes. Static adapters may retain them as features or evidence and project
cross-file relationships back to asset edges.

All edges have a type, confidence, resolution method, exact source location, and immutable evidence
IDs. Unresolved imports remain explicit. A graph edge scopes investigation but never proves data
flow, authorization failure, or exploitability.

## Vulnerability knowledge graph

`G_V` is separate from the repository graph. The packaged snapshot is generated from complete,
version-pinned CWE, CAPEC, ATLAS, and D3FEND releases. Nodes retain their native namespace and
source metadata. Relations retain catalog direction and semantics, including CWE and CAPEC
hierarchies, `CAPEC -> CWE` mappings, ATLAS sub-technique/tactic relationships, case-specific
ordered technique use, and mitigation links.

ATLAS case order is stored as relationship metadata, not promoted into a universal prerequisite.
Shared weaknesses or packages never create `CVE -> CVE` edges. Relevant CVE List v5 records are
instead loaded as targeted overlays with `MAPPED_TO_WEAKNESS` and `AFFECTS_PRODUCT` relationships;
package advisories remain dependency/SBOM-targeted enrichments.

## Semantic boundary

Module I is deterministic and may only emit `candidate_status=potential`. Module II and III accept
semantic proposals only from `DeepAgentsRuntime`. The runtime disables the default general-purpose
agent and all shell/write/list/search filesystem tools. Its state filesystem contains packaged
skills only; source access is through bounded hash-verifying tools.

The coordinator validates every candidate, asset, path, finding, and evidence identifier. Invalid
output becomes `not_analyzed`; it never silently falls back to a deterministic vulnerability
verdict.

## Optimization and execution

Z3 minimizes supported residual exposure, then effort, then disruption. Blocker mappings remain
predicted until a patch is implemented and Module II runs again. Accept/reject/defer decisions are
hard constraints.

An acceptance event binds proposal digest/version, actor role, repository, base commit, exact paths,
operations, and expiry. The write gateway repeats all checks and is disabled unless
`ENABLE_SOURCE_WRITES=true`. A draft branch or PR is not a deployed resolution.

