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
IDs. Unresolved imports remain explicit, labeled `external_reference` (third-party or standard
library), `wildcard_package_import`, `ambiguous_java_reference`, or `unresolved_local_reference`.
A graph edge scopes investigation but never proves data flow, authorization failure, or
exploitability.

Phase 0 resolves statically, without executing or installing anything:

- Python: relative imports, absolute imports from the source directory, the repository root, or an
  intermediate service root with package evidence (`medium` confidence), `from pkg import module`
  submodules, and Django `path()`/`re_path()`/`include()` dispatch as `ROUTES_TO` edges.
- JavaScript/TypeScript: relative ES/CommonJS imports with `..` normalized. Bare specifiers and
  path aliases are treated as external.
- Java: fully qualified and static imports against `…/<package path>.java`; wildcard imports stay
  unresolved. Spring `@*Mapping` routes and path variables are extracted as features.
- Go: imports resolved through each `go.mod` module path to the package directory's non-test
  files (`medium`). Router registrations and path parameters are extracted as features.
- Manifests: each source file links to the primary manifest of its own ecosystem in the nearest
  ancestor directory. Graph walks never step back out of a manifest to its other dependents, so a
  project-wide manifest does not make every file "related".

Java and Go extraction is pattern-based (parser status `supported_partial`), not a full AST.

## Agent budgets and partitions

Every agent and specialist subagent runs under `ToolBudgetMiddleware`, which counts executed tool
calls per transaction. Calls over the profile budget are refused with an instruction to answer;
typed responses are produced by the model node, never by tool execution, so an agent over budget
can always return its result. A model that keeps calling tools after repeated refusals aborts the
transaction.

Under `balanced` and `deep`, the repository is partitioned deterministically (paths and file types
only) into service components plus one supporting partition for files outside any component that
holds source code. The graph agent and Module I run once per partition with discovery tools and
the asset catalog scoped to it; point lookups stay global for cross-component context.
A component with more parser hints than the profile's `partition_max_hints` (300) is split by
its next path level and sibling groups are packed back together up to the cap, for example
`services/identity/{.,gradle,src/main}` and `services/identity/src/test`.

The graph agent adjudicates parser edge hints by `H######` handle (`accepted_hint_refs`,
`rejected_hints`). Accepted hints are materialized with their original observed evidence and
location; unadjudicated hints are excluded and counted in coverage warnings. Module I returns an
OWASP API Top 10 `coverage_checklist` per partition (candidate emitted, examined, not applicable,
not examined); the orchestrator adds how many candidates map to each risk through official
references and CWE ancestry. The checklist is surfaced as `ScanBundle.module1_coverage` and is a
coverage record, never a safety claim.

Harness profiles that strip deepagents' filesystem and shell tools are registered under both the
requested model ID and the identifier the built client reports, because OpenAI-compatible clients
(for example Moonshot) report themselves as `openai:<model>`.

## Vulnerability knowledge graph

`G_V` is separate from the repository graph. The packaged snapshot is generated from complete,
version-pinned CWE, CAPEC, ATLAS, and D3FEND releases plus the OWASP API Security Top 10 (2023),
whose risks link to the CWEs OWASP cites through `REFERENCES_WEAKNESS`. Nodes retain their native namespace and
source metadata. Relations retain catalog direction and semantics, including CWE and CAPEC
hierarchies, `CAPEC -> CWE` mappings, ATLAS sub-technique/tactic relationships, case-specific
ordered technique use, and mitigation links.

ATLAS case order is stored as relationship metadata, not promoted into a universal prerequisite.
Shared weaknesses or packages never create `CVE -> CVE` edges. Relevant CVE List v5 records are
instead loaded as targeted overlays with `MAPPED_TO_WEAKNESS` and `AFFECTS_PRODUCT` relationships;
package advisories remain dependency/SBOM-targeted enrichments.

## Semantic boundary

Deterministic rules produce Module I *leads* only. With a model configured, Deep Agents
specialists (mapping, discovery, independent review) and a synthesis agent select the final
candidates, which may only be `candidate_status=potential`. Module II and III accept semantic
proposals only from `DeepAgentsRuntime`. The runtime disables the default general-purpose agent and
all shell/write/list/search filesystem tools. Its state filesystem contains packaged skills only;
source access is through bounded hash-verifying tools.

The coordinator validates every candidate, asset, path, finding, and evidence identifier. Invalid
Module II output becomes `not_analyzed`; it never silently falls back to a deterministic
vulnerability verdict.

## Repair, salvage, and failing closed

Each graph and Module I synthesis is checked against its contract and gets one repair round with
the concrete errors. If it is still invalid, salvage fails closed *per item* using the same checks:
unconnected related assets are stripped, candidates or edges that still break the contract are
dropped, unknown hint references are removed, and missing OWASP checklist entries become
`not_examined`. Every removal is named in coverage warnings and a `salvaged` run event. If even the
salvaged output is invalid (`ContractRepairFailed`), that partition fails closed: no candidates,
every OWASP risk `not_examined`, and an explicit "not analyzed" warning, while the scan continues.
Provider, timeout, authentication, and budget errors are not contract failures and still abort.

## Caches and run telemetry

Validated outputs are cached under `.sentinel/agent-runs`: specialist reviews, per-partition graph
and Module I syntheses, Module II reviews, and the Module III plan. Keys include the inputs, model
IDs, and every scan-profile field, so a budget change never reuses results produced under another
budget. Finding IDs are derived from snapshot and candidate, so cached reviews and plans keep
pointing at the same findings. The graph checkpoint records the profile it was actually built with.

Every scan records `run_metrics` (per stage: duration, model calls, tokens, tool calls, outcome)
and `run_events` (cache hits, contract errors, repairs, salvages, partitions failed closed, and
exhausted tool budgets with refusal counts) on the `ScanBundle`. `sentinel scan --progress` prints
them live. A stage counts as passed only at its `validated`, `repaired`, or `salvaged` event.

## Optimization and execution

Z3 minimizes supported residual exposure, then effort, then disruption. Blocker mappings remain
predicted until a patch is implemented and Module II runs again. Accept/reject/defer decisions are
hard constraints.

An acceptance event binds proposal digest/version, actor role, repository, base commit, exact paths,
operations, and expiry. The write gateway repeats all checks and is disabled unless
`ENABLE_SOURCE_WRITES=true`. A draft branch or PR is not a deployed resolution.

