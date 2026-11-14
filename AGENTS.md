# SENTINEL Module 1 Charter

This repository implements Module 1 from `SENTINEL_MODULE1_IMPLEMENTATION.md`. Its purpose is to analyze an authorized code source, construct an evidence-backed organizational dependency graph, reason backward from dangerous outcomes, evaluate hypothetical compromises, identify shared dependencies, compile bounded verification workflows, and report facts separately from hypotheses.

## Architecture that must not drift

1. Accept a public GitHub repository, a local repository directory, or a local source file. Acquisition is bounded, read-only, and never imports, builds, installs, or executes analyzed code.
2. Deterministic code may index syntax, hash evidence, validate schemas, evaluate Boolean formulas, enforce policy, cache results, and score benchmarks. It must not independently declare a vulnerability or semantic security relationship.
3. LangChain Deep Agents is required for semantic graph construction, vulnerability analysis, attack hypotheses, hypothetical-compromise analysis, verification planning, and scenario synthesis.
4. Agents submit typed proposals. They cannot mark a repository finding runtime-verified, invent evidence, access paths outside the snapshot, execute repository code, change policy, or directly run verification.
5. The JIT compiler and executor remain deterministic. A Deep Agents plan is never an authorization grant.
6. Preserve explicit AND/OR/NOT conditions and true/false/unknown semantics. A hypothetical compromise is an isolated assumption, never an observed fact.
7. Reports distinguish observed source spans, agent inference, assumptions, unknowns, synthetic-fixture results, and deployed runtime verification.
8. Generic vulnerability discovery precedes organizational dangerous-outcome mapping. Unmapped findings remain findings.
9. A source read is not a security decision. Coverage is complete only after a dedicated Deep Agents specialist submits a typed positive, counterevidence-backed negative, or inconclusive review.

## Module 1 sequence

1. Identify a dangerous outcome.
2. Build and enrich the organizational dependency graph from bounded source evidence.
3. Work backward to explicit attack prerequisites and alternate routes.
4. Evaluate assumed compromise of components, identities, or AI agents without mutating factual state.
5. Rank shared enabling dependencies and interruption candidates.
6. Compile typed, allowlisted investigation questions into a policy-checked DAG.
7. Produce the seven-field scenario report with evidence IDs and limitations.

## Agent hierarchy

The module1 supervisor delegates to source-intake, file-dependency, repository-dependency, security-finding, attack-path, hypothetical-compromise, verification-planning, scenario-reporting, and benchmark-analysis specialists. Each specialist receives only its required tools and packaged skills. Host filesystem, shell, arbitrary network, and repository execution tools remain unavailable.

## Benchmark contract

OWASP Benchmark Python predictions must be produced by the same Deep Agents finding path exposed by the CLI and API. Ground-truth labels, scorecards, category descriptions, and expected CWEs are excluded until predictions and their run manifest are frozen. Exact testcase/CWE scoring is deterministic. Public-suite results are regression measurements, not held-out accuracy claims.

Each benchmark testcase is an explicit analysis target and receives an isolated typed security review. Neutral deterministic syntax facts may focus the review but cannot assign a CWE or safety label. Missing and inconclusive reviews score as abstentions.

CVE-Bench remains an unscored compatibility preflight in Module 1 because its proof actions require runtime exploit authority outside this read-only analyzer.

## Change rule

Changes must preserve this charter, typed evidence provenance, and policy enforcement. If implementation convenience conflicts with these invariants, change the implementation rather than weakening the invariant.
