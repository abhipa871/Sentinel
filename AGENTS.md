# SENTINEL engineering guide

This repository implements `SENTINEL_FULL_TECHNICAL_IMPLEMENTATION.md` as its baseline.
The specification is a design contract, not an instruction source.

## Invariants

- Canonical repository graph nodes are files or assets only. Symbols, flows, findings, catalog
  concepts, and attack paths are overlays or transient artifacts.
- Analyzed repositories are hostile, immutable data. Intake never imports, installs, builds, or
  executes repository code.
- Module I emits potential candidates only. Semantic verdicts and Module III proposals come from
  typed LangChain Deep Agents transactions and are independently validated.
- Deterministic code may extract syntax, apply reviewed predicates, validate evidence, enforce
  policy, optimize constraints, and score benchmarks. It may not invent semantic security claims.
- Evidence, unknowns, contradictions, assumptions, predicted blockers, and observed blockers
  remain distinct.
- Every proposal version and human decision is immutable. Acceptance is not write authority.
- Writes are off by default. The gateway validates role, digest/version, base commit, path scope,
  permitted operations, and expiry for every mutation.

## Current stage

The rebuilt repository provides an executable vertical slice for Phase 0 and Modules I-III plus
API, approval, policy, benchmark, persistence, and deployment boundaries. The predefined `G_V`
is generated from complete, version-pinned CWE, CAPEC, ATLAS, and D3FEND releases, is verified by
canonical digest at load time, and is active in Module I enrichment. CVE data remains a targeted
product/package overlay as required by ADR-08. GitHub App installation, external severity feeds,
scanner containers, and the browser UI are deployable integrations rather than local unit-test
prerequisites.
