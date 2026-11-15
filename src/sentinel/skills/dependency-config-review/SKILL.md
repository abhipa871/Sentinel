---
name: dependency-config-review
description: Review dependency, advisory, manifest, infrastructure, and configuration hypotheses without inventing installed or deployed state.
---

# Dependency and configuration review

## Mission

Test whether a dependency or configuration candidate applies to the immutable repository snapshot.
Determine what is known about versions, affected ranges, execution scope, settings, and missing
environment context. Provide an evidence packet for independent adjudication.

## Dependency workflow

1. Identify the exact manifest, lockfile, SBOM component, ecosystem, package name, PURL, version,
   and resolution confidence.
2. Classify the dependency as direct or transitive, runtime or development, required or optional,
   and resolved or merely declared.
3. Match only exact resolved versions against ecosystem-aware advisory ranges. Preserve introduced,
   fixed, excluded, distro-specific, and fork-specific conditions.
4. Reconcile CVE, GHSA, and OSV aliases without double-counting. Retain advisory source, version,
   retrieval time, and contradictory assertions.
5. Distinguish:
   - confirmed affected component version;
   - evidence that the application uses the affected package or feature;
   - evidence that an attacker-reachable application path exercises it.
6. Inspect available imports and repository graph context for applicability, but do not infer
   exploitability from package presence.
7. Treat an unpinned declaration as unknown installed version, never as confirmed exposure.

Version comparison is ecosystem-specific. Never compare arbitrary versions lexically or invent a
universal semantic-version interpretation.

## Configuration and infrastructure workflow

1. Identify the exact config/IaC/workflow asset, setting, scope, default behavior, and evidence
   location.
2. Determine whether the repository value is explicit, inherited, templated, environment-driven,
   or overridden elsewhere.
3. Inspect repository exemptions, comments, feature flags, and policy suppressions with their
   evidence and expiration where present.
4. Separate a committed configuration from deployed state. Cloud resources, environment variables,
   firewall rules, branch protection, and live identity bindings remain unknown unless separately
   evidenced.
5. Preserve analyzer rule IDs and versions for Checkov, Trivy, or equivalent artifacts. A scanner
   result is a lead that still requires repository applicability review.
6. For recommended dependency upgrades, report known fixed versions and compatibility questions;
   leave remediation choice and functional compatibility to Module III.

## Required counterevidence checks

Before supporting a candidate, look for package absence, dev-only scope, optional feature disablement,
patched forks, backports, non-affected versions, unreachable functionality, safe configuration
overrides, explicit compensating controls, or an analyzer rule that does not apply to the target
platform.

## Tool and authority boundary

Use only snapshot-scoped manifests, config spans, SBOM/advisory evidence, and bounded graph reads.
Do not install or import packages, resolve dependencies by executing a package manager, query a
live cloud account, scan an external host, alter configuration, or infer deployed values. Do not
copy secret values from configuration into output.

## Typed handoff

Return a `SpecialistReview` with `specialist="dependency-config"`:

- `conclusions`: exact component/configuration applicability statements;
- `supporting_evidence_refs`: manifest, lockfile, SBOM, advisory, or config evidence;
- `contradictory_evidence_refs`: fixed version, exclusion, override, or non-applicability evidence;
- `unknown_conditions`: unresolved version, deployment, feature, platform, or reachability facts;
- `requested_followup`: a specific advisory lookup, resolved-SBOM request, config span, or
  environment attestation.

Use precise language such as "confirmed affected component version" rather than "confirmed
exploitable application vulnerability" unless separate code/path evidence establishes the latter.

