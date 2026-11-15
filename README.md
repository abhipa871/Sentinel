# SENTINEL

SENTINEL is an authorized, defensive repository analyzer implementing
`SENTINEL_FULL_TECHNICAL_IMPLEMENTATION.md`.

The executable core follows four hard boundaries:

1. The canonical repository graph contains files/assets only.
2. Module I creates potential vulnerability candidates with deterministic, inspectable rules.
3. Modules II and III require typed LangChain Deep Agents outputs for semantic security
   decisions and remediation synthesis.
4. Source changes are disabled by default and require immutable per-proposal approval plus an
   independent path/base-commit authorization check.

## Local setup

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest
.venv\Scripts\sentinel scan . --output artifacts\scan.json
```

Without `--model`, the `scan` command performs Phase 0 and Module I without executing analyzed code. Modules II
and III require a configured Deep Agents runtime. Source writes stay disabled unless the
independently tested write gateway is deliberately enabled.

## Scan profiles and models

`--profile fast|balanced|deep` (default `DEFAULT_SCAN_PROFILE`, else `balanced`) sets enforced
tool-call budgets for every agent, the candidate budget, and whether the graph and Module I agents
run once per repository component. `balanced` and `deep` partition the repository by service
(the shallowest folder holding a manifest or Dockerfile), so each service gets its own budget.

```powershell
sentinel scan https://github.com/OWASP/crAPI --through module3 --model openai:gpt-5.6-luna --profile balanced
```

`--model` takes any LangChain `provider:model` ID. OpenAI-compatible providers are routed through
the OpenAI client; `moonshot:kimi-k3` reads `MOONSHOT_API_KEY` (and optional `MOONSHOT_BASE_URL`).
Validated stage outputs (graph and Module I partitions, Module II reviews, the Module III plan) are
cached under `.sentinel/agent-runs`, keyed by inputs, models, and every profile field, so an
interrupted scan resumes where it stopped. `--progress` prints per-stage usage and repair, salvage,
cache, and budget events; the same data is saved as `run_metrics` and `run_events` in the output.
`--reasoning-effort` (default `auto`: `none` for OpenAI, provider default elsewhere) controls
model reasoning.

## Vulnerability knowledge graph

SENTINEL ships a checksum-verified predefined `G_V` built from the complete MITRE CWE 5.0,
CAPEC 3.9, ATLAS 2026.10, and D3FEND 1.6.0 catalogs, plus the OWASP API Security Top 10 (2023)
with its published CWE references (CC BY-SA 4.0; see `src/sentinel/knowledge_data/SOURCES.md`). Module I uses the same immutable knowledge
snapshot ID as its reviewed applicability rules and enriches candidates with exact typed catalog
relationships. CVEs are intentionally added only as targeted product/package overlays; the graph
never fabricates CVE-to-CVE attack chains.

Regenerate the packaged graph from official sources with:

```powershell
python scripts/build_vulnerability_graph.py
```

For a previously downloaded cache, add `--offline`; add `--refresh owasp_api` to fetch only the
OWASP source. Source URLs, versions, SHA-256 hashes, entity
counts, relation counts, and the parser version are embedded in every snapshot.

## Measuring coverage

`benchmarks/crapi/challenges.json` encodes the 18 challenges documented by OWASP crAPI at a pinned
commit. Score any scan bundle against it with:

```powershell
python scripts/score_challenge_coverage.py artifacts\scan.json
```

Scoring is category-level per service (a candidate or finding in the right service whose ID equals,
or is `REFERENCES_WEAKNESS`-linked to, an expected OWASP API risk or CWE). It compares runs; it does
not prove any finding.

See [architecture](docs/architecture/overview.md), the
[vulnerability graph contract](docs/architecture/vulnerability-graph.md), and the
[API contract](docs/api/v1.md).
