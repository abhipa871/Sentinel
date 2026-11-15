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

The `scan` command performs Phase 0 and Module I without executing analyzed code. Modules II
and III require a configured Deep Agents runtime. Source writes stay disabled unless the
independently tested write gateway is deliberately enabled.

For an OpenAI-backed scan, copy `.env.example` to `.env` and set `OPENAI_API_KEY`.
The CLI loads `.env` from the current directory and preserves existing environment variables.

To use Kimi, add `MOONSHOT_API_KEY` to `.env` and pass `--model moonshot:kimi-k2.5`.

```powershell
.venv\Scripts\sentinel scan https://github.com/OWASP/crAPI --through module3 --model openai:gpt-5.6-luna --max-candidates 10 --output artifacts\crapi-openai-scan.json
```

Discovery, verification, and remediation agents can search the pinned MITRE CWE definitions
and read related mitigations through `search_weaknesses` and `knowledge_neighborhood`.
The catalog includes alternate terms, extended descriptions, consequences, detection guidance,
platforms, and mapping notes where supplied by MITRE. Agents must assess applicability against
repository evidence. The candidate limit bounds this run's scope, and coverage gaps appear in
the report.

## Vulnerability knowledge graph

SENTINEL ships a checksum-verified predefined `G_V` built from the complete MITRE CWE 5.0,
CAPEC 3.9, ATLAS 2026.10, and D3FEND 1.6.0 catalogs. Module I uses the same immutable knowledge
snapshot ID as its reviewed applicability rules and enriches candidates with exact typed catalog
relationships. CVEs are intentionally added only as targeted product/package overlays; the graph
never fabricates CVE-to-CVE attack chains.

Regenerate the packaged graph from official sources with:

```powershell
python scripts/build_vulnerability_graph.py
```

For a previously downloaded cache, add `--offline`. Source URLs, versions, SHA-256 hashes, entity
counts, relation counts, and the parser version are embedded in every snapshot.

See [architecture](docs/architecture/overview.md), the
[vulnerability graph contract](docs/architecture/vulnerability-graph.md), and the
[API contract](docs/api/v1.md).

## Hackathon website

The interactive asset graph demo is in [website/](website/README.md). Open `website/index.html` with `assets-data.js` in the same directory. The run button replays saved results; presentation labels and original verification outcomes are documented in the website README.
