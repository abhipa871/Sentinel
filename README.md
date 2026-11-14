# SENTINEL ? Module 1

Evidence-backed, repository-first security analysis implementing `SENTINEL_MODULE1_IMPLEMENTATION.md`.
SENTINEL builds a partial dependency graph, reasons backward from a dangerous outcome, models hypothetical compromises,
and compiles bounded investigation workflows. LangChain Deep Agents performs semantic graph ingestion and security
analysis; deterministic code provides bounded acquisition, syntax facts, evidence validation, Boolean evaluation, policy,
caching, and benchmark scoring.

## Run the demo

Requires Python 3.11?3.14 and [uv](https://docs.astral.sh/uv/).

```powershell
uv sync --all-extras --locked
uv run sentinel demo
```

The demo copies the bundled **synthetic** refund repository into `.sentinel/demos/`, analyzes it, adds one agent tool declaration,
and reanalyzes it. It prints cache reuse, invalidation, changed edges, and artifact locations. It runs both approved synthetic
verification fixtures. It never edits a repository supplied by the operator.

For an interactive terminal walkthrough of scenarios, hypothetical compromises, shared conditions, and workflow traces:

```powershell
uv run sentinel demo --interactive
```

## Analyze an authorized repository

```powershell
uv run sentinel analyze --repo ./tests/fixtures/toy_refund_app --authorized --outcome unauthorized_refund
uv run sentinel analyze --repo ./tests/fixtures/toy_refund_app --authorized --allow-mock
uv run sentinel analyze --repo ./path/to/example.py --authorized
uv run sentinel analyze --repo https://github.com/OWNER/REPO --authorized
uv run sentinel analyze --repo ./tests/fixtures/toy_refund_app --authorized --structure-only
```

`--authorized` confirms the operator has permission. A repository directory, supported single source file, or public
GitHub repository can be analyzed. The default requires a configured Deep Agents model provider.
`--structure-only` emits an inventory and syntax index without findings, scenarios, or vulnerability conclusions.
`--allow-mock` additionally runs the two fixed refund fixtures when the selected refund outcome is relevant. These fixtures
are independent of the analyzed source: a successful fixture test does **not** prove a vulnerability in that repository.

Supported outcomes are `unauthorized_refund`, `sensitive_data_exposure`, and `unauthorized_agent_tool_action`.
The run metadata also lists outcome suggestions based on observed source signals. No matching signal means no scenario
report for that outcome; the graph and workflow artifacts remain available.

```powershell
uv run sentinel report --run-id RUN_ID --format json
uv run sentinel report --run-id RUN_ID --format markdown
uv run sentinel graph --run-id RUN_ID --kind organization --format json
uv run sentinel graph --run-id RUN_ID --kind attack --format json
uv run sentinel reanalyze --run-id RUN_ID --changed-files app/agent.py
```

Use `uv run sentinel --state-dir PATH ...` or `SENTINEL_STATE_DIR` to choose a state directory. Reanalysis compares all indexed
file hashes, so omitted change hints cannot preserve stale results. Added and deleted files are detected automatically.

## Required Deep Agents orchestration

The `agents` extra installs the real LangChain `deepagents` package, pinned to the tested version **0.7.38**. Exact resolved
versions for all dependencies are in `uv.lock`. Omit `--all-extras` to install only the deterministic application.

Set the provider API key in the process environment and optionally set `SENTINEL_MODEL`, then run:

```powershell
uv run sentinel analyze --repo ./tests/fixtures/toy_refund_app --authorized
```

The supervisor delegates source intake, file and repository dependency construction, security findings, attack paths,
hypothetical compromises, verification planning, reporting, and benchmark analysis. Agents receive bounded numbered
source slices through an allowlisted tool and submit typed graph, finding, hypothesis, and investigation proposals.
Deterministic validators derive IDs, enforce snapshot provenance, and reject fabricated evidence. Free-form model prose
never becomes executable work.

The harness uses an ephemeral state backend plus a read-only route for packaged skills. The required `read_file` tool can
read only `/skills/**`; host and repository paths are denied. Filesystem mutation, shell execution, and arbitrary network
tools are absent. Shared tool quotas, model-call budgets, recursion limits, and provider timeouts bound an investigation.
An agent proposal cannot authorize mock verification.

The integration follows the installed API and the official
[Deep Agents reference](https://reference.langchain.com/python/deepagents/graph/create_deep_agent).
Tests invoke the real harness with a scripted model, exercise delegation, and verify denied filesystem reads. They make no
paid provider requests; behavior with a live provider is not part of the offline test suite.

## Local API

```powershell
$env:SENTINEL_REPO_ROOT = (Get-Location).Path
uv run uvicorn sentinel.api.main:app --host 127.0.0.1 --port 8000
```

Interactive API documentation is available at `http://127.0.0.1:8000/docs`.
Run a single worker. The API is intended for a trusted local operator: it accepts loopback clients only, validates Host
headers, restricts local repositories to `SENTINEL_REPO_ROOT`, and has no cross-origin configuration.

| Method | Path | Result |
| --- | --- | --- |
| POST | `/runs` | Synchronous authorized analysis; returns run ID and metrics |
| GET | `/runs/{id}` | Completed status, revision, warnings, and metrics |
| GET | `/runs/{id}/graph/organization` | Typed organization graph and provenance |
| GET | `/runs/{id}/graph/attack` | Boolean gates, conditions, bounds, and paths |
| GET | `/runs/{id}/scenarios` | Seven-field scenario reports |
| GET | `/runs/{id}/workflows` | Compiled DAGs, policy results, cache hits, and remaining questions |
| POST | `/runs/{id}/reanalyze` | Incremental extraction and recompilation |

Example request body for `POST /runs`:

```json
{"repo":"./tests/fixtures/toy_refund_app","authorized":true,"outcome":"unauthorized_refund","allow_mock":false,"use_agents":false}
```

Example reanalysis body: `{"changed_files":["app/agent.py"]}`.

## Evidence and reasoning

- Python AST extraction recognizes functions, FastAPI routes and dependency declarations, imports, static calls, decorated
  tools, agent tool lists, database calls, identity declarations, and declared tool scopes. Ambiguous calls stay unresolved.
- Every edge has a source snapshot, evidence IDs, and an epistemic status. Identity declarations do not prove a deployed
  `RUNS_AS` binding or deployed permissions; those remain unknown.
- Snapshot IDs are content hashes prefixed `snapshot:`. They are **not Git commit SHAs**. Evidence carries file paths, line
  spans, and this exact snapshot identifier; stable node IDs survive source revisions.
- Curated mechanisms inspired by CWE-862, CWE-863, CWE-1427, and CWE-200 expand into explicit AND/OR/NOT formulas. Evaluation
  uses true/false/unknown logic, including `NOT unknown = unknown`.
- Counterfactual assumptions are evaluated on copied facts and never modify factual graph truth. Shared dependency scores
  are ranking heuristics. Interruption candidates report whether they cover all *enumerated* paths and whether bounds were hit.
- Deterministic extraction is a syntax index, not a vulnerability detector. Deep Agents proposes semantic graph links and
  CWE findings, and every proposal remains an inference until independent runtime evidence exists.
- The MVP models one representative asset per role, not every asset combination. Recognized guard calls do not establish
  effective authorization, and missing recognized calls do not prove its absence.
- Runtime IAM, successful prompt injection, backend acceptance, and data sensitivity remain unknown without relevant evidence.

## JIT workflow implementation

Typed requests lower to `inspect_source`, `inspect_auth`, `inspect_agent_tools`, `retrieve_graph`, and optionally `mock_verify`.
The compiler adds inspection prerequisites, eliminates duplicate expressions and dead tasks, and topologically schedules
independent read-only tasks with up to four workers. It regenerates the remaining workflow after trusted evidence updates.
Policy runs before execution and again for every invocation, including cache hits; it cannot be optimized away.

SQLite caches successful read-only results by tool, normalized inputs, relevant file hashes, tool version, repository scope,
and policy context. Source inspections track only relevant files; tool inspections include declaration files on both ends
of relevant edges. Graph retrieval conservatively depends on all indexed files. A changed file invalidates dependent results,
while unaffected authorization/source inspections remain reusable. Reanalysis reparses only changed files and relinks the
combined graph to resolve cross-file changes. Every revision preserves its before/after artifacts.

## Synthetic verification boundary

Only `refund_vulnerable` and `refund_safeguarded` may execute, with synthetic principals and records. A fixed trusted worker
runs under an isolated Python interpreter, in an empty temporary directory, without inherited credentials or repository
code. It has a five-second wall limit, two-second CPU limit, and 128 MiB memory limit. Windows uses a Job Object; POSIX uses
resource limits. The worker denies network/process audit events and contains no network operations.

This is a restricted fixed-fixture runner, **not an OS sandbox for arbitrary hostile Python**. It does not accept generated
Python, shell commands, repository tests, external services, or production targets. Mock results are labeled
`verified_within_fixture` or `blocked_within_fixture`; source scenarios remain hypothetical.

## Output artifacts

Each completed revision lives under `.sentinel/runs/RUN_ID/revisions/N/`:

- `organization_graph.json`, `attack_graph.json`, and `scenarios.json`
- `compiled_workflows.json` and `verification_results.json`
- `counterfactuals.json`, `shared_dependencies.json`, and `incremental.json`
- `agent_trace.json`, `hypotheses.json`, and `report.md`
- `syntax_index.json`, `graph_proposals.json`, `skills_manifest.json`, and `agent_run_manifest.json`

Internal `hashes.json` and `file_facts.json` enable selective reanalysis. Source text and configuration values are not persisted.
The organization graph includes synthetic evidence nodes with explicit fixture scope; these do not verify source conditions.
The seven report fields are title/scenario, required conditions, possible impact, critical dependencies, alternate routes,
interruption points, and confidence/evidence. Assumptions and unknowns are separate from source-observed facts.

## Ingestion limits

Local ingestion skips linked files/directories, build environments, `.git`, `.sentinel`, real `.env` files, and credential-like
filenames. Supported configuration files contribute keys/dependency names only. Defaults cap individual files at 512 KB,
total indexed content at 20 MB, and indexed files at 2,000. YAML aliases are rejected. Parsing never imports or runs source.

Remote ingestion accepts only public `https://github.com/OWNER/REPO` URLs. It fetches a bounded archive from the fixed
`codeload.github.com` host, with redirects and inherited proxies disabled. Archive paths, symlinks, entry counts, expanded
sizes, and duplicate paths are checked. No checkout hooks, package installation, or repository code executes.
Private repositories, authenticated fetches, arbitrary refs, and arbitrary Git hosts are outside this MVP.

## Development

```powershell
uv sync --all-extras --locked
uv run pytest -q
uv run ruff check src tests
uv run ruff format --check src tests
uv build
```

The acceptance suite covers safe ingestion, provenance, Boolean semantics, counterfactual isolation, shared dependencies,
compiler reuse, selective invalidation, policy bypass attempts, Deep Agents delegation/restrictions, fixture verification,
report artifacts, and API scope. The terminal demo and API docs provide interactive inspection; the optional React graph UI
from the specification is not included.


## OpenRouter and benchmark evaluation

OpenRouter is supported through the official OpenAI-compatible endpoint. Set `SENTINEL_PROVIDER=openrouter`,
`SENTINEL_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free`, and supply `OPENROUTER_API_KEY` in the process environment.
The provider integration does not store credentials. It uses no model fallback and no automatic provider retries.

The evaluation scripts pin official OWASP Benchmark Python and CVE-Bench revisions:

```powershell
uv run python scripts/prepare_benchmarks.py
uv run python scripts/run_requested_benchmarks.py --read-key-stdin --case-limit 1 --batch-size 1 --skip-irrelevant-live --max-model-calls 50
```

The credential prompt disables terminal echo. Alternatively, set the key in the process environment and omit
`--read-key-stdin`. Omit `--case-limit` for the complete suite; `--batch-size` bounds each isolated Deep Agents context,
and `--max-model-calls` is the global provider budget. Use `--no-live` for a structure-only compatibility preflight.

Results, per-case CSVs, false negatives, and a Markdown report are saved under `benchmarks/results/`; `latest.json`
points to the most recent run. `live_checkpoint.json` freezes label-free predictions after every completed batch.
Downloaded inputs, working snapshots, and results are excluded from version control. The ground-truth CSV is excluded
from the analyzed corpus. Structure-only and Deep Agents predictions are frozen before labels are scored.

**Interpretation:** OWASP predictions now come only from evidence-backed Deep Agents finding proposals. The deterministic
structure-only preflight cannot emit CWE assertions. Predictions are saved before ground truth is loaded, and the evaluator
uses exact testcase/CWE matching. This remains a public-suite regression evaluation rather than an official OWASP scorecard
or a held-out measurement of model generalization. Provider failures are reported separately.

CVE-Bench's runtime proof-of-exploitation protocol is incompatible with SENTINEL's current read-only tool interface.
The script performs a compatibility preflight, lists the 40 pinned challenges, and checks Docker availability; it does
not claim to have run CVE-Bench, substitute another agent, or report a fabricated success rate.


### Gemini Flash evaluation

The native Google provider accepts `GEMINI_API_KEY` or `GOOGLE_API_KEY` from the process environment.
Set `SENTINEL_PROVIDER=gemini` and `SENTINEL_MODEL=gemini-3.8-flash` for ordinary analysis runs.
The benchmark runner can prompt for an ephemeral key without saving it:

```powershell
uv run python scripts/run_requested_benchmarks.py --provider gemini --model gemini-3.8-flash --read-key-stdin --case-limit 1 --batch-size 1 --skip-irrelevant-live --max-model-calls 50
```

The requested Gemini model exercises semantic graph ingestion and vulnerability analysis through the same typed proposal
tools used by normal runs. Provider-specific run metadata is saved as `gemini_live_run.json` alongside the report and
testcase metrics. API keys are never written to artifacts.

## Agent charter, skills, and framework MCP

`AGENTS.md` locks the Module 1 architecture and trust boundaries. `SKILLS.md` indexes ten packaged Deep Agents skills under
`src/sentinel/skills/`; each specialist receives bounded tools and the relevant skill instructions. The project `.mcp.json`
configures the official LangChain conceptual and API-reference MCP servers for development. Those documentation tools are
not exposed to SENTINEL analysis runs.
