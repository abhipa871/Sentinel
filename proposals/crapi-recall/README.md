# crAPI recall benchmark + Module I signal patch

Measured against crAPI's 18 documented challenges (`docs/challenges.md`, mapped to source in
`crapi_ground_truth.json`) at crAPI commit `b5fc307`.

| Run | Candidates | Found (file+CWE) | Confirmed by Module II |
|---|---|---|---|
| `artifacts/crapi-scan.json` (deterministic, current) | 11 | 1/18 | n/a |
| `artifacts/crapi-openai-scan.json` (agentic, current, `--max-candidates 10`) | 4 | 2/18 | 0/18 |
| Deterministic + `module1-signals.patch` | 50 | 17/18 | not yet run |

## Apply and measure

```powershell
git apply proposals\crapi-recall\module1-signals.patch
.venv\Scripts\python -m pytest
.venv\Scripts\sentinel scan ..\crAPI --through module1 --output artifacts\crapi-signals.json
python proposals\crapi-recall\score_crapi.py artifacts\crapi-signals.json
```

## What the patch does

- `signals.py` (new): language-aware static signals for Python/Java/Go/JS/TS with exact line
  numbers. Comments and docstrings are blanked first, so crAPI's "BOLA vulnerability" comments
  can't leak into detection.
- `phase0.py`: records `security_signals` and `is_test` per asset and emits one line-level
  `EvidenceRef` per signal hit. Module II can now cite spans, not only whole files. Also stops
  treating `mock.patch` decorators as routes.
- `module1.py`: supports `all_signals`, `any_signals` and `excluded_features.any_signals`
  predicates, cites span evidence, and drops test files and empty files. Empty `__init__.py`
  files were producing "unknown" predicates that became 4 of the 11 baseline candidates.
- `knowledge.py`: adds 13 signal rules covering OWASP API Top 10 and LLM classes: CWE-639,
  285, 306, 307, 918, 770, 89, 943, 915, 347, 213, 1427 and 441.

## Caveats

- crAPI is a dev set: these rules were written while looking at it. Before claiming generality,
  validate on held-out targets such as VAmPI, DVWS-node, Juice Shop and DVGA.
- The one miss (C1) is cross-file: the path ID is in `VehicleController` and the unscoped
  lookup is in `VehicleServiceImpl`. Catching it needs controller-to-service composition over
  the graph.
- `CWE-213` (entity/JSON exposure) is the noisiest rule and needs field-level scoping.
