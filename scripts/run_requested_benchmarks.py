"""Reproducible SENTINEL inventory baseline and blinded Deep Agents evaluation.
The operator's API key is read from a pipe or environment and is never serialized.
"""

import argparse
import csv
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from datetime import UTC, datetime
from pathlib import Path

from sentinel.evaluation.owasp import load_labels, native_predictions, score
from sentinel.reporting.serialize import write_json
from sentinel.service import SentinelService

OUTCOMES = ["unauthorized_refund", "sensitive_data_exposure", "unauthorized_agent_tool_action"]
DEFAULT_MODELS = {"openrouter": "nvidia/nemotron-3-ultra-550b-a55b:free", "gemini": "gemini-3.8-flash"}


def safe_error(exc):
    frames = traceback.extract_tb(exc.__traceback__)
    known_reasons = [
        "Agent tool quota exhausted",
        "Proposal budget exhausted",
        "Hypothesis budget exhausted",
        "Unknown graph node",
        "Graph retrieval bounds exceeded",
        "Outcome outside authorized scope",
        "Unknown condition or evidence ID",
        "Unapproved outcome",
        "Retrieved context exceeds the bounded response size; narrow the query",
        "Evaluation model call budget reached",
        "Recursion limit of",
        "Required specialist proposal missing",
    ]
    message = str(exc)
    return {
        "type": type(exc).__name__,
        "http_status": getattr(exc, "status_code", None),
        "reason": next(
            (r for r in known_reasons if r in message),
            "Unclassified validation/provider failure; payload omitted",
        ),
        "stack": [{"file": Path(f.filename).name, "function": f.name, "line": f.lineno} for f in frames[-6:]],
        "tool_trace": getattr(exc, "sentinel_trace", []),
    }


def write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "case_id",
                "category",
                "cwe",
                "expected_vulnerable",
                "predicted_vulnerable",
                "outcome",
                "reason",
            ],
        )
        writer.writeheader()
        writer.writerows({key: row[key] for key in writer.fieldnames} for row in rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=sorted(DEFAULT_MODELS), default="openrouter")
    parser.add_argument("--model")
    parser.add_argument("--read-key-stdin", action="store_true")
    parser.add_argument("--no-live", action="store_true")
    parser.add_argument("--skip-irrelevant-live", action="store_true")
    parser.add_argument("--max-model-calls", type=int, default=40)
    parser.add_argument(
        "--batch-size",
        type=int,
        default=8,
        help="Number of OWASP testcases in each isolated Deep Agents run",
    )
    parser.add_argument(
        "--case-limit",
        type=int,
        help="Analyze only the first N sorted cases for a smoke run; omit for the complete benchmark",
    )
    args = parser.parse_args()
    if args.batch_size < 1:
        raise SystemExit("--batch-size must be positive")
    if sys.version_info < (3, 12):
        # The analyzer parses with the host ``ast``; the pinned corpus uses PEP 701 f-strings,
        # so an older interpreter silently turns ~38% of cases into parse-error abstentions.
        raise SystemExit(
            "OWASP Benchmark Python requires a Python 3.12+ parser. Re-run with, for example: "
            "UV_PROJECT_ENVIRONMENT=.venv-bench uv run --python 3.13 python scripts/run_requested_benchmarks.py"
        )
    model_name = args.model or DEFAULT_MODELS[args.provider]
    credential_variable = "GEMINI_API_KEY" if args.provider == "gemini" else "OPENROUTER_API_KEY"
    live_artifact = args.provider + "_live_run.json"
    os.environ["LANGSMITH_TRACING"] = "false"
    os.environ["LANGCHAIN_TRACING_V2"] = "false"
    key = None
    if args.read_key_stdin:
        print("Ready for credential on private process stdin (input is not logged).", flush=True)
        key = getpass.getpass("Credential: ") if sys.stdin.isatty() else sys.stdin.readline().strip()
        if not key:
            raise SystemExit("No credential received")
        os.environ[credential_variable] = key
    os.environ["SENTINEL_PROVIDER"] = args.provider
    os.environ["SENTINEL_MODEL"] = model_name
    root = Path(__file__).resolve().parents[1]
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output = root / "benchmarks" / "results" / run_id
    output.mkdir(parents=True)
    work = root / "benchmarks" / "work" / run_id
    corpus = work / "blind_corpus"
    corpus.mkdir(parents=True)
    source_meta = json.loads((root / "benchmarks/vendor/owasp-python.json").read_text())
    source = Path(source_meta["directory"])
    # Prediction corpus excludes ground truth, scorecards, descriptions, and benchmark runners.
    case_sources = sorted((source / "testcode").glob("BenchmarkTest*.py"))
    if args.case_limit is not None:
        if args.case_limit < 1:
            raise SystemExit("--case-limit must be positive")
        case_sources = case_sources[: args.case_limit]
    selected_sources = case_sources + sorted((source / "helpers").rglob("*.py"))
    helper_sources = sorted((source / "helpers").rglob("*.py"))
    for original in selected_sources:
        target = corpus / original.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
    case_ids = sorted(p.stem for p in (corpus / "testcode").glob("BenchmarkTest*.py"))
    case_batches = [
        case_sources[index : index + args.batch_size]
        for index in range(0, len(case_sources), args.batch_size)
    ]
    batch_corpora = []
    for index, batch_sources in enumerate(case_batches, start=1):
        batch_corpus = work / "live_batches" / f"batch-{index:04d}"
        for original in batch_sources + helper_sources:
            target = batch_corpus / original.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
        batch_corpora.append((index, batch_corpus, [path.stem for path in batch_sources]))
    print(f"Blind corpus prepared: {len(case_ids)} cases. Ground-truth CSV is excluded.", flush=True)
    service = SentinelService(work / "state")
    run_records, native_reports, native_findings, native_coverage = [], [], [], []
    for outcome in OUTCOMES:
        print(f"Structure-only preflight: {outcome}", flush=True)
        started = time.monotonic()
        run = service.analyze(str(corpus), outcome, authorized=True, use_agents=False)
        reports = service.artifact(run["id"], "scenarios")
        native_reports.extend(reports)
        native_findings.extend(service.artifact(run["id"], "findings"))
        native_coverage.extend(service.artifact(run["id"], "source_analysis"))
        run_records.append(
            {
                "outcome": outcome,
                "run_id": run["id"],
                "metrics": run["metrics"],
                "warnings": run["warnings"],
                "suggested_outcomes": run["suggested_outcomes"],
                "seconds": round(time.monotonic() - started, 3),
                "artifact_directory": run["artifact_directory"],
            }
        )
        print(f"Completed: {run['metrics']}", flush=True)
    # Freeze predictions before reading expected results. Do not tune detectors to these labels.
    predictions = native_predictions(case_ids, native_reports, native_findings, native_coverage)
    write_json(output / "native_predictions.json", predictions)
    write_json(output / "static_findings.json", list({f["id"]: f for f in native_findings}.values()))
    write_json(output / "native_runs.json", run_records)
    parse_failures = sorted(
        {
            d.split(":", 1)[1]
            for item in native_coverage
            for d in item.get("diagnostics", [])
            if d.startswith("parse_error:")
        }
    )
    environment = {
        "python": sys.version.split()[0],
        "parse_failures": len(parse_failures),
        "parse_failure_files": parse_failures,
    }
    live = {
        "requested_model": model_name,
        "provider": args.provider,
        "model_calls": 0,
        "runs": [],
        "status": "not_requested" if args.no_live else "pending",
        "paid_fallback": False,
        "labels_sent_to_model": False,
        "raw_source_sent_to_model": True,
        "source_context": "Bounded numbered source slices from the authorized snapshot",
    }
    live_predictions = None
    if not args.no_live:
        from langchain_core.callbacks import BaseCallbackHandler

        from sentinel.agents import providers

        original_factory = providers.build_model
        last_call = [0.0]

        class BudgetObserver(BaseCallbackHandler):
            raise_error = True

            def on_llm_start(self, serialized, prompts, **kwargs):
                if live["model_calls"] >= args.max_model_calls:
                    raise RuntimeError("Evaluation model call budget reached")
                wait = max(0, 3.2 - (time.monotonic() - last_call[0]))
                if wait:
                    time.sleep(wait)
                last_call[0] = time.monotonic()
                live["model_calls"] += 1
                print(f"{args.provider} model request {live['model_calls']} (content omitted)", flush=True)

        observer = BudgetObserver()

        def model_factory():
            model = original_factory()
            model.callbacks = [observer]
            return model

        providers.build_model = model_factory
        try:
            print("Checking the requested model endpoint...", flush=True)
            reply = model_factory().invoke("Respond with READY only. This is a connectivity check.")
            live["connectivity"] = {
                "status": "ok",
                "response_nonempty": bool(reply.content),
                "reported_model": reply.response_metadata.get("model_name"),
            }
            live_reports, live_findings, live_coverage = [], [], []
            live_failed = False
            for outcome in OUTCOMES:
                native_run = next(r for r in run_records if r["outcome"] == outcome)
                if args.skip_irrelevant_live and outcome not in {
                    r["id"] for r in native_run["suggested_outcomes"]
                }:
                    live["runs"].append(
                        {
                            "outcome": outcome,
                            "status": "skipped_no_relevance_signal",
                            "reason": "All source was extracted; this outcome's applicability gate was false",
                        }
                    )
                    print(f"Skipped irrelevant live outcome: {outcome}", flush=True)
                    continue
                for batch_index, batch_corpus, batch_case_ids in batch_corpora:
                    print(
                        f"SENTINEL + {model_name} scan: {outcome}; batch {batch_index}/{len(batch_corpora)}",
                        flush=True,
                    )
                    started = time.monotonic()
                    try:
                        run = service.analyze(
                            str(batch_corpus),
                            outcome,
                            authorized=True,
                            use_agents=True,
                            analysis_targets=[f"testcode/{case_id}.py" for case_id in batch_case_ids],
                        )
                        live_reports.extend(service.artifact(run["id"], "scenarios"))
                        live_findings.extend(service.artifact(run["id"], "findings"))
                        live_coverage.extend(service.artifact(run["id"], "source_analysis"))
                        trace = service.artifact(run["id"], "agent_trace")
                        live["runs"].append(
                            {
                                "outcome": outcome,
                                "batch": batch_index,
                                "case_ids": batch_case_ids,
                                "status": "completed",
                                "run_id": run["id"],
                                "metrics": run["metrics"],
                                "agent_trace": trace,
                                "seconds": round(time.monotonic() - started, 3),
                                "artifact_directory": run["artifact_directory"],
                            }
                        )
                        checkpoint_predictions = native_predictions(
                            case_ids, live_reports, live_findings, live_coverage
                        )
                        write_json(
                            output / "live_checkpoint.json",
                            {
                                "labels_loaded": False,
                                "completed_runs": len(live["runs"]),
                                "runs": live["runs"],
                                "predictions": checkpoint_predictions,
                            },
                        )
                        print(
                            f"Live batch completed: {outcome} #{batch_index}; "
                            f"{len(trace)} orchestration events",
                            flush=True,
                        )
                    except Exception as exc:
                        live["runs"].append(
                            {
                                "outcome": outcome,
                                "batch": batch_index,
                                "case_ids": batch_case_ids,
                                "status": "failed",
                                "error": safe_error(exc),
                            }
                        )
                        print("Live batch stopped: " + json.dumps(safe_error(exc)), flush=True)
                        live_failed = True
                        break
                if live_failed:
                    break
            if not live_failed and all(
                r["status"] in {"completed", "skipped_no_relevance_signal"} for r in live["runs"]
            ):
                live["status"] = "completed"
                live_predictions = native_predictions(case_ids, live_reports, live_findings, live_coverage)
                write_json(output / "live_predictions.json", live_predictions)
            else:
                live["status"] = "incomplete_not_scored"
        except Exception as exc:
            live["status"] = "provider_unavailable_not_scored"
            live["error"] = safe_error(exc)
            print("Provider check failed: " + json.dumps(safe_error(exc)), flush=True)
        finally:
            providers.build_model = original_factory
    # Predictions are persisted before ground truth is read. This prevents label leakage into either analysis path.
    selected_case_ids = set(case_ids)
    labels = [
        row for row in load_labels(source / "expectedresults-0.1.csv") if row["case_id"] in selected_case_ids
    ]
    scored = score(labels, predictions)
    scored["benchmark"] = source_meta
    scored["environment"] = environment
    scored["mode"] = "structure_only_unscored_baseline"
    scored["native_scenario_count"] = len(native_reports)
    scored["model_used"] = False
    write_json(output / "owasp_native_results.json", scored)
    live_score = None
    if live_predictions is not None:
        live_score = score(labels, live_predictions)
        live_score["benchmark"] = source_meta
        live_score["mode"] = "deepagents_agent_analysis"
        live_score["model"] = model_name
        live_score["environment"] = environment
        write_json(output / "owasp_live_results.json", live_score)
        live["overall"] = live_score["overall"]
    primary = live_score or scored
    write_csv(output / "false_negatives.csv", primary["false_negatives"])
    write_csv(output / "false_positives.csv", primary["false_positives"])
    write_csv(output / "all_cases.csv", primary["cases"])
    write_json(output / live_artifact, live)
    print("Benchmark results: " + json.dumps(primary["overall"]), flush=True)
    cve_meta = json.loads((root / "benchmarks/vendor/cve-bench.json").read_text())
    tree = json.loads((Path(cve_meta["directory"]) / "repository_tree.json").read_text())
    challenges = sorted(
        {
            match.group(1)
            for item in tree["tree"]
            if (match := re.match(r"src/critical/challenges/(CVE-[0-9]+-[0-9]+)(?:/|$)", item["path"]))
        }
    )
    docker = shutil.which("docker")
    docker_ready = False
    docker_error = "Docker executable unavailable"
    if docker:
        try:
            process = subprocess.run(
                [docker, "info", "--format", "{{json .ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            docker_ready = process.returncode == 0
            docker_error = None if docker_ready else "Docker Desktop Linux engine is not reachable"
        except subprocess.TimeoutExpired:
            docker_error = "Docker engine check timed out"
    cve = {
        "benchmark": cve_meta,
        "status": "not_run_incompatible_agent_interface",
        "challenge_count": len(challenges),
        "challenges": challenges,
        "attempted_challenges": 0,
        "success_rate": None,
        "docker_ready": docker_ready,
        "docker_error": docker_error,
        "blockers": [
            "SENTINEL has no Inspect/CVE-Bench solver adapter",
            "Its allowlisted tools cannot interact with benchmark target services or execute proof actions",
            "CVE-Bench evaluates runtime attack success, not static classification precision/recall",
        ],
        "no_vulnerable_containers_started": True,
        "no_reference_exploit_executed": True,
    }
    write_json(output / "cve_bench_preflight.json", cve)
    summary = {
        "run_id": run_id,
        "directory": str(output),
        "environment": {k: v for k, v in environment.items() if k != "parse_failure_files"},
        "owasp_structure_only": scored["overall"],
        "provider": args.provider,
        "model": model_name,
        "owasp_live_status": live["status"],
        "owasp_live": live.get("overall"),
        "cve_bench_status": cve["status"],
    }
    write_json(output / "summary.json", summary)
    write_json(root / "benchmarks/results/latest.json", summary)

    def pct(value):
        return "n/a" if value is None else format(value, ".1%")

    reported_score = live_score or scored
    table = "\n".join(
        f"| {r['category']} | {r['cwe']} | {r['cases']} | {r['true_positives']} | {r['false_positives']} | "
        f"{r['false_negatives']} | {r['true_negatives']} | {pct(r['recall'])} | {pct(r['precision'])} |"
        for r in reported_score["by_category"]
    )
    if live.get("overall"):
        live_line = (
            f"Deep Agents recall {pct(live['overall']['recall'])}, "
            f"precision {pct(live['overall']['precision'])}. Inspect `live_predictions.json` for case evidence."
        )
    else:
        live_line = "The live run was not scored."
    report = f"""# SENTINEL benchmark evaluation

## OWASP Benchmark Python

Pinned revision: `{source_meta["commit"]}`. Analyzed all **{len(case_ids)} testcases** through all three existing outcome templates.
Ground-truth labels were held outside the analysis corpus and loaded only after structure-only and Deep Agents predictions were frozen.
The analyzer emits evidence-backed static CWE candidates and the evaluator matches their source/sink paths to cases.
Unresolved inspections are explicitly inconclusive. A negative result is not proof that a case is safe.
Hypothetical outcome scenarios and synthetic fixture verification are excluded from CWE predictions.

- Recall: {pct(reported_score["overall"]["recall"])}
- Precision: {"undefined (no positive predictions)" if reported_score["overall"]["precision"] is None else pct(reported_score["overall"]["precision"])}
- F1: {"n/a" if reported_score["overall"]["f1"] is None else format(reported_score["overall"]["f1"], ".3f")}
- TP: {reported_score["overall"]["true_positives"]}; FP: {reported_score["overall"]["false_positives"]}; FN: {reported_score["overall"]["false_negatives"]}; TN: {reported_score["overall"]["true_negatives"]}
- Inconclusive (abstained) inspections: {reported_score["overall"]["abstentions"]}; extra non-target CWE reports: {reported_score["extra_cwe_predictions"]}
- Parser: Python {environment["python"]}; files that failed to parse: {environment["parse_failures"]}

This measures bounded source-analysis candidates, not production exploitability or the selected model's standalone ability.
The public suite was previously inspected; this is a regression evaluation, not an unseen generalization result.
It is a custom SENTINEL-output coverage calculation, not an official OWASP scorecard.

| Category | CWE | Cases | TP | FP | FN | TN | Recall | Precision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{table}

Missed and falsely flagged testcase IDs are in `false_negatives.csv` and `false_positives.csv`; the complete matrix is in
`all_cases.csv`. Structure-only inventory metrics and parser warnings are in `native_runs.json`.

## Requested model

Provider: `{args.provider}`. Model: `{model_name}`. Live-run status: **{live["status"]}**. Model requests: {live["model_calls"]}.
{live_line}
See `{live_artifact}` for the actual completed/failed stages and sanitized errors.
No alternate model fallback was used. API failures are not classified as vulnerability misses.
Deep Agents receive bounded, numbered source slices from the authorized snapshot, but never ground-truth labels.
The evaluator consumes the same source-analysis artifacts exposed by the SENTINEL CLI and API.

## CVE-Bench

Pinned revision: `{cve_meta["commit"]}`; {len(challenges)} challenge directories identified.
**Not executed and not scored.** SENTINEL has no compatible runtime attack solver, and its policy-gated static tools cannot
perform CVE-Bench's proof actions. Docker engine ready: {docker_ready}. Engine diagnostic: {docker_error}.
Running the benchmark's default Claude Code agent would measure a different agent, so it was not substituted.
Details and task IDs are in `cve_bench_preflight.json`. No vulnerable applications or reference exploits were executed.

## Remaining limitations

The analyzer is bounded and can miss dynamic dispatch, complex control flow, unmodeled sanitizers, and library semantics.
Static findings and hypothetical outcome graphs remain separate from runtime verification. A CVE-Bench run additionally needs a separate isolated,
benchmark-specific runtime solver and target-service interface. Keep that execution authority outside the current read-only
Module 1 analyzer.

Sources: [OWASP Benchmark Python]({source_meta["repository"]}), [CVE-Bench]({cve_meta["repository"]}).
"""
    (output / "REPORT.md").write_text(report, encoding="utf-8")
    if args.read_key_stdin:
        os.environ.pop(credential_variable, None)
    key = None
    print("Finished: " + json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
