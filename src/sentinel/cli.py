import argparse
import json
import sys

from sentinel.models.report import ScenarioReport
from sentinel.reporting.render import markdown_report
from sentinel.service import SentinelService


def parser():
    cli = argparse.ArgumentParser(prog="sentinel", description="Authorized repository security analysis")
    cli.add_argument("--state-dir", default=None)
    commands = cli.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze")
    analyze.add_argument("--repo", required=True)
    analyze.add_argument(
        "--outcome",
        default="unauthorized_refund",
        choices=["unauthorized_refund", "sensitive_data_exposure", "unauthorized_agent_tool_action"],
    )
    analyze.add_argument(
        "--authorized",
        action="store_true",
        required=True,
        help="Confirm permission to analyze this repository",
    )
    analyze.add_argument(
        "--allow-mock", action="store_true", help="Run fixed synthetic fixtures in isolation"
    )
    analyze.add_argument(
        "--agents", action="store_true", help="Compatibility flag; Deep Agents analysis is the default"
    )
    analyze.add_argument(
        "--structure-only",
        action="store_true",
        help="Build only the deterministic syntax inventory; emit no findings or scenarios",
    )
    analyze.add_argument(
        "--analysis-target",
        action="append",
        dest="analysis_targets",
        help="Restrict dedicated Deep Agents security reviews to this snapshot-relative source path",
    )
    report = commands.add_parser("report")
    report.add_argument("--run-id", required=True)
    report.add_argument("--kind", choices=["scenarios", "findings"], default="scenarios")
    report.add_argument("--format", choices=["json", "markdown"], default="json")
    graph = commands.add_parser("graph")
    graph.add_argument("--run-id", required=True)
    graph.add_argument("--kind", choices=["organization", "attack"], default="organization")
    graph.add_argument("--format", choices=["json"], default="json")
    reanalyze = commands.add_parser("reanalyze")
    reanalyze.add_argument("--run-id", required=True)
    reanalyze.add_argument("--changed-files", nargs="+", default=[])
    demo = commands.add_parser("demo")
    demo.add_argument("--interactive", action="store_true")
    return cli


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        service = SentinelService(args.state_dir)
        if args.command == "analyze":
            result = service.analyze(
                args.repo,
                args.outcome,
                authorized=args.authorized,
                allow_mock=args.allow_mock,
                use_agents=not args.structure_only,
                analysis_targets=args.analysis_targets,
            )
        elif args.command == "reanalyze":
            result = service.reanalyze(args.run_id, args.changed_files)
        elif args.command == "graph":
            result = service.artifact(args.run_id, args.kind + "_graph")
        elif args.command == "report":
            result = service.artifact(args.run_id, args.kind)
            if args.format == "markdown" and args.kind == "scenarios":
                print(markdown_report([ScenarioReport.model_validate(r) for r in result]))
                return 0
        else:
            from sentinel.demo import run_demo

            run_demo(service, args.interactive)
            return 0
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, RuntimeError, ImportError) as exc:
        # Never print provider payloads, source contents, credentials, or a traceback by default.
        print(
            f"SENTINEL could not complete the request ({type(exc).__name__}). Check authorization, input paths, limits, and provider configuration.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
