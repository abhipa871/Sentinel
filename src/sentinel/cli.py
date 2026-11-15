from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentinel.agents.runtime import DeepAgentsRuntime
from sentinel.config import get_settings
from sentinel.pipeline import SentinelPipeline
from sentinel.profiles import PROFILES, get_profile


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Run the immutable repository analysis pipeline")
    scan.add_argument("source", help="Local path or canonical public GitHub URL")
    scan.add_argument("--ref", default="HEAD")
    scan.add_argument("--through", choices=("module1", "module2", "module3"), default="module1")
    scan.add_argument(
        "--model",
        help=(
            "LangChain provider:model identifier; enables agent-owned Module I and is required "
            "for Modules II/III"
        ),
    )
    scan.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default=None,
        help="Scan budget profile (default: DEFAULT_SCAN_PROFILE, else balanced)",
    )
    scan.add_argument(
        "--max-candidates",
        type=int,
        default=None,
        help="Final Module I candidate budget (default: the profile's budget)",
    )
    scan.add_argument(
        "--reasoning-effort",
        default="auto",
        choices=("auto", "provider-default", "none", "minimal", "low", "medium", "high"),
        help=(
            "auto: 'none' for OpenAI (required by GPT-5.6 Luna with tools), provider default "
            "elsewhere; provider-default: never send the parameter"
        ),
    )
    scan.add_argument(
        "--progress",
        action="store_true",
        help="Print one line per stage, repair, salvage, cache hit, and budget event to stderr",
    )
    scan.add_argument("--output", type=Path)
    api = sub.add_parser("api", help="Run the FastAPI service")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "api":
        import uvicorn

        uvicorn.run("sentinel.api:app", host=args.host, port=args.port)
        return 0
    profile = get_profile(args.profile or get_settings().default_scan_profile)
    runtime = (
        DeepAgentsRuntime(args.model, profile=profile, reasoning_effort=args.reasoning_effort)
        if args.model
        else None
    )
    if args.through != "module1" and runtime is None:
        raise SystemExit("--model is required for Module II or III")
    bundle = SentinelPipeline(runtime=runtime).scan(
        args.source,
        ref=args.ref,
        through=args.through,
        max_candidates=args.max_candidates,
        profile=profile,
        progress=(lambda line: print(line, file=sys.stderr, flush=True)) if args.progress else None,
    )
    rendered = json.dumps(bundle.model_dump(mode="json"), indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
