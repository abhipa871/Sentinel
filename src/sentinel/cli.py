from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from dotenv import load_dotenv

from sentinel.agents.runtime import DeepAgentsRuntime
from sentinel.pipeline import SentinelPipeline


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
    scan.add_argument("--max-candidates", type=int, default=500)
    scan.add_argument("--progress", action="store_true", help="Log agent stage progress to stderr")
    scan.add_argument("--provider-timeout", type=float, help="Model request timeout in seconds")
    scan.add_argument("--output", type=Path)
    api = sub.add_parser("api", help="Run the FastAPI service")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    load_dotenv(Path.cwd() / ".env", override=False)
    if args.command == "api":
        import uvicorn

        uvicorn.run("sentinel.api:app", host=args.host, port=args.port)
        return 0
    if args.progress:
        logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
        logging.getLogger("sentinel.agents.runtime").setLevel(logging.INFO)
    if args.provider_timeout is not None and not 0 < args.provider_timeout < float("inf"):
        raise SystemExit("--provider-timeout must be a finite positive number")
    runtime_options = {}
    if args.provider_timeout is not None:
        runtime_options = {
            "provider_timeout_seconds": args.provider_timeout,
            "max_provider_retries": 0,
        }
    runtime = DeepAgentsRuntime(args.model, **runtime_options) if args.model else None
    if args.through != "module1" and runtime is None:
        raise SystemExit("--model is required for Module II or III")
    bundle = SentinelPipeline(runtime=runtime).scan(
        args.source,
        ref=args.ref,
        through=args.through,
        max_candidates=args.max_candidates,
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
