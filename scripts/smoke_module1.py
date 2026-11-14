"""Run one live Module 1 analysis and print only sanitized failure metadata."""

import argparse
import json

from run_requested_benchmarks import safe_error

from sentinel.service import SentinelService


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("repo")
    parser.add_argument("--outcome", default="sensitive_data_exposure")
    parser.add_argument("--state-dir", default="benchmarks/work/module1-smoke")
    args = parser.parse_args()
    try:
        run = SentinelService(args.state_dir).analyze(args.repo, args.outcome, authorized=True)
        print(json.dumps({"status": "completed", "run": run}, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": safe_error(exc)}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
