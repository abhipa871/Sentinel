"""Trusted, fixed synthetic fixtures; this module never imports analyzed code."""

import json
import sys


def run_fixture(fixture_id):
    if fixture_id not in {"refund_vulnerable", "refund_safeguarded"}:
        raise ValueError("Unknown fixture")
    records = {"synthetic-order-001": {"owner": "synthetic-customer", "paid": 100, "refunded": 0}}
    principal = "synthetic-attacker"
    order = records["synthetic-order-001"]
    permitted = fixture_id == "refund_vulnerable" or principal == order["owner"]
    if permitted:
        order["refunded"] += 20
    return {
        "fixture_id": fixture_id,
        "scope": "synthetic_fixture_only",
        "synthetic_data": True,
        "unauthorized_request_made": True,
        "backend_accepted": permitted,
        "status": "verified_within_fixture" if permitted else "blocked_within_fixture",
        "refunded_amount": order["refunded"],
        "production_vulnerability": "not_established",
    }


def main():
    import os

    if os.name != "nt":
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

    def audit(event, args):
        if event.startswith(("socket.", "subprocess.", "urllib.", "http.client.")) or event in {
            "os.system",
            "os.exec",
            "os.posix_spawn",
        }:
            raise PermissionError("Network and process creation are disabled in mock fixtures")

    sys.addaudithook(audit)
    fixture_id = sys.stdin.readline(100).strip()
    print(json.dumps(run_fixture(fixture_id)))


if __name__ == "__main__":
    main()
