"""Score a SENTINEL scan bundle against crAPI's 18 documented challenges.

Usage: python score_crapi.py artifacts/crapi-scan.json [more.json ...]
A challenge counts as found (file+CWE) when a candidate's node is one of the challenge's
files and its CWE is in the accepted set; (file) relaxes the CWE requirement.
Ground truth: crAPI docs/challenges.md, mapped to source by hand. Treat as a dev set:
validate rule changes on held-out apps before claiming generality.
"""
import json
import sys
from pathlib import Path

GT = json.loads((Path(__file__).with_name("crapi_ground_truth.json")).read_text())


def score(bundle_path: str) -> None:
    data = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    cands = data["candidates"]
    findings = {f["candidate_id"]: f["verification_status"] for f in data.get("findings", [])}
    strict, loose, confirmed, tp = set(), set(), set(), 0
    for c in cands:
        node, cwe, hit = c["node"].replace("\\", "/"), c["vulnerability_id"], False
        for g in GT:
            if node in g["files"]:
                loose.add(g["id"])
                if cwe in g["cwes"]:
                    strict.add(g["id"])
                    hit = True
                    if findings.get(c["candidate_id"]) in {"confirmed", "strongly_supported"}:
                        confirmed.add(g["id"])
        tp += hit
    n = len(GT)
    print(f"{Path(bundle_path).name}: candidates={len(cands)} "
          f"recall(file+CWE)={len(strict)}/{n} recall(file)={len(loose)}/{n} "
          f"precision={tp}/{len(cands)} confirmed={len(confirmed)}/{n}")
    for g in GT:
        mark = "CONFIRMED" if g["id"] in confirmed else "found" if g["id"] in strict else "file-only" if g["id"] in loose else "MISSED"
        print(f"  {g['id']:>4} {mark:<9} {g['title']}")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        score(p)
