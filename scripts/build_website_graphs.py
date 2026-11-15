"""Build website/graphs-data.js: sample subsets of the repository graph and of G_V.

Usage: python scripts/build_website_graphs.py artifacts/crapi-full-v7.json

Both graphs are copied from real data: file-to-file edges from the scan bundle's repository
graph, and catalog entities and relations from the packaged vulnerability knowledge graph. The
website's own assets-data.js is only read (for the CWEs and files it shows), never written.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from sentinel.contracts import EdgeType
from sentinel.knowledge_graph import KnowledgeGraphIndex, load_predefined_graph

MAX_FILES_PER_SERVICE = 36
MAX_ATTACK_PATTERNS_PER_CWE = 2
CODE_EDGES = {edge_type.value for edge_type in EdgeType}


def _service(path: str) -> str:
    parts = path.split("/")
    return parts[1] if parts[0] == "services" and len(parts) > 2 else "Repository"


def repository_graph(bundle: dict, finding_paths: set[str]) -> dict[str, dict]:
    graph = bundle["graph"]
    paths = {asset["asset_id"]: asset["path"] for asset in graph["assets"]}
    languages = {asset["path"]: asset.get("language") or "" for asset in graph["assets"]}
    by_service: dict[str, list[tuple[str, str, str]]] = {}
    for edge in graph["edges"]:
        if edge["edge_type"] not in CODE_EDGES:
            continue
        source, target = paths[edge["source_asset_id"]], paths[edge["target_asset_id"]]
        if _service(source) == _service(target):
            by_service.setdefault(_service(source), []).append((source, target, edge["edge_type"]))
    result = {}
    for service, edges in sorted(by_service.items()):
        degree = Counter(node for source, target, _ in edges for node in (source, target))
        # Preserve finding files and at least one observed example of every relationship type
        # before filling the remaining display budget with the most-connected files.
        keep = {node for node in finding_paths if node in degree}
        for kind in sorted({edge[2] for edge in edges}):
            for source, target, edge_kind in sorted(edges):
                if edge_kind != kind:
                    continue
                proposed = keep | {source, target}
                if len(proposed) <= MAX_FILES_PER_SERVICE:
                    keep = proposed
                    break
        ranked = sorted(degree, key=lambda node: (node not in finding_paths, -degree[node], node))
        for node in ranked:
            if len(keep) >= MAX_FILES_PER_SERVICE:
                break
            keep.add(node)
        kept_edges = sorted({edge for edge in edges if edge[0] in keep and edge[1] in keep})
        nodes = sorted({node for source, target, _ in kept_edges for node in (source, target)})
        result[service] = {
            "nodes": [{"id": node, "language": languages[node]} for node in nodes],
            "edges": [{"source": s, "target": t, "type": kind} for s, t, kind in kept_edges],
            "total_files": len(degree),
            "total_edges": len(edges),
        }
    return result


def vulnerability_graph(cwes: list[str]) -> dict[str, list]:
    index = KnowledgeGraphIndex(load_predefined_graph())
    nodes: dict[str, dict] = {}
    edges: set[tuple[str, str, str]] = set()

    def add(entity_id: str, role: str) -> bool:
        entity = index.entity(entity_id)
        if entity is None:
            return False
        nodes.setdefault(
            entity_id,
            {
                "id": entity_id,
                "label": entity.raw_id if entity.entity_type == "OWASP_API_RISK" else entity_id,
                "name": entity.name,
                "kind": entity.entity_type,
                "role": role,
                "description": (entity.description or "")[:320],
            },
        )
        return True

    for cwe in cwes:
        if not add(cwe, "finding"):
            continue
        nodes[cwe]["role"] = "finding"
        for relation in index.outgoing.get(cwe, []):
            if relation.relation_type == "CHILD_OF" and add(relation.target_id, "parent"):
                edges.add((cwe, relation.target_id, "CHILD_OF"))
        for risk in index.owasp_api_risks(cwe):
            add(risk.entity_id, "owasp")
            edges.add((risk.entity_id, cwe, "REFERENCES_WEAKNESS"))
        patterns = sorted(
            relation.source_id
            for relation in index.incoming.get(cwe, [])
            if relation.relation_type == "EXPLOITS_WEAKNESS"
        )
        for pattern in patterns[:MAX_ATTACK_PATTERNS_PER_CWE]:
            if add(pattern, "attack"):
                edges.add((pattern, cwe, "EXPLOITS_WEAKNESS"))
    return {
        "nodes": sorted(nodes.values(), key=lambda node: node["id"]),
        "edges": [{"source": s, "target": t, "type": kind} for s, t, kind in sorted(edges)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--assets", type=Path, default=Path("website/assets-data.js"))
    parser.add_argument("--output", type=Path, default=Path("website/graphs-data.js"))
    args = parser.parse_args()

    assets_js = args.assets.read_text(encoding="utf-8")
    match = re.search(r"const assetFindings\s*=\s*(\[.*\])\s*;?\s*$", assets_js, re.S)
    if match is None:
        raise SystemExit(f"{args.assets} does not define assetFindings")
    findings = json.loads(match.group(1))
    cwes = sorted({row["cwe"] for row in findings}, key=lambda item: int(item.split("-")[1]))
    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    repo = repository_graph(bundle, {row["path"] for row in findings})
    knowledge = vulnerability_graph(cwes)
    args.output.write_text(
        "const repoGraph = "
        + json.dumps(repo, sort_keys=True)
        + ";\nconst vulnGraph = "
        + json.dumps(knowledge, sort_keys=True)
        + ";\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "repo_services": {
                    name: [len(data["nodes"]), len(data["edges"])] for name, data in repo.items()
                },
                "vulnerability_nodes": Counter(node["role"] for node in knowledge["nodes"]),
                "vulnerability_edges": Counter(edge["type"] for edge in knowledge["edges"]),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
