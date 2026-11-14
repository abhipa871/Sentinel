"""Typed Deep Agents proposals and their deterministic trust boundary."""

from pathlib import PurePosixPath

from sentinel.models.agentic import GraphDelta
from sentinel.models.base import stable_id
from sentinel.models.evidence import Evidence
from sentinel.models.finding import SourceLocation, StaticFinding
from sentinel.models.graph import Edge, Node, OrganizationGraph


def safe_source_slice(context, path: str, start_line: int, end_line: int):
    snapshot = context.run.snapshot
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or "\\" in path or ":" in path:
        raise ValueError("Unsafe source path")
    if path not in snapshot.files:
        raise ValueError("Source path is outside the authorized snapshot")
    lines = snapshot.files[path].splitlines()
    end_line = min(end_line, max(1, len(lines)))
    if not 1 <= start_line <= end_line <= max(1, len(lines)) or end_line - start_line > 199:
        raise ValueError("Source slice exceeds bounds")
    selected = lines[start_line - 1 : end_line]
    rendered = "\n".join(f"{number}: {line}" for number, line in enumerate(selected, start_line))
    if len(rendered) > 12_000:
        raise ValueError("Source slice exceeds response budget")
    eid = stable_id(
        "agent-source",
        snapshot.repository_id,
        path,
        snapshot.hashes[path],
        str(start_line),
        str(end_line),
    )
    context.source_evidence[eid] = Evidence(
        id=eid,
        path=path,
        start_line=start_line,
        end_line=end_line,
        commit=snapshot.commit,
        claim="Bounded source slice supplied to Deep Agents as untrusted data",
        status="observed",
        source_hash=snapshot.hashes[path],
    )
    return {
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "evidence_id": eid,
        "source": rendered,
    }


def validate_graph_delta(context, raw) -> GraphDelta:
    delta = GraphDelta.model_validate({"nodes": raw.get("nodes", []), "edges": raw.get("edges", [])})
    evidence = {e.id for e in context.run.graph.evidence} | set(context.source_evidence)
    snapshot = context.run.snapshot
    existing = {node.id for node in context.run.graph.nodes}
    proposed = {node.key for node in delta.nodes}
    for node in delta.nodes:
        if node.path is not None and node.path not in snapshot.files:
            raise ValueError("Graph proposal path is outside the authorized snapshot")
        if not set(node.evidence_ids) <= evidence:
            raise ValueError("Graph proposal cites fabricated evidence")
    for edge in delta.edges:
        if edge.source not in existing | proposed or edge.target not in existing | proposed:
            raise ValueError("Graph proposal edge has an unknown endpoint")
        if not set(edge.evidence_ids) <= evidence:
            raise ValueError("Graph proposal cites fabricated evidence")
    return delta


def apply_graph_deltas(context):
    graph = context.run.graph
    evidence = {item.id: item for item in graph.evidence}
    evidence.update(context.source_evidence)
    nodes = {item.id: item for item in graph.nodes}
    edges = {item.id: item for item in graph.edges}
    for delta in context.graph_deltas:
        keys = {}
        for item in delta.nodes:
            node_id = stable_id(
                "agent-node",
                context.run.snapshot.repository_id,
                item.type,
                item.path or "",
                item.symbol or "",
                item.name,
            )
            keys[item.key] = node_id
            nodes[node_id] = Node(
                id=node_id,
                type=item.type,
                name=item.name,
                path=item.path,
                symbol=item.symbol,
                evidence_ids=sorted(set(item.evidence_ids)),
                attributes={**item.attributes, "producer": "deepagents", "epistemic_status": "inferred"},
            )
        for item in delta.edges:
            source, target = keys.get(item.source, item.source), keys.get(item.target, item.target)
            edge_id = stable_id("agent-edge", source, target, item.type)
            edges[edge_id] = Edge(
                id=edge_id,
                source=source,
                target=target,
                type=item.type,
                epistemic_status=item.epistemic_status,
                evidence_ids=sorted(set(item.evidence_ids)),
                source_commit=context.run.snapshot.commit,
                attributes={**item.attributes, "producer": "deepagents"},
            )
    graph.evidence[:] = sorted(evidence.values(), key=lambda item: item.id)
    graph.nodes[:] = sorted(nodes.values(), key=lambda item: item.id)
    graph.edges[:] = sorted(edges.values(), key=lambda item: item.id)
    OrganizationGraph.model_validate(graph.model_dump())


def finding_proposal_id(context, proposal):
    return stable_id(
        "agent-finding",
        context.run.snapshot.repository_id,
        proposal.path,
        str(proposal.sink_start_line),
        proposal.cwe,
        proposal.symbol,
    )


def build_findings(context):
    evidence = {item.id: item for item in context.run.graph.evidence}
    evidence.update(context.source_evidence)
    findings = {}
    for proposal in context.finding_proposals:
        ids = set(proposal.source_evidence_ids + proposal.sink_evidence_ids)
        if not ids <= set(evidence):
            raise ValueError("Finding proposal cites fabricated evidence")
        if proposal.path not in context.run.snapshot.files:
            raise ValueError("Finding proposal is outside the authorized snapshot")
        line_count = max(1, len(context.run.snapshot.files[proposal.path].splitlines()))
        if proposal.sink_end_line > line_count:
            raise ValueError("Finding sink is outside the source file")
        trace = []
        for evidence_id in proposal.source_evidence_ids:
            item = evidence[evidence_id]
            trace.append(
                SourceLocation(
                    path=item.path, start_line=item.start_line, end_line=item.end_line, role="source"
                )
            )
        sink = SourceLocation(
            path=proposal.path,
            start_line=proposal.sink_start_line,
            end_line=proposal.sink_end_line,
            role="sink",
        )
        trace.append(sink)
        finding_id = finding_proposal_id(context, proposal)
        mapped_outcome = context.outcome_mappings.get(finding_id)
        findings[finding_id] = StaticFinding(
            id=finding_id,
            rule_id="deepagents-" + proposal.cwe.lower(),
            cwe=proposal.cwe,
            title=proposal.title,
            path=proposal.path,
            symbol=proposal.symbol,
            sink=sink,
            trace=trace,
            evidence_ids=sorted(ids),
            confidence=proposal.confidence,
            dangerous_outcome=mapped_outcome.outcome_id if mapped_outcome else None,
            assumptions=proposal.assumptions or ["The modeled code path executes in deployment"],
            unknowns=proposal.unknowns or ["Runtime reachability and deployed controls are unverified"],
            interruption_points=proposal.interruption_points,
        )
    return sorted(findings.values(), key=lambda item: (item.path, item.sink.start_line, item.cwe))
