"""Deep Agents finding feedback, kept separate from runtime claims."""

from sentinel.models.attack import AttackGraph, Condition, Formula
from sentinel.models.base import stable_id
from sentinel.models.graph import Edge, Node
from sentinel.models.report import ScenarioReport


def attach_agent_findings(context, findings, source_evidence):
    """Attach validated Deep Agents findings without changing their inferred status."""
    evidence = {item.id: item for item in context.graph.evidence}
    evidence.update(source_evidence)
    context.graph.evidence[:] = sorted(evidence.values(), key=lambda item: item.id)
    nodes = {item.id: item for item in context.graph.nodes}
    edges = {item.id: item for item in context.graph.edges}
    by_path = {}
    for node in nodes.values():
        by_path.setdefault(node.path, []).append(node)
    for finding in findings:
        nodes[finding.id] = Node(
            id=finding.id,
            type="SECURITY_STATE",
            name=finding.title,
            path=finding.path,
            evidence_ids=finding.evidence_ids,
            attributes={
                "finding_id": finding.id,
                "cwe": finding.cwe,
                "status": finding.status,
                "epistemic_status": "inferred",
                "runtime_verified": False,
                "producer": "deepagents",
            },
        )
        owners = [
            node
            for node in by_path.get(finding.path, [])
            if node.symbol and finding.symbol.endswith("." + node.symbol)
        ]
        for owner in owners[:1]:
            owner.attributes.setdefault("static_finding_ids", []).append(finding.id)
            edge_id = stable_id("edge", owner.id, finding.id, "MAY_ENABLE")
            edges[edge_id] = Edge(
                id=edge_id,
                source=owner.id,
                target=finding.id,
                type="MAY_ENABLE",
                epistemic_status="inferred",
                evidence_ids=finding.evidence_ids,
                source_commit=context.snapshot.commit,
                attributes={"producer": "deepagents"},
            )
        for evidence_id in finding.evidence_ids:
            item = evidence[evidence_id]
            node_id = stable_id("evidence-node", evidence_id)
            nodes[node_id] = Node(
                id=node_id,
                type="EVIDENCE",
                name="Agent-reviewed source span",
                path=item.path,
                evidence_ids=[evidence_id],
            )
            edge_id = stable_id("edge", finding.id, node_id, "SUPPORTED_BY_EVIDENCE")
            edges[edge_id] = Edge(
                id=edge_id,
                source=finding.id,
                target=node_id,
                type="SUPPORTED_BY_EVIDENCE",
                epistemic_status="observed",
                evidence_ids=[evidence_id],
                source_commit=context.snapshot.commit,
            )
    context.graph.nodes[:] = sorted(nodes.values(), key=lambda item: item.id)
    context.graph.edges[:] = sorted(edges.values(), key=lambda item: item.id)


def finding_attack_graph(finding):
    if not finding.dangerous_outcome:
        raise ValueError("Generic finding has not been mapped to an authorized dangerous outcome")
    flow = Condition(
        id=finding.id + ":static_flow",
        description=finding.title,
        asset_ids=[finding.id],
        status="inferred",
        truth="true",
        evidence_ids=finding.evidence_ids,
        mechanism_id=finding.cwe,
        analyzer="inspect_source",
        binding="source_finding",
    )
    runtime = Condition(
        id=finding.id + ":runtime_reachability",
        description="The modeled operation is reachable in deployment",
        asset_ids=[finding.id],
        status="unknown",
        truth="unknown",
        mechanism_id=finding.cwe,
        analyzer="inspect_source",
        binding="runtime",
        assumptions=finding.assumptions,
    )
    boundary = Condition(
        id=finding.id + ":effective_external_control",
        description="An independent control blocks this path",
        asset_ids=[finding.id],
        status="unknown",
        truth="unknown",
        mechanism_id=finding.cwe,
        analyzer="inspect_auth",
        binding="runtime_control",
    )
    formula = Formula(
        op="AND",
        children=[
            Formula(condition_id=flow.id),
            Formula(condition_id=runtime.id),
            Formula(op="NOT", children=[Formula(condition_id=boundary.id)]),
        ],
    )
    return AttackGraph(
        outcome_id=finding.dangerous_outcome,
        formula=formula,
        conditions=[flow, runtime, boundary],
        paths=[[flow.id, runtime.id, "!" + boundary.id]],
        bounds={"max_depth": 3, "max_paths": 1, "truncated": False},
        limitations=["A statically supported flow does not verify a deployed attack"],
    )


def finding_scenario(finding):
    if not finding.dangerous_outcome:
        raise ValueError("Generic finding has not been mapped to an authorized dangerous outcome")
    attack = finding_attack_graph(finding)
    return ScenarioReport(
        scenario_id=stable_id("scenario", finding.id),
        title=finding.title,
        status="static_supported",
        finding_ids=[finding.id],
        dangerous_outcome=finding.dangerous_outcome,
        required_conditions=[
            {**c.model_dump(), "required_truth": "false" if c.binding == "runtime_control" else "true"}
            for c in attack.conditions
        ],
        possible_impact=f"Potential {finding.dangerous_outcome.replace('_', ' ')} if the modeled path executes",
        critical_dependencies=[finding.id],
        alternate_routes=["Other entry points and deployment routes are not exhaustively modeled"],
        interruption_points=[
            {"action": text, "qualification": "Validate effectiveness on the actual code path"}
            for text in finding.interruption_points
        ],
        verified_facts=[],
        assumptions=finding.assumptions,
        unknowns=finding.unknowns,
        evidence_ids=finding.evidence_ids,
        confidence_evidence={
            "level": "static_supported",
            "epistemic_status": "inferred",
            "cwe": finding.cwe,
            "path": finding.path,
            "line": finding.sink.start_line,
            "numeric_probability": None,
            "runtime_verified": False,
        },
    )
