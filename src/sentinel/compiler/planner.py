from sentinel.models.base import digest, stable_id
from sentinel.models.investigation import InvestigationQuestion, InvestigationRequest
from sentinel.models.workflow import TaskIR, WorkflowIR
from sentinel.reasoning.schema_validation import validate_request
from sentinel.runtime.policy import validate_workflow

from .passes import deduplicate, eliminate_dead_tasks, topological_schedule


def default_requests(context):
    conditions = context.attack.conditions
    groups = [("authorization", "inspect_auth"), ("agent_tools", "inspect_agent_tools")]
    requests = []
    for hypothesis, analyzer in groups:
        relevant = [c for c in conditions if c.analyzer == analyzer]
        questions = [
            InvestigationQuestion(
                hypothesis_id=hypothesis,
                condition_id=c.id,
                analyzer=analyzer,
                evidence_ids=c.evidence_ids,
                reason=c.description,
            )
            for c in relevant
        ]
        if conditions:
            questions.insert(
                0,
                InvestigationQuestion(
                    hypothesis_id=hypothesis,
                    condition_id=conditions[0].id,
                    analyzer="retrieve_graph",
                    reason="Retrieve shared causal context",
                ),
            )
        requests.append(InvestigationRequest(outcome_id=context.attack.outcome_id, questions=questions[:12]))
    return requests


def compile_request(request, context):
    request = validate_request(request, context.graph, context.attack)
    nodes = {n.id: n for n in context.graph.nodes}
    conditions = {c.id: c for c in context.attack.conditions}
    tasks, outputs = [], []

    def add(kind, inputs, files, node_ids, deps=(), evidence=()):
        files = set(files)
        if kind == "inspect_agent_tools":
            # A tool's declarations may live in another source file. Include both
            # ends so a changed agent declaration invalidates tool inspections.
            for edge in context.graph.edges:
                if edge.type == "CAN_INVOKE" and set(node_ids).intersection({edge.source, edge.target}):
                    files.update(nodes[i].path for i in (edge.source, edge.target) if nodes[i].path)
        task_id = stable_id("task", kind, digest(inputs), context.snapshot.repository_id)
        # Duplicate requests deliberately reach CSE before task IDs are canonicalized.
        instance_id = task_id + ":" + str(len(tasks))
        task = TaskIR(
            id=instance_id,
            kind=kind,
            inputs=inputs,
            depends_on=list(deps),
            evidence_requirements=list(evidence),
            file_dependencies=sorted(set(files)),
            node_dependencies=sorted(set(node_ids)),
            cacheable=kind != "mock_verify",
            sandbox_required=kind == "mock_verify",
        )
        tasks.append(task)
        return instance_id

    def graph_task():
        ids = sorted({asset for c in context.attack.conditions for asset in c.asset_ids})[:20]
        # Conservative dependency closure: changes anywhere can alter a neighborhood.
        return add("retrieve_graph", {"node_ids": ids, "depth": 2}, context.snapshot.files, ids)

    for question in request.questions:
        condition = conditions[question.condition_id]
        if question.analyzer == "retrieve_graph":
            outputs.append(graph_task())
        elif question.analyzer == "mock_verify":
            dependencies = [graph_task()]
            for analyzer in ("inspect_auth", "inspect_agent_tools"):
                for c in context.attack.conditions:
                    if c.analyzer != analyzer:
                        continue
                    for asset in c.asset_ids:
                        node = nodes[asset]
                        if node.path:
                            source = add(
                                "inspect_source",
                                {"path": node.path, "node_ids": [asset]},
                                [node.path],
                                [asset],
                            )
                            dependencies.append(
                                add(
                                    analyzer,
                                    {"path": node.path, "node_ids": [asset]},
                                    [node.path],
                                    [asset],
                                    [source],
                                )
                            )
            outputs.append(add("mock_verify", {"fixture_id": question.fixture_id}, [], [], dependencies))
        else:
            for asset in condition.asset_ids:
                node = nodes[asset]
                if not node.path:
                    continue
                inputs = {"path": node.path, "node_ids": [asset]}
                source = add("inspect_source", inputs, [node.path], [asset], evidence=question.evidence_ids)
                output = (
                    source
                    if question.analyzer == "inspect_source"
                    else add(question.analyzer, inputs, [node.path], [asset], [source], question.evidence_ids)
                )
                outputs.append(output)
            if not condition.asset_ids:
                outputs.append(graph_task())
    tasks, outputs = deduplicate(tasks, outputs, context.snapshot.commit, context.policy_context)
    tasks = eliminate_dead_tasks(tasks, outputs)
    hypothesis = request.questions[0].hypothesis_id if request.questions else "resolved"
    workflow = WorkflowIR(
        id=stable_id("workflow", hypothesis, context.snapshot.commit, request.model_dump_json()),
        hypothesis_id=hypothesis,
        repository_commit=context.snapshot.commit,
        tasks=tasks,
        outputs=outputs,
        scope="mock_sandbox" if any(t.kind == "mock_verify" for t in tasks) else "read_only",
        schedule=topological_schedule(tasks),
        policy_version=context.policy_version,
        passes=[
            "specialization",
            "dependency_lowering",
            "common_subexpression_elimination",
            "cache_keys_at_execution",
            "dead_task_elimination",
            "parallel_schedule",
            "policy_validation",
        ],
    )
    validate_workflow(workflow, context)
    return workflow


def specialize_remaining(request, context, resolved_condition_ids):
    """Recompile only unresolved questions; callers must supply trusted resolution evidence."""
    remaining = request.model_copy(
        update={"questions": [q for q in request.questions if q.condition_id not in resolved_condition_ids]}
    )
    return compile_request(remaining, context)
