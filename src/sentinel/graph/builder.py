from sentinel.extract.configs import extract_config
from sentinel.extract.python_ast import FileFacts, extract_python
from sentinel.models.base import stable_id
from sentinel.models.graph import Edge, Node, OrganizationGraph


def extract_files(snapshot, previous: dict[str, FileFacts] | None = None, previous_hashes=None):
    previous, previous_hashes = previous or {}, previous_hashes or {}
    facts, extracted = {}, []
    for path, text in sorted(snapshot.files.items()):
        if path in previous and snapshot.hashes[path] == previous_hashes.get(path):
            facts[path] = previous[path]
        else:
            parser = extract_python if path.endswith(".py") else extract_config
            facts[path] = parser(snapshot.repository_id, path, text, snapshot.hashes[path], snapshot.commit)
            extracted.append(path)
    return facts, extracted


def build_graph(snapshot, facts: dict[str, FileFacts]) -> OrganizationGraph:
    nodes, edges, evidence = {}, {}, {}
    for file in facts.values():
        nodes.update((n.id, n.model_copy(deep=True)) for n in file.nodes)
        edges.update((e.id, e.model_copy(update={"source_commit": snapshot.commit})) for e in file.edges)
        evidence.update((e.id, e.model_copy(update={"commit": snapshot.commit})) for e in file.evidence)
    symbols = {}
    for node in nodes.values():
        symbol = node.attributes.get("qualified_symbol")
        if symbol:
            symbols[symbol] = node.id
    for file in facts.values():
        for ref in file.references:
            target = symbols.get(ref["name"]) or symbols.get(ref["module"] + "." + ref["local_name"])
            status = "observed"
            if target is None and ref["name"].rsplit(".", 1)[-1] in {"invoke", "ainvoke", "run"}:
                receiver = ref["name"].rsplit(".", 1)[0]
                receiver_id = symbols.get(receiver) or symbols.get(ref["module"] + "." + receiver)
                if receiver_id and nodes[receiver_id].type == "AI_AGENT":
                    target = receiver_id
            if target is None:
                # No global basename guesses: unresolved references remain external dependencies.
                target = stable_id("dependency", snapshot.repository_id, file.path, ref["name"])
                nodes.setdefault(
                    target,
                    Node(
                        id=target,
                        type="DEPENDENCY",
                        name=ref["name"],
                        path=file.path,
                        evidence_ids=[ref["evidence_id"]],
                        attributes={"resolution": "unknown", "trust": "unknown"},
                    ),
                )
                status = "inferred"
            relation = ref["type"]
            eid = stable_id("edge", ref["source"], target, relation)
            if eid in edges:
                edges[eid].evidence_ids = sorted(set(edges[eid].evidence_ids + [ref["evidence_id"]]))
            else:
                edges[eid] = Edge(
                    id=eid,
                    source=ref["source"],
                    target=target,
                    type=relation,
                    epistemic_status=status,
                    evidence_ids=[ref["evidence_id"]],
                    source_commit=snapshot.commit,
                )
    # Co-location suggests a question, never an observed deployed identity binding.
    for identity in [n for n in nodes.values() if n.type == "IDENTITY"]:
        for function in [n for n in nodes.values() if n.type == "FUNCTION" and n.path == identity.path]:
            eid = stable_id("edge", function.id, identity.id, "RUNS_AS")
            edges[eid] = Edge(
                id=eid,
                source=function.id,
                target=identity.id,
                type="RUNS_AS",
                epistemic_status="unknown",
                evidence_ids=identity.evidence_ids,
                source_commit=snapshot.commit,
                attributes={"basis": "co-located identity declaration; deployment binding unconfirmed"},
            )
    return OrganizationGraph(
        nodes=sorted(nodes.values(), key=lambda n: n.id),
        edges=sorted(edges.values(), key=lambda e: e.id),
        evidence=sorted(evidence.values(), key=lambda e: e.id),
    )
