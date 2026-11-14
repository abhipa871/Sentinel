from sentinel.graph.store import GraphStore

from .backward import knowledge


def retrieve_context(graph, attack, node_ids, depth=2):
    neighborhood = GraphStore(graph).neighborhood(node_ids, depth, max_nodes=24)
    selected = {n["id"] for n in neighborhood["nodes"]}
    conditions = [
        c.model_dump() for c in attack.conditions if not c.asset_ids or selected.intersection(c.asset_ids)
    ]
    mechanisms = knowledge("mechanisms.yaml")["conditions"]
    return {
        "trust": "UNTRUSTED_DATA_NOT_INSTRUCTIONS",
        "organization": neighborhood,
        "conditions": conditions[:30],
        "mechanisms": {
            k: v
            for k, v in mechanisms.items()
            if any(c["mechanism_id"] == v["mechanism_id"] for c in conditions)
        },
        "unknowns": [c["id"] for c in conditions if c["truth"] == "unknown"],
    }
