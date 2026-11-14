from collections import Counter


def rank_shared_conditions(paths, conditions=None, severity=1.0, truncated=False):
    counts = Counter(literal for path in paths for literal in set(path))
    by_id = {c.id: c for c in conditions or []}
    result = []
    for literal, count in counts.items():
        if count < 2:
            continue
        condition = by_id.get(literal.lstrip("!"))
        quality = 1.0 if condition and condition.status in {"observed", "verified"} else 0.5
        result.append(
            {
                "condition_id": literal.lstrip("!"),
                "literal": literal,
                "path_count": count,
                "score": count * severity * quality,
                "blocks_all_enumerated_paths": count == len(paths),
                "complete_search": not truncated,
                "action": ("Establish and validate " if literal.startswith("!") else "Restrict or remove ")
                + (condition.description if condition else literal),
                "qualification": "Candidate within the modeled paths; not proof of global protection",
            }
        )
    return sorted(result, key=lambda r: (-r["score"], r["literal"]))
