"""Neutral AST facts for agents; this module never classifies security behavior."""

import ast

from .semantic import safe_source_slice


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _names(node):
    return sorted({item.id for item in ast.walk(node) if isinstance(item, ast.Name)})[:40]


def _span(context, path, node):
    start = getattr(node, "lineno", 1)
    end = min(getattr(node, "end_lineno", start) or start, start + 20)
    evidence = safe_source_slice(context, path, start, end)
    return {
        "start_line": start,
        "end_line": end,
        "evidence_id": evidence["evidence_id"],
    }


def extract_neutral_syntax_facts(context, path):
    """Return bounded syntax/data-reference facts without source/sink or CWE judgments."""
    if path not in context.run.snapshot.files:
        raise ValueError("Syntax fact path is outside the authorized snapshot")
    text = context.run.snapshot.files[path]
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, RecursionError):
        return {"path": path, "parse_status": "failed", "assignments": [], "calls": [], "returns": []}

    assignments, calls, returns = [], [], []
    for node in ast.walk(tree):
        if len(assignments) + len(calls) + len(returns) >= 240:
            break
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            assignments.append(
                {
                    **_span(context, path, node),
                    "targets": [_dotted(item) for item in targets if _dotted(item)],
                    "value_kind": type(value).__name__,
                    "referenced_names": _names(value),
                }
            )
        elif isinstance(node, ast.Call):
            calls.append(
                {
                    **_span(context, path, node),
                    "callee": _dotted(node.func),
                    "arguments": [
                        {"kind": type(argument).__name__, "referenced_names": _names(argument)}
                        for argument in node.args[:12]
                    ],
                    "keywords": [
                        {
                            "name": keyword.arg,
                            "kind": type(keyword.value).__name__,
                            "referenced_names": _names(keyword.value),
                        }
                        for keyword in node.keywords[:12]
                    ],
                }
            )
        elif isinstance(node, ast.Return):
            returns.append(
                {
                    **_span(context, path, node),
                    "value_kind": type(node.value).__name__ if node.value else "None",
                    "referenced_names": _names(node.value) if node.value else [],
                }
            )
    return {
        "path": path,
        "parse_status": "parsed",
        "assignments": assignments,
        "calls": calls,
        "returns": returns,
        "truncated": len(assignments) + len(calls) + len(returns) >= 240,
        "semantics": "unclassified_syntax_only",
    }
