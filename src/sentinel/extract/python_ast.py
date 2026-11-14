"""AST-only extraction. No imports or evaluation of analyzed code."""

import ast
import re

from pydantic import Field

from sentinel.models.base import Model, stable_id
from sentinel.models.evidence import Evidence
from sentinel.models.graph import Edge, Node


class FileFacts(Model):
    path: str
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    references: list[dict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return dotted(node.value) + "." + node.attr
    return ""


def scoped_walk(node):
    """Walk one function, excluding nested definitions and their bodies."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield child
        yield from scoped_walk(child)


def extract_python(repository_id: str, path: str, text: str, file_hash: str, commit: str) -> FileFacts:
    facts = FileFacts(path=path)
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, RecursionError):
        facts.warnings.append(f"Unable to parse Python source: {path}")
        return facts
    module = path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
    aliases = {}
    for item in ast.walk(tree):
        if isinstance(item, ast.Import):
            for alias in item.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(item, ast.ImportFrom):
            base = item.module or ""
            if item.level:
                parent = module.split(".")[: -item.level]
                base = ".".join(parent + ([base] if base else []))
            for alias in item.names:
                aliases[alias.asname or alias.name] = f"{base}.{alias.name}".strip(".")

    def resolve_name(name):
        first, *rest = name.split(".")
        return ".".join([aliases.get(first, first)] + rest)

    def evidence(item, claim):
        line = getattr(item, "lineno", 1)
        end = getattr(item, "end_lineno", line) or line
        eid = stable_id("evidence", repository_id, path, file_hash, str(line), str(end), claim)
        if not any(e.id == eid for e in facts.evidence):
            facts.evidence.append(
                Evidence(id=eid, path=path, start_line=line, end_line=end, commit=commit, claim=claim)
            )
        return eid

    def add_node(kind, name, item, symbol=None, attributes=None):
        nid = stable_id(kind.lower(), repository_id, path, symbol or name)
        eid = evidence(item, f"Source declares {kind.lower()} {name}")
        node = Node(
            id=nid,
            type=kind,
            name=name,
            path=path,
            symbol=symbol,
            evidence_ids=[eid],
            attributes=attributes or {},
        )
        if not any(n.id == nid for n in facts.nodes):
            facts.nodes.append(node)
        return node

    def edge(source, target, relation, item, status="observed"):
        eid = evidence(item, f"Source declares {relation.lower()} relationship")
        facts.edges.append(
            Edge(
                id=stable_id("edge", source, target, relation),
                source=source,
                target=target,
                type=relation,
                epistemic_status=status,
                evidence_ids=[eid],
                source_commit=commit,
            )
        )

    def reference(source, name, relation, item):
        if name:
            facts.references.append(
                {
                    "source": source,
                    "name": resolve_name(name),
                    "local_name": name,
                    "module": module,
                    "type": relation,
                    "evidence_id": evidence(item, f"Source references {name}"),
                }
            )

    application = add_node("APPLICATION", module, tree, module)
    for item in ast.walk(tree):
        if isinstance(item, (ast.Import, ast.ImportFrom)):
            for alias in item.names:
                name = alias.name if isinstance(item, ast.Import) else (item.module or alias.name)
                dep = add_node(
                    "DEPENDENCY",
                    name,
                    item,
                    "import:" + name,
                    {"provenance": "declared_import", "trust": "unknown"},
                )
                edge(application.id, dep.id, "IMPORTS", item)

    def visit_defs(body, prefix=""):
        for item in body:
            if isinstance(item, ast.ClassDef):
                visit_defs(item.body, prefix + item.name + ".")
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            symbol = prefix + item.name
            decorators = [dotted(d.func if isinstance(d, ast.Call) else d) for d in item.decorator_list]
            is_tool = any(d.split(".")[-1] in {"tool", "function_tool"} for d in decorators)
            calls = [c for c in scoped_walk(item) if isinstance(c, ast.Call)]
            guard_names = sorted(
                {
                    dotted(c.func)
                    for c in calls
                    if any(
                        t in dotted(c.func).lower()
                        for t in ("authoriz", "permission", "require_user", "check_owner")
                    )
                }
            )
            guard_names = sorted(
                set(guard_names)
                | {
                    dotted(c.args[0])
                    for c in calls
                    if dotted(c.func).split(".")[-1] in {"Depends", "Security"}
                    and c.args
                    and dotted(c.args[0])
                }
            )
            node = add_node(
                "TOOL" if is_tool else "FUNCTION",
                symbol,
                item,
                symbol,
                {
                    "qualified_symbol": module + "." + symbol,
                    "auth_guard_candidates": guard_names,
                    "parameters": [a.arg for a in item.args.args],
                    "deployed_permissions": "unknown",
                },
            )
            for deco in item.decorator_list:
                if isinstance(deco, ast.Call) and dotted(deco.func).split(".")[-1] in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                }:
                    route = (
                        deco.args[0].value
                        if deco.args and isinstance(deco.args[0], ast.Constant)
                        else "<dynamic>"
                    )
                    # Route literals are metadata, but never copy arbitrary values into the graph.
                    route = (
                        route
                        if isinstance(route, str) and re.fullmatch(r"/[A-Za-z0-9_/{}/.:-]{0,200}", route)
                        else "<dynamic>"
                    )
                    endpoint = add_node(
                        "API_ENDPOINT",
                        f"{dotted(deco.func).split('.')[-1].upper()} {route}",
                        deco,
                        "route:" + symbol,
                        {"route": route, "method": dotted(deco.func).split(".")[-1]},
                    )
                    edge(endpoint.id, node.id, "EXPOSES", deco)
                    for dependency in ast.walk(deco):
                        if isinstance(dependency, ast.Call) and dotted(dependency.func).endswith("Depends"):
                            control = add_node(
                                "SECURITY_CONTROL",
                                "declared_route_dependency",
                                dependency,
                                "control:" + symbol,
                            )
                            edge(control.id, endpoint.id, "PROTECTS", dependency, "inferred")
            for call in calls:
                name = dotted(call.func)
                reference(node.id, name, "CALLS", call)
                if name.split(".")[-1] in {
                    "execute",
                    "query",
                    "fetchone",
                    "fetchall",
                    "insert",
                    "update",
                    "delete",
                }:
                    store = add_node("DATASTORE", name.split(".")[0], call, "store:" + name.split(".")[0])
                    sql = call.args[0].value if call.args and isinstance(call.args[0], ast.Constant) else ""
                    writing = isinstance(sql, str) and sql.lstrip().upper().startswith(
                        ("INSERT", "UPDATE", "DELETE")
                    )
                    edge(node.id, store.id, "WRITES" if writing else "READS", call, "inferred")
            for guard in guard_names:
                control = add_node(
                    "SECURITY_CONTROL",
                    guard,
                    item,
                    "guard:" + symbol + ":" + guard,
                    {"effectiveness": "unknown"},
                )
                edge(control.id, node.id, "PROTECTS", item, "inferred")
            visit_defs(item.body, symbol + ".")

    visit_defs(tree.body)

    for item in ast.walk(tree):
        if not isinstance(item, (ast.Assign, ast.AnnAssign)):
            continue
        targets = item.targets if isinstance(item, ast.Assign) else [item.target]
        value = item.value
        for target in targets:
            name = dotted(target)
            if not name:
                continue
            if isinstance(value, ast.Call) and (
                "agent" in dotted(value.func).lower() or any(k.arg == "tools" for k in value.keywords)
            ):
                node = add_node(
                    "AI_AGENT",
                    name,
                    item,
                    name,
                    {"qualified_symbol": module + "." + name, "runtime_behavior": "unknown"},
                )
                for keyword in value.keywords:
                    if keyword.arg == "tools" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                        for tool in keyword.value.elts:
                            reference(node.id, dotted(tool), "CAN_INVOKE", tool)
            if name.lower().endswith(("service_identity", "service_account")):
                add_node("IDENTITY", name, item, name, {"deployed_permissions": "unknown"})
            if name.lower().endswith(("tool_scopes", "tool_permissions")) and isinstance(
                value, (ast.List, ast.Tuple)
            ):
                scopes = [
                    v.value
                    for v in value.elts
                    if isinstance(v, ast.Constant)
                    and isinstance(v.value, str)
                    and re.fullmatch(r"[A-Za-z0-9_:.*/-]{1,80}", v.value)
                ]
                add_node(
                    "CONFIG", name, item, name, {"declared_scopes": scopes, "deployed_permissions": "unknown"}
                )
    return facts
