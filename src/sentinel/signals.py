"""Reviewed, language-aware static security signals for Phase 0.

Signals are syntactic observations with exact line spans. They are *not* findings: Module I
rules combine them into potential candidates and Module II decides applicability. Comments and
docstrings are blanked before matching so that repository prose (which is hostile data, and in
benchmark repos often names the vulnerability outright) cannot drive candidate generation.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|testdata|fixtures?)(/|$|\.py$)|(^|/)test_[^/]*\.py$|_test\.(go|py)$"
    r"|\.(spec|test)\.[jt]sx?$|(^|/)[^/]*Tests?\.java$"
)


@dataclass(frozen=True)
class SignalHit:
    name: str
    line: int
    excerpt: str


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH.search(path))


def _blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def strip_comments(text: str, language: str | None) -> str:
    """Blank comments/docstrings while preserving line numbers."""
    if language == "python":
        text = re.sub(r'("""|\'\'\')(?:.|\n)*?\1', _blank, text)
        return re.sub(r"(?m)#.*$", _blank, text)
    if language in {"java", "go", "javascript", "typescript", "rust"}:
        text = re.sub(r"/\*(?:.|\n)*?\*/", _blank, text)
        return re.sub(r"(?m)(?<![:\"'])//.*$", _blank, text)
    return text


IGNORE_CASE = re.IGNORECASE
# name -> {language: [patterns]}; "*" applies to every source language.
PATTERNS: dict[str, dict[str, list[re.Pattern[str]]]] = {
    "route_handler": {
        "python": [
            re.compile(r"@\w+(?:\.\w+)*\.(?:route|get|post|put|delete|api_route)\("),
            re.compile(r"^\s*def (?:get|post|put|patch|delete)\(self,\s*request", re.M),
        ],
        "java": [re.compile(r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b")],
        "go": [
            re.compile(r"\.(?:HandleFunc|Handle)\(|\.Methods\(\"|\.(?:GET|POST|PUT|DELETE)\(\"")
        ],
        "javascript": [re.compile(r"\b(?:app|router)\.(?:get|post|put|delete|patch)\(")],
        "typescript": [re.compile(r"\b(?:app|router)\.(?:get|post|put|delete|patch)\(")],
    },
    "object_id_param": {
        "python": [
            re.compile(r"request\.(?:GET|query_params|data)\[\s*[\"']\w*id[\"']\s*\]", IGNORE_CASE),
            re.compile(r"\b\w+_id\s*=\s*None\b"),
            re.compile(r"<(?:int|uuid|str):\w*id>|\(\?P<\w*id>", IGNORE_CASE),
        ],
        "java": [re.compile(r"@PathVariable|@RequestParam\(\s*\"?\w*id", IGNORE_CASE)],
        "go": [re.compile(r"mux\.Vars\(|URL\.Query\(\)\.Get\(\"\w*id", IGNORE_CASE)],
        "javascript": [re.compile(r"req\.(?:params|query)\.\w*id", IGNORE_CASE)],
        "typescript": [re.compile(r"req\.(?:params|query)\.\w*id", IGNORE_CASE)],
    },
    "lookup_by_client_id": {
        "python": [
            re.compile(r"\.objects\.(?:get|filter)\(\s*(?:id|pk|\w+_id)\s*=\s*(?!user\b)\w")
        ],
        "java": [
            re.compile(
                r"\.(?:findById|findByUuid|findBy\w*Id|getById|getReferenceById)\(\s*(?!user)"
            )
        ],
        "go": [re.compile(r"\.(?:First|Find|Where|FindOne)\([^)]*\b(?:id|ID|Id)\b")],
        "javascript": [re.compile(r"\.(?:findById|findByPk|findOne)\(\s*req\.")],
        "typescript": [re.compile(r"\.(?:findById|findByPk|findOne)\(\s*req\.")],
    },
    "admin_route": {
        "java": [re.compile(r"Mapping\(\s*(?:value\s*=\s*)?\"[^\"]*/admin/", IGNORE_CASE)],
        "python": [re.compile(r"(?:path|re_path|url|route)\(\s*r?[\"'][^\"']*admin", IGNORE_CASE)],
        "go": [re.compile(r"\"[^\"]*/admin/[^\"]*\"", IGNORE_CASE)],
    },
    "auth_sensitive_route": {
        "java": [
            re.compile(
                r"Mapping\(\s*(?:value\s*=\s*)?\"[^\"]*(?:otp|login|password|reset|token)",
                IGNORE_CASE,
            )
        ],
        "python": [
            re.compile(
                r"(?:path|re_path|url|route|post)\(\s*r?[\"'][^\"']*(?:otp|login|password|reset)",
                IGNORE_CASE,
            )
        ],
        "go": [re.compile(r"HandleFunc\(\s*\"[^\"]*(?:otp|login|password|reset)", IGNORE_CASE)],
    },
    "rate_limit_marker": {
        "*": [
            re.compile(
                r"ratelimit|rate_limit|throttl|bucket4j|RateLimiter|max_?attempts|lockout",
                IGNORE_CASE,
            )
        ],
    },
    "outbound_request_dynamic": {
        "python": [
            re.compile(
                r"\b(?:requests|httpx|session)\.(?:get|post|put|request|head)\(\s*(?![\"'f])\w"
            ),
            re.compile(r"\burlopen\(\s*(?![\"'])\w"),
        ],
        "java": [re.compile(r"\.openConnection\(|new URL\(\s*(?!\")|RestTemplate|WebClient\.")],
        "go": [re.compile(r"http\.(?:Get|Post|NewRequest)\(\s*(?:\"[A-Z]+\",\s*)?(?!\")\w")],
        "javascript": [re.compile(r"\b(?:axios\.\w+|fetch|got)\(\s*(?![\"'`])\w")],
        "typescript": [re.compile(r"\b(?:axios\.\w+|fetch|got)\(\s*(?![\"'`])\w")],
    },
    "request_repeat_param": {
        "*": [re.compile(r"[\"']\w*(?:repeat|retries|retry|times|number_of)\w*[\"']", IGNORE_CASE)],
    },
    "raw_sql_concat": {
        "python": [
            re.compile(
                r"\.(?:execute|executemany|raw)\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:\+|%|\.format))"
            )
        ],
        "java": [re.compile(r"create(?:Native)?Query\([^;]*\+|createStatement\(\)")],
        "go": [re.compile(r"\.(?:Raw|Exec|Query)\(\s*(?:fmt\.Sprintf|\"[^\"]*\"\s*\+)")],
        "javascript": [re.compile(r"\.(?:query|raw)\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)")],
        "typescript": [re.compile(r"\.(?:query|raw)\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)")],
    },
    "nosql_query": {
        "go": [re.compile(r"\.(?:Find|FindOne|UpdateOne|DeleteOne|Aggregate)\(")],
        "python": [re.compile(r"\.(?:find|find_one|update_one|delete_one|aggregate)\(")],
        "javascript": [re.compile(r"\.(?:find|findOne|updateOne|deleteOne|aggregate)\(|\$where")],
        "typescript": [re.compile(r"\.(?:find|findOne|updateOne|deleteOne|aggregate)\(|\$where")],
    },
    "untyped_request_filter": {
        "go": [re.compile(r"var \w+ (?:bson\.M|map\[string\]interface\{\})|\w+ bson\.M\)")],
        "python": [re.compile(r"json\.loads\(\s*request|=\s*request\.(?:data|json)\s*$", re.M)],
        "javascript": [re.compile(r"\.(?:find|findOne)\(\s*req\.(?:body|query)")],
        "typescript": [re.compile(r"\.(?:find|findOne)\(\s*req\.(?:body|query)")],
    },
    "request_body_input": {
        "python": [re.compile(r"request\.(?:data|GET|POST|body|json|query_params)\b|request_data")],
        "java": [re.compile(r"@RequestBody|@RequestParam|HttpServletRequest")],
        "go": [re.compile(r"r\.Body|ReadAll\(r|r\.URL\.Query|json\.Unmarshal\(")],
        "javascript": [re.compile(r"req\.(?:body|query|params)")],
        "typescript": [re.compile(r"req\.(?:body|query|params)")],
    },
    "attr_from_request": {
        "python": [re.compile(r"\b\w+\.\w+\s*=\s*(?:request_data|request\.data)\[")],
        "java": [re.compile(r"\.set\w+\(\s*\w+(?:Form|Request|Dto|DTO)\.get\w+\(\)")],
        "go": [re.compile(r"Decode\(&\w+\)")],
        "javascript": [re.compile(r"Object\.assign\(\s*\w+,\s*req\.body|\.update\(\s*req\.body")],
        "typescript": [re.compile(r"Object\.assign\(\s*\w+,\s*req\.body|\.update\(\s*req\.body")],
    },
    "serializer_all_fields": {
        "python": [re.compile(r"fields\s*=\s*[\"']__all__[\"']")],
    },
    "jwt_header_trust": {
        "java": [
            re.compile(
                r"getAlgorithm\(\)|getJWKURL\(\)|parseUnverified|Algorithm\.none|alg\.getName\(\)"
            )
        ],
        "python": [
            re.compile(
                r"get_unverified_header|verify_signature[\"']?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False"
            )
        ],
        "go": [re.compile(r"token\.Header\[\s*\"(?:alg|kid|jku)\"")],
        "javascript": [re.compile(r"jwt\.decode\(|algorithms\s*:\s*\[[^\]]*none", IGNORE_CASE)],
        "typescript": [re.compile(r"jwt\.decode\(|algorithms\s*:\s*\[[^\]]*none", IGNORE_CASE)],
    },
    "sensitive_json_field": {
        "go": [
            re.compile(
                r"json:\"(?:email|password|vehicleid|vin|phone\w*|ssn|token|api_?key)\"",
                IGNORE_CASE,
            )
        ],
    },
    "jpa_entity_unfiltered": {
        "java": [re.compile(r"^@Entity\b", re.M)],
    },
    "json_ignore_marker": {
        "java": [re.compile(r"@JsonIgnore|JsonProperty\.Access")],
    },
    "llm_client": {
        "python": [
            re.compile(
                r"\b(?:ChatOpenAI|AzureChatOpenAI|ChatAnthropic|ChatBedrock\w*|init_chat_model|OpenAI)\("
            )
        ],
        "javascript": [re.compile(r"new OpenAI\(|ChatOpenAI\(")],
        "typescript": [re.compile(r"new OpenAI\(|ChatOpenAI\(")],
    },
    "llm_tools_or_agent": {
        "python": [
            re.compile(
                r"create_react_agent|bind_tools|AgentExecutor|initialize_agent|StateGraph\(|MultiServerMCPClient|get_tools\("
            )
        ],
        "javascript": [re.compile(r"tools\s*:\s*\[|createReactAgent")],
        "typescript": [re.compile(r"tools\s*:\s*\[|createReactAgent")],
    },
    "tool_server": {
        "python": [re.compile(r"FastMCP|@\w+\.tool\b|from_openapi\(")],
    },
    "static_service_credential": {
        "python": [
            re.compile(
                r"(?:api_?key|token|secret)\w*\s*=\s*(?:os\.(?:environ|getenv)|config|settings)",
                IGNORE_CASE,
            ),
            re.compile(r"[\"']Authorization[\"']\s*:\s*f?[\"'](?:Bearer|ApiKey)", IGNORE_CASE),
        ],
    },
}


def _python_unauthenticated_handlers(text: str) -> list[SignalHit]:
    """HTTP handler methods/functions with no auth decorator or class permission policy."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    auth_words = ("auth", "login_required", "permission", "jwt")
    hits: list[SignalHit] = []

    def decorated_auth(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        return any(
            any(w in ast.unparse(d).lower() for w in auth_words) for d in node.decorator_list
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and any(
            ast.unparse(b).endswith(("APIView", "View", "ViewSet")) for b in node.bases
        ):
            class_policy = any(
                isinstance(s, ast.Assign)
                and any(
                    getattr(t, "id", "") in {"permission_classes", "authentication_classes"}
                    for t in s.targets
                )
                for s in node.body
            )
            for item in node.body:
                if (
                    isinstance(item, ast.FunctionDef)
                    and item.name in {"get", "post", "put", "patch", "delete"}
                    and not class_policy
                    and not decorated_auth(item)
                ):
                    hits.append(
                        SignalHit(
                            "unauthenticated_handler", item.lineno, f"{node.name}.{item.name}"
                        )
                    )
    return hits


def _java_authorization_links(code: str) -> list[SignalHit]:
    imports = {name.rsplit(".", 1)[-1]: name for name in re.findall(r"\bimport\s+([\w.]+);", code)}
    package = re.search(r"\bpackage\s+([\w.]+);", code)
    implementation = re.search(r"\bclass\s+\w+\s+implements\s+(\w+)", code)
    hits = []
    methods = re.finditer(
        r"(?m)^(?P<indent>[ \t]*)(?:public|protected|private)[ \t]+(?:[\w.<>,?\[\]]+[ \t]+)+"
        r"(?P<method>\w+)\((?P<params>(?:[^(){}]|\([^(){}]*\))*)\)\s*\{"
        r"(?P<body>.*?)(?:^(?P=indent)\}|\}(?=[ \t]*$))",
        code,
        re.S | re.M,
    )
    fields = dict((name, kind) for kind, name in re.findall(r"\b(\w+)\s+(\w+)\s*;", code))
    for method in methods:
        body = method["body"]
        if re.search(r"\b(?:checkPermission|requireOwner|authorize|assertOwner)\s*\(", body):
            continue
        path_id = re.search(r"@PathVariable(?:\([^)]*\))?\s+\w+\s+(\w+)", method["params"])
        if path_id:
            for call in re.finditer(
                r"\b(\w+)\.(\w+)\(\s*" + re.escape(path_id[1]) + r"\s*\)", body
            ):
                kind = fields.get(call[1], "")
                contract = imports.get(kind)
                if contract:
                    line = code.count("\n", 0, method.start("body") + call.start()) + 1
                    hits.append(
                        SignalHit(f"java_client_delegate:{contract}.{call[2]}", line, call[0])
                    )
        if not implementation or not package:
            continue
        parameter = re.fullmatch(r"\s*\w+\s+(\w+)\s*", method["params"])
        if not parameter:
            continue
        lookup = re.search(
            r"\b\w+\.(?:findById|findByUuid|getById)\(\s*" + re.escape(parameter[1]) + r"\s*\)",
            body,
        )
        if lookup:
            contract = imports.get(implementation[1], f"{package[1]}.{implementation[1]}")
            line = code.count("\n", 0, method.start("body") + lookup.start()) + 1
            hits.append(SignalHit(f"java_id_lookup:{contract}.{method['method']}", line, lookup[0]))
    return hits


def extract_signals(path: str, text: str, language: str | None) -> list[SignalHit]:
    if language not in {"python", "java", "go", "javascript", "typescript"}:
        return []
    code = strip_comments(text, language)
    lines = text.splitlines()
    hits: list[SignalHit] = []
    for name, table in PATTERNS.items():
        for pattern in table.get(language, []) + table.get("*", []):
            for match in pattern.finditer(code):
                line = code.count("\n", 0, match.start()) + 1
                excerpt = lines[line - 1].strip()[:160] if line <= len(lines) else ""
                hits.append(SignalHit(name, line, excerpt))
    if language == "python":
        hits.extend(_python_unauthenticated_handlers(text))
    elif language == "java":
        hits.extend(_java_authorization_links(code))
    # De-duplicate per (signal, line).
    unique = {(h.name, h.line): h for h in hits}
    return sorted(unique.values(), key=lambda h: (h.name, h.line))


def signal_names(hits: list[SignalHit]) -> list[str]:
    return sorted({h.name for h in hits})


__all__ = ["SignalHit", "extract_signals", "is_test_path", "signal_names", "strip_comments"]
_ = PurePosixPath
