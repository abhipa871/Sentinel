from __future__ import annotations

import ast
import hashlib
import json
import os
import posixpath
import re
import sys
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from uuid import UUID, uuid5

from sentinel.contracts import (
    Asset,
    AssetEdge,
    AssetType,
    CoverageState,
    EdgeType,
    EvidenceRef,
    RepositoryAssetGraph,
    RepositorySnapshot,
    UnresolvedReference,
)

NAMESPACE = UUID("6d74e78a-b9ca-4aae-bc64-16f98b891f50")
IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "vendor",
}
MANIFEST_NAMES = {
    "pyproject.toml",
    "requirements.txt",
    "requirements.lock",
    "poetry.lock",
    "uv.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "pipfile",
    "pipfile.lock",
    "setup.cfg",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
}
# requirements.txt, dev-requirements.txt, requirements-dev.txt, requirements_test.txt, ...
REQUIREMENTS_MANIFEST = re.compile(r"^(?:[\w.-]+[-_])?requirements(?:[-_.][\w.-]+)?\.txt$")
# Ecosystem -> manifest names, most authoritative first. A source file is associated with the
# primary manifest of its own ecosystem in the nearest ancestor directory that has one.
MANIFEST_ECOSYSTEMS: dict[str, tuple[str, ...]] = {
    "python": (
        "pyproject.toml",
        "setup.cfg",
        "pipfile",
        "requirements.txt",
        "poetry.lock",
        "uv.lock",
        "pipfile.lock",
        "requirements.lock",
    ),
    "node": ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
    "go": ("go.mod", "go.sum"),
    "jvm": (
        "build.gradle",
        "build.gradle.kts",
        "pom.xml",
        "settings.gradle",
        "settings.gradle.kts",
    ),
    "rust": ("cargo.toml", "cargo.lock"),
}
LANGUAGE_ECOSYSTEM = {
    "python": "python",
    "javascript": "node",
    "typescript": "node",
    "go": "go",
    "java": "jvm",
    "rust": "rust",
}
JS_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx")
HTTP_METHOD_NAMES = {"get", "post", "put", "delete", "patch"}
ROUTE_DECORATOR_NAMES = HTTP_METHOD_NAMES | {"route", "api_view"}
# Path parameters: Django/Flask <int:pk>, regex (?P<pk>...), OpenAPI/Spring/mux {id}, Express/gin :id
_ROUTE_PARAM = re.compile(r"<(?:\w+:)?(\w+)>|\(\?P<(\w+)>|\{(\w+)(?::[^}]*)?\}|(?:^|/):(\w+)")
_JAVA_IMPORT = re.compile(r"(?m)^[ \t]*import[ \t]+(static[ \t]+)?([A-Za-z_][\w.]*?)(\.\*)?[ \t]*;")
_JAVA_MAPPING = re.compile(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\b(?:\s*\(([^)]*)\))?")
_JAVA_CONTROLLER = re.compile(r"@(?:Rest)?Controller\b")
_GO_IMPORT_BLOCK = re.compile(r"(?ms)^import[ \t]*\((.*?)^\)")
_GO_IMPORT_SINGLE = re.compile(r'(?m)^import[ \t]+(?:[\w.]+[ \t]+)?"([^"]+)"')
_GO_IMPORT_SPEC = re.compile(r'(?m)^[ \t]*(?:[\w.]+[ \t]+)?"([^"]+)"')
_GO_ROUTE = re.compile(
    r"\.\s*(HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch)\s*\(\s*\"([^\"]*)\""
)
_GO_COMPOSITE = re.compile(r"\b(bson\.[MDAE])\s*\{")
_GO_MODULE = re.compile(r"(?m)^module[ \t]+(\S+)")
# Qualified call names (`http.Get(`, `restTemplate.exchange(`); a chained `.setSigningKey(` after
# `)` is captured on its own. Annotations (`@GetMapping(`) are excluded.
_CALL_NAME = re.compile(r"(?<![\w@$])([A-Za-z_]\w*(?:[ \t]*\.[ \t]*[A-Za-z_]\w*)*)[ \t]*\(")
_NON_CALL_WORDS = {
    # Java and Go control keywords and builtins that look like calls to the regex.
    "if", "for", "while", "switch", "catch", "synchronized", "return", "new", "super", "this",
    "try", "else", "do", "throw", "assert", "case", "func", "go", "defer", "select", "range",
    "make", "len", "cap", "append", "panic", "recover", "copy", "delete", "print", "println",
    "close", "string", "int", "int64", "int32", "uint", "byte", "rune", "error", "float64",
    "bool", "map", "chan", "struct", "interface",
}  # fmt: skip
MAX_API_SYMBOLS = 300
BINARY_EXTENSIONS = {".db", ".sqlite", ".sqlite3", ".png", ".jpg", ".jpeg", ".gif", ".pdf"}
SOURCE_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
}
CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".env"}
DOC_EXTENSIONS = {".md", ".rst", ".txt"}
DATA_EXTENSIONS = {".csv", ".tsv", ".parquet"}


def _sha(value: bytes | str) -> str:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def _stable_id(prefix: str, *parts: object) -> str:
    return f"{prefix}:{_sha(':'.join(map(str, parts)))}"


@dataclass
class _ParseFacts:
    features: dict[str, Any] = field(default_factory=dict)
    references: list[tuple[str, str, int]] = field(default_factory=list)
    parse_error: str | None = None


class _PythonFacts(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: list[tuple[str, str, int]] = []
        # Local name -> module reference it binds (`from . import views` binds views -> ".views").
        self.aliases: dict[str, str] = {}
        self.calls: set[str] = set()
        self.strings: set[str] = set()
        self.routes: list[str] = []
        self.route_paths: set[str] = set()
        # Django/DRF URL patterns: (route, handler root name, line).
        self.url_routes: list[tuple[str, str | None, int]] = []
        self.included_urlconfs: list[tuple[str, int]] = []
        self.http_handlers: list[str] = []
        self.has_functions = False
        self.tls_verification_disabled = False
        self.jwt_signature_verification_disabled = False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append((alias.name, "python_import", node.lineno))
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                root = alias.name.split(".")[0]
                self.aliases[root] = root
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = "." * node.level + (node.module or "")
        self.imports.append((module, "python_import", node.lineno))
        for alias in node.names:
            if alias.name == "*":
                continue
            # `from pkg import name` may name a submodule file; it is resolved when one exists
            # and otherwise ignored, because it is most likely a symbol.
            member = f"{module}.{alias.name}" if node.module else f"{module}{alias.name}"
            self.imports.append((member, "python_import_member", node.lineno))
            self.aliases[alias.asname or alias.name] = member
        self.generic_visit(node)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.has_functions = True
        for decorator in node.decorator_list:
            text = (
                _call_name(decorator.func)
                if isinstance(decorator, ast.Call)
                else _call_name(decorator)
            )
            if text and text.split(".")[-1].lower() in ROUTE_DECORATOR_NAMES:
                self.routes.append(text)
                if isinstance(decorator, ast.Call) and decorator.args:
                    first = decorator.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        self.route_paths.add(first.value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Class-based views (Django/DRF): HTTP-method handlers taking (self, request, ...).
        for item in node.body:
            if (
                isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
                and item.name in HTTP_METHOD_NAMES
                and len(item.args.args) >= 2
                and item.args.args[0].arg == "self"
            ):
                self.http_handlers.append(f"{node.name}.{item.name}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if name:
            self.calls.add(name)
            for keyword in node.keywords:
                if (
                    keyword.arg == "verify"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                ):
                    if name.split(".")[-1] == "decode":
                        self.jwt_signature_verification_disabled = True
                    else:
                        self.tls_verification_disabled = True
            if name.split(".")[-1] in {"path", "re_path", "url"} and len(node.args) >= 2:
                route, handler = node.args[0], node.args[1]
                if isinstance(route, ast.Constant) and isinstance(route.value, str):
                    self.route_paths.add(route.value)
                    included = _included_urlconf(handler)
                    if included:
                        # include("crapi.shop.urls") names the dispatched module directly.
                        self.included_urlconfs.append((included, node.lineno))
                    else:
                        self.url_routes.append((route.value, _root_name(handler), node.lineno))
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values, strict=True):
            if (
                isinstance(key, ast.Constant)
                and key.value == "verify_signature"
                and isinstance(value, ast.Constant)
                and value.value is False
            ):
                self.jwt_signature_verification_disabled = True
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and len(node.value) <= 500:
            self.strings.add(node.value)


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _root_name(node: ast.AST) -> str | None:
    """Leftmost name of a handler expression such as `views.OrderView.as_view()`."""
    while True:
        if isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Name):
            return node.id
        else:
            return None


def _included_urlconf(node: ast.AST) -> str | None:
    """Module path of a Django `include("pkg.urls")` handler, if that is what this is."""
    if (
        isinstance(node, ast.Call)
        and (_call_name(node.func) or "").split(".")[-1] == "include"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        return node.args[0].value
    return None


def _route_params(paths: Iterable[str]) -> list[str]:
    return sorted(
        {
            next(group for group in match.groups() if group)
            for path in paths
            for match in _ROUTE_PARAM.finditer(path)
        }
    )


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _call_symbols(text: str) -> list[str]:
    symbols = {
        re.sub(r"\s+", "", match.group(1))
        for match in _CALL_NAME.finditer(text)
        if match.group(1).split(".")[0].strip() not in _NON_CALL_WORDS
    }
    return sorted(symbols)[:MAX_API_SYMBOLS]


def manifest_ecosystem(name: str) -> str | None:
    lowered = name.lower()
    if REQUIREMENTS_MANIFEST.match(lowered):
        return "python"
    return next(
        (ecosystem for ecosystem, names in MANIFEST_ECOSYSTEMS.items() if lowered in names),
        None,
    )


def _manifest_rank(name: str) -> tuple[int, str]:
    """Most authoritative manifest first; requirements variants after every exact name."""
    lowered = name.lower()
    names = MANIFEST_ECOSYSTEMS.get(manifest_ecosystem(lowered) or "", ())
    return (names.index(lowered) if lowered in names else len(names), lowered)


def _classify(path: PurePosixPath) -> tuple[AssetType, str | None]:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if ".github/workflows/" in f"/{path.as_posix()}" and suffix in {".yaml", ".yml"}:
        return AssetType.WORKFLOW_FILE, "yaml"
    if name in MANIFEST_NAMES or REQUIREMENTS_MANIFEST.match(name):
        return AssetType.MANIFEST_FILE, suffix.lstrip(".") or None
    if name == "dockerfile" or suffix == ".tf":
        return AssetType.INFRA_FILE, "dockerfile" if name == "dockerfile" else "terraform"
    if suffix in SOURCE_LANGUAGES:
        return AssetType.SOURCE_FILE, SOURCE_LANGUAGES[suffix]
    if suffix == ".sql":
        return AssetType.SQL_FILE, "sql"
    if suffix in {".db", ".sqlite", ".sqlite3"}:
        return AssetType.DATABASE_FILE, "sqlite"
    if suffix in CONFIG_EXTENSIONS:
        return AssetType.CONFIG_FILE, suffix.lstrip(".")
    if suffix == ".ipynb":
        return AssetType.NOTEBOOK_FILE, "jupyter"
    if suffix in {".onnx", ".pt", ".pth", ".safetensors"}:
        return AssetType.MODEL_ARTIFACT, None
    if suffix in DATA_EXTENSIONS:
        return AssetType.DATA_FILE, None
    if suffix in DOC_EXTENSIONS:
        return AssetType.DOCUMENTATION_FILE, None
    if suffix in BINARY_EXTENSIONS:
        return AssetType.BINARY_ASSET, None
    return AssetType.OTHER_FILE, None


def _parse_python(text: str) -> _ParseFacts:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as exc:
        return _ParseFacts(parse_error=str(exc))
    visitor = _PythonFacts()
    visitor.visit(tree)
    calls = sorted(visitor.calls)
    features: dict[str, Any] = {
        "api_symbols": calls,
        "has_route": bool(visitor.routes or visitor.url_routes or visitor.http_handlers),
        "route_decorators": sorted(visitor.routes),
        "route_paths": sorted(visitor.route_paths)[:100],
        "route_params": _route_params(visitor.route_paths),
        "http_handlers": sorted(visitor.http_handlers)[:100],
        "has_functions": visitor.has_functions,
        "string_literals": sorted(visitor.strings)[:100],
        "tls_verification_disabled": visitor.tls_verification_disabled,
        "jwt_signature_verification_disabled": visitor.jwt_signature_verification_disabled,
    }
    refs = list(visitor.imports)
    for _route, handler, line in visitor.url_routes:
        if handler and handler in visitor.aliases:
            refs.append((visitor.aliases[handler], "python_route", line))
    refs.extend((module, "python_route", line) for module, line in visitor.included_urlconfs)
    return _ParseFacts(features=features, references=refs)


def _parse_java(text: str) -> _ParseFacts:
    refs: list[tuple[str, str, int]] = []
    for match in _JAVA_IMPORT.finditer(text):
        static, name, wildcard = match.groups()
        kind = "java_static_import" if static else "java_import"
        refs.append((f"{name}.*" if wildcard else name, kind, _line_of(text, match.start())))
    mappings = list(_JAVA_MAPPING.finditer(text))
    route_paths = {
        literal
        for match in mappings
        if match.group(2)
        for literal in re.findall(r'"([^"]*)"', match.group(2))
    }
    features: dict[str, Any] = {
        "api_symbols": _call_symbols(text),
        "has_route": bool(mappings),
        "controller": bool(_JAVA_CONTROLLER.search(text)),
        "route_decorators": sorted({f"{match.group(1)}Mapping" for match in mappings}),
        "route_paths": sorted(route_paths)[:100],
        "route_params": _route_params(route_paths),
        "request_body_binding": bool(re.search(r"@RequestBody\b", text)),
    }
    return _ParseFacts(features=features, references=refs)


def _parse_go(text: str) -> _ParseFacts:
    refs: list[tuple[str, str, int]] = []
    for block in _GO_IMPORT_BLOCK.finditer(text):
        for spec in _GO_IMPORT_SPEC.finditer(block.group(1)):
            refs.append(
                (spec.group(1), "go_import", _line_of(text, block.start(1) + spec.start(1)))
            )
    for match in _GO_IMPORT_SINGLE.finditer(text):
        refs.append((match.group(1), "go_import", _line_of(text, match.start())))
    routes = list(_GO_ROUTE.finditer(text))
    route_paths = {match.group(2) for match in routes}
    symbols = set(_call_symbols(text)) | {match.group(1) for match in _GO_COMPOSITE.finditer(text)}
    features: dict[str, Any] = {
        "api_symbols": sorted(symbols)[:MAX_API_SYMBOLS],
        "has_route": bool(routes),
        "route_decorators": sorted({match.group(1) for match in routes}),
        "route_paths": sorted(route_paths)[:100],
        "route_params": _route_params(route_paths),
        "tls_verification_disabled": bool(re.search(r"InsecureSkipVerify\s*:\s*true", text)),
        "request_body_binding": bool(
            re.search(
                r"\.(?:ShouldBindJSON|BindJSON|ShouldBind)\s*\(|"
                r"json\.NewDecoder\([^)]*\.Body\)\s*\.\s*Decode\s*\(",
                text,
            )
        ),
    }
    return _ParseFacts(features=features, references=refs)


def _parse_text(path: PurePosixPath, text: str, language: str | None) -> _ParseFacts:
    if language == "python":
        return _parse_python(text)
    if language == "java":
        return _parse_java(text)
    if language == "go":
        return _parse_go(text)
    if path.name.lower() == "go.mod":
        module = _GO_MODULE.search(text)
        return _ParseFacts(features={"go_module": module.group(1)} if module else {})
    refs: list[tuple[str, str, int]] = []
    features: dict[str, Any] = {}
    if language in {"javascript", "typescript"}:
        for line_no, line in enumerate(text.splitlines(), 1):
            for match in re.finditer(
                r"(?:from\s+|require\(|import\s*\()\s*['\"]([^'\"]+)['\"]", line
            ):
                refs.append((match.group(1), "js_import", line_no))
        features["api_symbols"] = sorted(
            set(re.findall(r"\b(?:exec|query|deserialize|fetch|readFile|writeFile)\b", text))
        )
    elif language == "sql":
        features["sql_operations"] = sorted(
            set(
                match.upper()
                for match in re.findall(r"\b(select|insert|update|delete)\b", text, re.I)
            )
        )
    elif path.name.lower() == "dockerfile":
        features["docker_instructions"] = re.findall(
            r"^(FROM|RUN|COPY|ADD|USER|EXPOSE)\b", text, re.I | re.M
        )
    elif path.suffix.lower() in {".yaml", ".yml", ".json", ".toml"}:
        features["config_keys"] = sorted(
            set(re.findall(r"(?m)^\s*([A-Za-z_][\w.-]*)\s*[:=]", text))
        )[:200]
    return _ParseFacts(features=features, references=refs)


def _normalize(candidate: str) -> str | None:
    """Collapse `.`/`..` segments; reject anything that escapes the repository root."""
    normalized = posixpath.normpath(candidate)
    if normalized in {".", ".."} or normalized.startswith(("../", "/")):
        return None
    return normalized


PYTHON_PROJECT_MARKERS = (
    "manage.py",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "requirements.txt",
)
EDGE_CONFIDENCE: dict[str, Literal["high", "medium", "low"]] = {
    "static_module_resolution": "high",
    "java_package_resolution": "high",
    "static_module_resolution_ancestor_root": "medium",
    "go_package_directory": "medium",
}


class _Resolver:
    """Offline, deterministic reference-to-file resolution over the immutable path inventory.

    It never guesses: ambiguous matches stay unresolved, and references that cannot be local
    (third-party packages, standard libraries) are labeled `external_reference`.
    """

    def __init__(self, paths: set[str], facts: dict[str, _ParseFacts]) -> None:
        self.paths = paths
        self.python_names: set[str] = set()
        self.java_by_suffix: dict[str, list[str]] = defaultdict(list)
        self.java_prefixes: set[str] = set()
        self.go_files: dict[str, list[str]] = defaultdict(list)
        for path in paths:
            parts = path.split("/")
            self.python_names.update(parts[:-1])
            if path.endswith(".py"):
                self.python_names.add(parts[-1][:-3])
            elif path.endswith(".java"):
                for index in range(len(parts)):
                    self.java_by_suffix["/".join(parts[index:])].append(path)
                self.java_prefixes.update(f"{left}/{right}" for left, right in pairwise(parts[:-1]))
            elif path.endswith(".go") and not path.endswith("_test.go"):
                self.go_files[posixpath.dirname(path)].append(path)
        self.go_modules = sorted(
            (
                (str(parsed.features["go_module"]), posixpath.dirname(path))
                for path, parsed in facts.items()
                if parsed.features.get("go_module")
            ),
            key=lambda item: (-len(item[0]), item[1]),
        )

    def resolve(self, source: str, reference: str, kind: str) -> tuple[tuple[str, ...], str]:
        if kind in {"python_import", "python_import_member", "python_route"}:
            return self._python(source, reference, kind)
        if kind == "js_import":
            return self._javascript(source, reference)
        if kind in {"java_import", "java_static_import"}:
            return self._java(source, reference, kind)
        if kind == "go_import":
            return self._go(reference)
        return (), "unsupported_reference_kind"

    @staticmethod
    def _python_candidates(base: str, module: str) -> list[str]:
        if not module:
            return [posixpath.join(base, "__init__.py")]
        stem = posixpath.join(base, *module.split("."))
        return [f"{stem}.py", posixpath.join(stem, "__init__.py")]

    def _python_root(self, root: str, package: str) -> bool:
        """An intermediate directory counts as an import root only with package evidence."""
        if posixpath.join(root, package, "__init__.py") in self.paths:
            return True
        return any(posixpath.join(root, marker) in self.paths for marker in PYTHON_PROJECT_MARKERS)

    def _python(self, source: str, reference: str, kind: str) -> tuple[tuple[str, ...], str]:
        dots = len(reference) - len(reference.lstrip("."))
        module = reference.lstrip(".")
        attempts = [module]
        if kind == "python_route" and "." in module:
            attempts.append(module.rsplit(".", 1)[0])  # views.OrderView -> views
        source_dir = posixpath.dirname(source)
        if dots:
            base = source_dir
            for _ in range(dots - 1):
                base = posixpath.dirname(base)
            for attempt in attempts:
                for candidate in self._python_candidates(base, attempt):
                    target = _normalize(candidate)
                    if target in self.paths:
                        return (target,), "static_module_resolution"
            missing = "unresolved_member" if kind == "python_import_member" else None
            return (), missing or "unresolved_local_reference"
        roots = [source_dir]
        while roots[-1]:
            roots.append(posixpath.dirname(roots[-1]))
        for attempt in attempts:
            package = attempt.split(".")[0]
            for root in roots:
                intermediate = root not in {source_dir, ""}
                if intermediate and not self._python_root(root, package):
                    continue
                for candidate in self._python_candidates(root, attempt):
                    target = _normalize(candidate)
                    if target in self.paths:
                        method = (
                            "static_module_resolution_ancestor_root"
                            if intermediate
                            else "static_module_resolution"
                        )
                        return (target,), method
        if kind == "python_import_member":
            return (), "unresolved_member"
        top_level = module.split(".")[0]
        if top_level in sys.stdlib_module_names or top_level not in self.python_names:
            return (), "external_reference"
        return (), "unresolved_local_reference"

    def _javascript(self, source: str, reference: str) -> tuple[tuple[str, ...], str]:
        if not reference.startswith("."):
            return (), "external_reference"
        base = _normalize(posixpath.join(posixpath.dirname(source), reference))
        if base is None:
            return (), "unresolved_local_reference"
        candidates = (
            base,
            *(f"{base}{extension}" for extension in JS_EXTENSIONS),
            *(f"{base}/index{extension}" for extension in JS_EXTENSIONS),
        )
        for candidate in candidates:
            if candidate in self.paths:
                return (candidate,), "static_module_resolution"
        return (), "unresolved_local_reference"

    def _java(self, source: str, reference: str, kind: str) -> tuple[tuple[str, ...], str]:
        if reference.endswith(".*"):
            return (), "wildcard_package_import"
        segments = reference.split(".")
        type_segments = segments[:-1] if kind == "java_static_import" else segments
        # Try the type itself, then its enclosing type for nested-class imports.
        for parts in (type_segments, type_segments[:-1]):
            if not parts:
                continue
            matches = sorted(set(self.java_by_suffix.get("/".join(parts) + ".java", ())))
            if len(matches) == 1:
                return (matches[0],), "java_package_resolution"
            if len(matches) > 1:
                shared = [len(posixpath.commonprefix([source, match])) for match in matches]
                best = max(shared)
                if shared.count(best) == 1:
                    return (matches[shared.index(best)],), "java_package_resolution"
                return (), "ambiguous_java_reference"
        if "/".join(segments[:2]) in self.java_prefixes:
            return (), "unresolved_local_reference"
        return (), "external_reference"

    def _go(self, reference: str) -> tuple[tuple[str, ...], str]:
        for module, module_dir in self.go_modules:
            if reference != module and not reference.startswith(f"{module}/"):
                continue
            relative = reference[len(module) :].lstrip("/")
            directory = posixpath.normpath(posixpath.join(module_dir, relative))
            files = tuple(sorted(self.go_files.get("" if directory == "." else directory, ())))
            if files:
                return files, "go_package_directory"
            return (), "unresolved_local_reference"
        return (), "external_reference"


class RepositoryExtractor:
    def __init__(self, *, max_files: int = 20_000, max_file_bytes: int = 5_000_000) -> None:
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes

    def extract(
        self,
        source: str | Path,
        *,
        pinned_commit_sha: str | None = None,
        repository_identity: str | None = None,
        acquisition_mode: Literal[
            "LOCAL_READ_ONLY", "API_ONLY", "PINNED_CLONE", "METADATA_ONLY"
        ] = "LOCAL_READ_ONLY",
    ) -> RepositoryAssetGraph:
        root_input = Path(source).resolve()
        root = root_input.parent if root_input.is_file() else root_input
        if not root_input.exists():
            raise FileNotFoundError(root_input)
        files = [root_input] if root_input.is_file() else list(self._files(root))
        partial = len(files) > self.max_files
        files = files[: self.max_files]
        repo_id = uuid5(NAMESPACE, repository_identity or str(root))
        snapshot_seed = pinned_commit_sha or self._snapshot_seed(root, files)
        snapshot_id = uuid5(NAMESPACE, f"{repo_id}:{snapshot_seed}")
        warnings = ("file limit reached",) if partial else ()
        snapshot = RepositorySnapshot(
            snapshot_id=snapshot_id,
            repo_id=repo_id,
            source=str(root_input),
            commit_sha=snapshot_seed,
            acquisition_mode=acquisition_mode,
            partial=partial,
            warnings=warnings,
        )
        assets: list[Asset] = []
        evidence: list[EvidenceRef] = []
        parse_facts: dict[str, _ParseFacts] = {}
        for file_path in files:
            rel = file_path.relative_to(root).as_posix()
            node_type, language = _classify(PurePosixPath(rel))
            raw = file_path.read_bytes()
            digest = _sha(raw)
            binary = b"\x00" in raw[:8192] or node_type in {
                AssetType.DATABASE_FILE,
                AssetType.BINARY_ASSET,
                AssetType.MODEL_ARTIFACT,
            }
            too_large = len(raw) > self.max_file_bytes
            text = ""
            facts = _ParseFacts()
            if not binary and not too_large:
                text = raw.decode("utf-8", errors="replace")
                # Parse empty files too: an empty __init__.py has observed features (no routes,
                # no calls). Leaving them absent would make every rule report "unknown".
                facts = _parse_text(PurePosixPath(rel), text, language)
            facts.features.update(
                {
                    "file_role": node_type.value.lower(),
                    "entrypoint": bool(facts.features.get("has_route")),
                    "size_bytes": len(raw),
                }
            )
            parse_facts[rel] = facts
            status = (
                CoverageState.METADATA_ONLY
                if binary or too_large
                else CoverageState.ERROR
                if facts.parse_error
                else CoverageState.SUPPORTED_FULL
                if language in {"python", "javascript", "typescript", "sql", "yaml", "json", "toml"}
                else CoverageState.SUPPORTED_PARTIAL
            )
            evidence_id = _stable_id("ev", snapshot_id, rel, digest)
            evidence.append(
                EvidenceRef(
                    evidence_id=evidence_id,
                    producer="phase0.inventory",
                    source_path=rel,
                    content_sha256=digest,
                    assertion_origin="observed",
                    summary="Immutable file inventory and static parse evidence",
                )
            )
            assets.append(
                Asset(
                    snapshot_id=snapshot_id,
                    asset_id=_stable_id("asset", repo_id, snapshot_seed, rel),
                    logical_asset_key=f"{repo_id}:{rel}",
                    path=rel,
                    node_type=node_type,
                    language=language,
                    content_sha256=digest,
                    size_bytes=len(raw),
                    line_count=None if binary else text.count("\n") + (1 if text else 0),
                    is_binary=binary,
                    parser_status=status,
                    features=facts.features,
                    evidence_refs=(evidence_id,),
                )
            )
        path_to_asset = {asset.path: asset for asset in assets}
        edges, unresolved, edge_evidence = self._edges(snapshot, path_to_asset, parse_facts)
        evidence.extend(edge_evidence)
        graph_material = {
            "assets": [(a.asset_id, a.path, a.content_sha256) for a in assets],
            "edges": [(e.source_asset_id, e.edge_type, e.target_asset_id) for e in edges],
        }
        return RepositoryAssetGraph(
            snapshot=snapshot,
            assets=tuple(assets),
            edges=tuple(edges),
            unresolved=tuple(unresolved),
            evidence=tuple(evidence),
            digest=_sha(json.dumps(graph_material, sort_keys=True)),
        )

    def _files(self, root: Path) -> Iterable[Path]:
        for current, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = sorted(
                d for d in dirs if d not in IGNORE_DIRS and not (Path(current) / d).is_symlink()
            )
            for name in sorted(names):
                path = Path(current) / name
                if not path.is_symlink() and path.is_file():
                    yield path

    def _snapshot_seed(self, root: Path, files: list[Path]) -> str:
        material = []
        for path in files:
            rel = path.relative_to(root).as_posix()
            material.append((rel, _sha(path.read_bytes())))
        return _sha(json.dumps(material, sort_keys=True))[:40]

    def _edges(
        self,
        snapshot: RepositorySnapshot,
        path_to_asset: dict[str, Asset],
        facts: dict[str, _ParseFacts],
    ) -> tuple[list[AssetEdge], list[UnresolvedReference], list[EvidenceRef]]:
        edges: list[AssetEdge] = []
        unresolved: list[UnresolvedReference] = []
        evidence: list[EvidenceRef] = []
        seen: set[tuple[str, str, EdgeType]] = set()
        recorded_evidence: set[str] = set()
        resolver = _Resolver(set(path_to_asset), facts)
        for source_path, parsed in facts.items():
            source_asset = path_to_asset[source_path]
            for reference, kind, line in parsed.references:
                targets, method = resolver.resolve(source_path, reference, kind)
                if not targets:
                    if method == "unresolved_member":
                        # `from pkg import name` where name is not a submodule: a symbol, which
                        # the canonical file graph does not model.
                        continue
                    unresolved.append(
                        UnresolvedReference(
                            snapshot_id=snapshot.snapshot_id,
                            source_asset_id=source_asset.asset_id,
                            reference=reference,
                            kind=kind,
                            location=f"{source_path}:{line}",
                            reason=method,
                        )
                    )
                    continue
                edge_type = EdgeType.ROUTES_TO if kind == "python_route" else EdgeType.IMPORTS
                evidence_id = _stable_id("ev", snapshot.snapshot_id, source_path, line, reference)
                if kind == "python_route":
                    summary = f"Static URL route handler {reference!r} resolves to {targets[0]}"
                elif kind == "go_import":
                    summary = (
                        f"Static Go import {reference!r} resolves to package directory "
                        f"{posixpath.dirname(targets[0]) or '.'} ({len(targets)} files)"
                    )
                else:
                    summary = f"Static import {reference!r} resolves to {targets[0]}"
                for target_path in targets:
                    if target_path == source_path:
                        continue
                    target = path_to_asset[target_path]
                    key = (source_asset.asset_id, target.asset_id, edge_type)
                    if key in seen:
                        continue
                    seen.add(key)
                    if evidence_id not in recorded_evidence:
                        recorded_evidence.add(evidence_id)
                        evidence.append(
                            EvidenceRef(
                                evidence_id=evidence_id,
                                producer="phase0.static_resolver",
                                source_path=source_path,
                                start_line=line,
                                end_line=line,
                                content_sha256=source_asset.content_sha256,
                                assertion_origin="observed",
                                summary=summary,
                            )
                        )
                    edges.append(
                        AssetEdge(
                            snapshot_id=snapshot.snapshot_id,
                            edge_id=_stable_id("edge", snapshot.snapshot_id, *key, line),
                            source_asset_id=source_asset.asset_id,
                            target_asset_id=target.asset_id,
                            edge_type=edge_type,
                            confidence=EDGE_CONFIDENCE.get(method, "medium"),
                            resolution_method=method,
                            source_location=f"{source_path}:{line}",
                            target_location=target_path,
                            evidence_refs=(evidence_id,),
                        )
                    )
        by_dir: dict[str, list[Asset]] = defaultdict(list)
        manifests = [a for a in path_to_asset.values() if a.node_type is AssetType.MANIFEST_FILE]
        manifests_by_dir: dict[str, list[Asset]] = defaultdict(list)
        for manifest in manifests:
            manifests_by_dir[posixpath.dirname(manifest.path)].append(manifest)
        for asset in path_to_asset.values():
            by_dir[str(PurePosixPath(asset.path).parent)].append(asset)

        def link_manifest(asset: Asset, manifest: Asset, method: str, summary: str) -> None:
            key = (asset.asset_id, manifest.asset_id, EdgeType.DEPENDS_ON_MANIFEST)
            if key in seen:
                return
            seen.add(key)
            ev = _stable_id("ev", snapshot.snapshot_id, asset.path, manifest.path)
            evidence.append(
                EvidenceRef(
                    evidence_id=ev,
                    producer="phase0.manifest_association",
                    source_path=asset.path,
                    content_sha256=asset.content_sha256,
                    assertion_origin="derived_rule",
                    summary=summary,
                )
            )
            edges.append(
                AssetEdge(
                    snapshot_id=snapshot.snapshot_id,
                    edge_id=_stable_id("edge", snapshot.snapshot_id, *key),
                    source_asset_id=asset.asset_id,
                    target_asset_id=manifest.asset_id,
                    edge_type=EdgeType.DEPENDS_ON_MANIFEST,
                    confidence="medium",
                    resolution_method=method,
                    source_location=asset.path,
                    target_location=manifest.path,
                    evidence_refs=(ev,),
                )
            )

        # Source files: the primary manifest of their own ecosystem in the nearest ancestor
        # directory that has one (a Java file under src/main/java -> the module's build.gradle).
        for asset in sorted(path_to_asset.values(), key=lambda item: item.path):
            ecosystem = (
                LANGUAGE_ECOSYSTEM.get(asset.language or "")
                if asset.node_type is AssetType.SOURCE_FILE
                else None
            )
            if ecosystem is None:
                continue
            directory = posixpath.dirname(asset.path)
            while True:
                candidates = sorted(
                    (
                        manifest
                        for manifest in manifests_by_dir.get(directory, ())
                        if manifest_ecosystem(PurePosixPath(manifest.path).name) == ecosystem
                    ),
                    key=lambda manifest: _manifest_rank(PurePosixPath(manifest.path).name),
                )
                if candidates:
                    link_manifest(
                        asset,
                        candidates[0],
                        "nearest_ancestor_manifest",
                        f"Nearest {ecosystem} manifest for this {asset.language} file is "
                        f"{candidates[0].path}",
                    )
                    break
                if not directory:
                    break
                directory = posixpath.dirname(directory)
        # Other assets keep the same-directory association.
        for manifest in manifests:
            directory = str(PurePosixPath(manifest.path).parent)
            for asset in by_dir[directory]:
                if asset.asset_id == manifest.asset_id or asset.node_type is AssetType.SOURCE_FILE:
                    continue
                link_manifest(
                    asset,
                    manifest,
                    "same_directory_manifest",
                    f"Asset shares repository directory with manifest {manifest.path}",
                )
        return edges, unresolved, evidence
