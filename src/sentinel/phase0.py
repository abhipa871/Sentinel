from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
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
from sentinel.signals import extract_signals, is_test_path, signal_names

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
    "cargo.toml",
}
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
        self.imports: list[tuple[str, int]] = []
        self.calls: set[str] = set()
        self.strings: set[str] = set()
        self.routes: list[str] = []
        self.has_functions = False

    def visit_Import(self, node: ast.Import) -> None:
        self.imports.extend((alias.name, node.lineno) for alias in node.names)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = "." * node.level + (node.module or "")
        self.imports.append((module, node.lineno))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.has_functions = True
        for decorator in node.decorator_list:
            text = (
                _call_name(decorator.func)
                if isinstance(decorator, ast.Call)
                else _call_name(decorator)
            )
            if (
                text
                and text.split(".")[0] not in {"mock", "patch", "unittest"}
                and text != "patch"
                and text.split(".")[-1].lower()
                in {
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "route",
                }
            ):
                self.routes.append(text)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.has_functions = True
        for decorator in node.decorator_list:
            text = (
                _call_name(decorator.func)
                if isinstance(decorator, ast.Call)
                else _call_name(decorator)
            )
            if (
                text
                and text.split(".")[0] not in {"mock", "patch", "unittest"}
                and text != "patch"
                and text.split(".")[-1].lower()
                in {
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "route",
                }
            ):
                self.routes.append(text)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if name:
            self.calls.add(name)
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


def _classify(path: PurePosixPath) -> tuple[AssetType, str | None]:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if ".github/workflows/" in f"/{path.as_posix()}" and suffix in {".yaml", ".yml"}:
        return AssetType.WORKFLOW_FILE, "yaml"
    if name in MANIFEST_NAMES:
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
        "has_route": bool(visitor.routes),
        "route_decorators": sorted(visitor.routes),
        "has_functions": visitor.has_functions,
        "string_literals": sorted(visitor.strings)[:100],
    }
    refs = [(module, "python_import", line) for module, line in visitor.imports]
    return _ParseFacts(features=features, references=refs)


def _parse_text(path: PurePosixPath, text: str, language: str | None) -> _ParseFacts:
    if language == "python":
        return _parse_python(text)
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


def _resolve_reference(
    source: str, reference: str, kind: str, paths: set[str]
) -> tuple[str | None, str]:
    source_path = PurePosixPath(source)
    candidates: list[str] = []
    if kind == "python_import":
        dots = len(reference) - len(reference.lstrip("."))
        module = reference.lstrip(".")
        base = source_path.parent
        for _ in range(max(0, dots - 1)):
            base = base.parent
        rel = PurePosixPath(*module.split(".")) if module else PurePosixPath()
        candidates.extend(
            [(base / rel).with_suffix(".py").as_posix(), (base / rel / "__init__.py").as_posix()]
        )
        if dots == 0:
            candidates.extend([rel.with_suffix(".py").as_posix(), (rel / "__init__.py").as_posix()])
    elif kind == "js_import" and reference.startswith("."):
        base = source_path.parent / reference
        candidates.extend(
            [
                base.as_posix(),
                *(base.with_suffix(ext).as_posix() for ext in (".js", ".jsx", ".ts", ".tsx")),
            ]
        )
        candidates.extend((base / f"index{ext}").as_posix() for ext in (".js", ".ts", ".tsx"))
    for candidate in candidates:
        normalized = PurePosixPath(candidate).as_posix().lstrip("./")
        if normalized in paths:
            return normalized, "static_module_resolution"
    return None, "unresolved_local_reference"


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
            if not binary and not too_large:
                text = raw.decode("utf-8", errors="replace")
            facts = _ParseFacts()
            if text:
                facts = _parse_text(PurePosixPath(rel), text, language)
            facts.features.update(
                {
                    "file_role": node_type.value.lower(),
                    "entrypoint": bool(facts.features.get("has_route")),
                    "size_bytes": len(raw),
                }
            )
            hits = extract_signals(rel, text, language) if text else []
            facts.features["security_signals"] = signal_names(hits)
            facts.features["is_test"] = is_test_path(rel)
            signal_evidence: dict[str, list[str]] = {}
            for hit in hits:
                span_id = _stable_id("ev", snapshot_id, rel, digest, hit.name, hit.line)
                signal_evidence.setdefault(hit.name, []).append(span_id)
                evidence.append(
                    EvidenceRef(
                        evidence_id=span_id,
                        producer=f"phase0.signal.{hit.name}",
                        source_path=rel,
                        start_line=hit.line,
                        end_line=hit.line,
                        content_sha256=digest,
                        assertion_origin="observed",
                        summary=f"{hit.name} at {rel}:{hit.line}: {hit.excerpt}",
                    )
                )
            facts.features["signal_evidence"] = signal_evidence
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
        paths = set(path_to_asset)
        for source_path, parsed in facts.items():
            source_asset = path_to_asset[source_path]
            for reference, kind, line in parsed.references:
                target_path, method = _resolve_reference(source_path, reference, kind, paths)
                if not target_path:
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
                target = path_to_asset[target_path]
                key = (source_asset.asset_id, target.asset_id, EdgeType.IMPORTS)
                if key in seen:
                    continue
                seen.add(key)
                evidence_id = _stable_id("ev", snapshot.snapshot_id, source_path, line, reference)
                evidence.append(
                    EvidenceRef(
                        evidence_id=evidence_id,
                        producer="phase0.static_resolver",
                        source_path=source_path,
                        start_line=line,
                        end_line=line,
                        content_sha256=source_asset.content_sha256,
                        assertion_origin="observed",
                        summary=f"Static import {reference!r} resolves to {target_path}",
                    )
                )
                edges.append(
                    AssetEdge(
                        snapshot_id=snapshot.snapshot_id,
                        edge_id=_stable_id("edge", snapshot.snapshot_id, *key, line),
                        source_asset_id=source_asset.asset_id,
                        target_asset_id=target.asset_id,
                        edge_type=EdgeType.IMPORTS,
                        confidence="high",
                        resolution_method=method,
                        source_location=f"{source_path}:{line}",
                        target_location=target_path,
                        evidence_refs=(evidence_id,),
                    )
                )
        by_dir: dict[str, list[Asset]] = defaultdict(list)
        manifests = [a for a in path_to_asset.values() if a.node_type is AssetType.MANIFEST_FILE]
        for asset in path_to_asset.values():
            by_dir[str(PurePosixPath(asset.path).parent)].append(asset)
        for manifest in manifests:
            directory = str(PurePosixPath(manifest.path).parent)
            for asset in by_dir[directory]:
                if asset.asset_id == manifest.asset_id:
                    continue
                key = (asset.asset_id, manifest.asset_id, EdgeType.DEPENDS_ON_MANIFEST)
                if key in seen:
                    continue
                seen.add(key)
                ev = _stable_id("ev", snapshot.snapshot_id, asset.path, manifest.path)
                evidence.append(
                    EvidenceRef(
                        evidence_id=ev,
                        producer="phase0.manifest_association",
                        source_path=asset.path,
                        content_sha256=asset.content_sha256,
                        assertion_origin="derived_rule",
                        summary=f"Asset shares repository directory with manifest {manifest.path}",
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
                        resolution_method="same_directory_manifest",
                        source_location=asset.path,
                        target_location=manifest.path,
                        evidence_refs=(ev,),
                    )
                )
        return edges, unresolved, evidence
