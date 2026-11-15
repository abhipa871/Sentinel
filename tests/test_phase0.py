from pathlib import Path

from sentinel.contracts import AssetType, EdgeType
from sentinel.phase0 import RepositoryExtractor


def test_graph_contains_only_file_assets_and_evidenced_edges(sample_graph):
    assert sample_graph.assets
    assert {asset.node_type for asset in sample_graph.assets} <= set(AssetType)
    assert all("/" in asset.asset_id for asset in [])  # no symbol-shaped nodes exist
    assert all(edge.evidence_refs for edge in sample_graph.edges)
    assert all(edge.edge_type in set(EdgeType) for edge in sample_graph.edges)
    paths = {asset.path for asset in sample_graph.assets}
    assert "api/routes.py" in paths
    assert "services/loader.py" in paths
    assert any(edge.edge_type is EdgeType.IMPORTS for edge in sample_graph.edges)


def test_single_file_source_is_supported(tmp_path: Path):
    source = tmp_path / "one.py"
    source.write_text("import json\n", encoding="utf-8")
    graph = RepositoryExtractor().extract(source)
    assert len(graph.assets) == 1
    assert graph.assets[0].path == "one.py"


def test_binary_database_is_one_metadata_asset(tmp_path: Path):
    database = tmp_path / "payments.db"
    database.write_bytes(b"SQLite format 3\x00" + b"x" * 100)
    graph = RepositoryExtractor().extract(tmp_path)
    assert len(graph.assets) == 1
    assert graph.assets[0].node_type is AssetType.DATABASE_FILE
    assert graph.assets[0].is_binary
    assert graph.assets[0].line_count is None


def _write(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")


def _edges(graph, edge_type=None):
    paths = {asset.asset_id: asset.path for asset in graph.assets}
    return {
        (paths[edge.source_asset_id], paths[edge.target_asset_id], edge.resolution_method)
        for edge in graph.edges
        if edge_type is None or edge.edge_type is edge_type
    }


POLYGLOT_REPO = {
    # JS/TS: ../ climbs are normalized; bare specifiers are external.
    "web/package.json": "{}",
    "web/src/actions/userActions.ts": "export const a = 1;\n",
    "web/src/containers/signup/signup.js": (
        "import { a } from '../../actions/userActions';\nimport React from 'react';\n"
    ),
    # Python: imports written from the service root, `from . import views`, Django urls.
    "svc/manage.py": "",
    "svc/crapi/__init__.py": "",
    "svc/crapi/mechanic/__init__.py": "",
    "svc/crapi/mechanic/models.py": "class M: ...\n",
    "svc/crapi/mechanic/urls.py": "urlpatterns = []\n",
    "svc/crapi/shop/__init__.py": "",
    "svc/crapi/shop/views.py": (
        "import logging\nfrom crapi.mechanic.models import M\n"
        "class OrderView:\n    def get(self, request, order_id):\n        return M\n"
    ),
    "svc/crapi/shop/urls.py": (
        "from django.urls import re_path, include\nfrom . import views\n"
        "urlpatterns = [\n"
        "    re_path(r'orders/(?P<order_id>\\d+)$', views.OrderView.as_view()),\n"
        "    re_path(r'mech/', include('crapi.mechanic.urls')),\n]\n"
    ),
    # Java: fully qualified imports, routes, and path variables.
    "id/build.gradle.kts": "plugins {}\n",
    "id/src/main/java/com/x/service/Svc.java": "package com.x.service;\nclass Svc {}\n",
    "id/src/main/java/com/x/Ctl.java": (
        "package com.x;\nimport com.x.service.Svc;\nimport java.util.List;\n"
        "import com.x.model.*;\n@RestController\nclass Ctl {\n"
        '  @GetMapping("/api/v2/vehicle/{carId}/location")\n'
        "  Object get() { return restTemplate.getForObject(url, String.class); }\n}\n"
    ),
    # Go: grouped imports resolved through go.mod to package files (tests excluded).
    "go/go.mod": "module example.com/community\n\ngo 1.21\n",
    "go/api/models/coupon.go": "package models\n",
    "go/api/models/coupon_test.go": "package models\n",
    "go/api/router/routes.go": (
        'package router\n\nimport (\n\t"net/http"\n\tm "example.com/community/api/models"\n)\n'
        'func R() { r.HandleFunc("/community/api/v2/posts/{postID}", h)\n'
        '  _ = bson.M{"code": c}\n  cfg := &tls.Config{InsecureSkipVerify: true}\n}\n'
    ),
}


def test_polyglot_static_resolution(tmp_path: Path):
    _write(tmp_path, POLYGLOT_REPO)
    graph = RepositoryExtractor().extract(tmp_path)
    imports = _edges(graph, EdgeType.IMPORTS)
    assert (
        "web/src/containers/signup/signup.js",
        "web/src/actions/userActions.ts",
        "static_module_resolution",
    ) in imports
    assert (
        "svc/crapi/shop/views.py",
        "svc/crapi/mechanic/models.py",
        "static_module_resolution_ancestor_root",
    ) in imports
    assert (
        "id/src/main/java/com/x/Ctl.java",
        "id/src/main/java/com/x/service/Svc.java",
        "java_package_resolution",
    ) in imports
    assert ("go/api/router/routes.go", "go/api/models/coupon.go", "go_package_directory") in (
        imports
    )
    assert not any(target.endswith("_test.go") for _, target, _ in imports)
    routes = {(source, target) for source, target, _ in _edges(graph, EdgeType.ROUTES_TO)}
    assert routes == {
        ("svc/crapi/shop/urls.py", "svc/crapi/shop/views.py"),
        ("svc/crapi/shop/urls.py", "svc/crapi/mechanic/urls.py"),
    }
    reasons = {(item.reference, item.reason) for item in graph.unresolved}
    assert ("react", "external_reference") in reasons
    assert ("logging", "external_reference") in reasons
    assert ("java.util.List", "external_reference") in reasons
    assert ("com.x.model.*", "wildcard_package_import") in reasons
    assert ("net/http", "external_reference") in reasons
    assets = {asset.path: asset for asset in graph.assets}
    controller = assets["id/src/main/java/com/x/Ctl.java"].features
    assert controller["has_route"] and controller["route_params"] == ["carId"]
    assert "restTemplate.getForObject" in controller["api_symbols"]
    router = assets["go/api/router/routes.go"].features
    assert router["route_params"] == ["postID"]
    assert "bson.M" in router["api_symbols"] and router["tls_verification_disabled"]
    views = assets["svc/crapi/shop/views.py"].features
    assert views["http_handlers"] == ["OrderView.get"] and views["has_route"]
    assert assets["svc/crapi/shop/urls.py"].features["route_params"] == ["order_id"]
    assert assets["id/build.gradle.kts"].node_type is AssetType.MANIFEST_FILE


def test_source_files_link_to_nearest_manifest_of_their_own_ecosystem(tmp_path: Path):
    _write(
        tmp_path,
        {
            "requirements.txt": "flask\n",
            "svc/dev-requirements.txt": "pytest\n",
            "svc/requirements.txt": "django\n",
            "svc/app/deep/module.py": "x = 1\n",
            "svc/web/package.json": "{}",
            "svc/web/src/index.js": "export {};\n",
        },
    )
    graph = RepositoryExtractor().extract(tmp_path)
    manifests = _edges(graph, EdgeType.DEPENDS_ON_MANIFEST)
    module_targets = {target for source, target, _ in manifests if source.endswith("module.py")}
    assert module_targets == {"svc/requirements.txt"}
    js_targets = {target for source, target, _ in manifests if source.endswith("index.js")}
    assert js_targets == {"svc/web/package.json"}


def test_python_security_syntax_flags(tmp_path: Path):
    _write(
        tmp_path,
        {
            "a.py": (
                "import requests, jwt\n"
                "requests.get(url, verify=False)\n"
                "jwt.decode(token, options={'verify_signature': False})\n"
            ),
            "b.py": "import requests\nrequests.get(url)\n",
        },
    )
    graph = RepositoryExtractor().extract(tmp_path)
    features = {asset.path: asset.features for asset in graph.assets}
    assert features["a.py"]["tls_verification_disabled"] is True
    assert features["a.py"]["jwt_signature_verification_disabled"] is True
    assert features["b.py"]["tls_verification_disabled"] is False


def test_path_normalization_keeps_dotfile_directories(tmp_path: Path):
    _write(
        tmp_path,
        {
            ".github/scripts/util.js": "export {};\n",
            ".github/scripts/run.js": "import u from './util';\n",
            "escape.js": "import x from '../../outside';\n",
        },
    )
    graph = RepositoryExtractor().extract(tmp_path)
    assert (".github/scripts/run.js", ".github/scripts/util.js", "static_module_resolution") in (
        _edges(graph, EdgeType.IMPORTS)
    )
    assert any(item.reference == "../../outside" for item in graph.unresolved)
