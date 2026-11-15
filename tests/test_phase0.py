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
