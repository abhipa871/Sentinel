import shutil
from pathlib import Path

import pytest

from sentinel.compiler.invalidation import AnalysisCache
from sentinel.graph.builder import build_graph, extract_files
from sentinel.ingest.repository import ingest
from sentinel.reasoning.backward import backward_expand
from sentinel.runtime.policy import RunContext


@pytest.fixture
def repo(tmp_path):
    target = tmp_path / "repo"
    shutil.copytree(Path(__file__).parent / "fixtures" / "toy_refund_app", target)
    return target


@pytest.fixture
def context(repo):
    snapshot = ingest(str(repo), authorized=True)
    facts, _ = extract_files(snapshot)
    graph = build_graph(snapshot, facts)
    attack = backward_expand("unauthorized_refund", graph)
    return RunContext(snapshot, graph, attack, authorized=True)


@pytest.fixture
def cache(tmp_path):
    return AnalysisCache(tmp_path / "cache.sqlite3")
