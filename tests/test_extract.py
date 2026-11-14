from io import BytesIO
from zipfile import ZipFile

import pytest

from sentinel.config import Limits
from sentinel.graph.builder import build_graph, extract_files
from sentinel.ingest.repository import IngestionError, archive_snapshot, github_archive_url, ingest


def test_extracts_fastapi_route_and_source_span(context):
    endpoint = next(n for n in context.graph.nodes if n.type == "API_ENDPOINT")
    assert endpoint.name == "POST /support"
    evidence = next(e for e in context.graph.evidence if e.id in endpoint.evidence_ids)
    assert evidence.path == "app/main.py"
    assert evidence.start_line == 7
    assert evidence.end_line >= evidence.start_line
    assert evidence.commit.startswith("snapshot:")


def test_extracts_agent_tool_declaration(context):
    nodes = {n.id: n for n in context.graph.nodes}
    callable_edge = next(e for e in context.graph.edges if e.type == "CAN_INVOKE")
    assert nodes[callable_edge.source].name == "support_agent"
    assert nodes[callable_edge.target].name == "refund_tool"
    assert callable_edge.epistemic_status == "observed"
    payment = next(n for n in nodes.values() if n.name == "payment_api")
    assert any(
        e.source == callable_edge.target and e.target == payment.id and e.type == "CALLS"
        for e in context.graph.edges
    )
    assert any(e.type == "WRITES" for e in context.graph.edges)
    assert any(e.target == callable_edge.source and e.type == "CALLS" for e in context.graph.edges)
    assert all(e.epistemic_status == "unknown" for e in context.graph.edges if e.type == "RUNS_AS")


def test_ingestion_never_executes_repository_code(repo, tmp_path):
    marker = tmp_path / "executed"
    (repo / "trap.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('BAD')\nraise RuntimeError('do not execute')\n"
    )
    snapshot = ingest(str(repo), authorized=True)
    extract_files(snapshot)
    assert not marker.exists()


def test_secret_files_and_values_are_not_exposed(repo):
    (repo / ".env").write_text("OPENAI_API_KEY=do-not-disclose")
    (repo / ".env.example").write_text("API_KEY=also-do-not-disclose")
    (repo / "settings.json").write_text('{"password": "secret-config-value"}')
    snapshot = ingest(str(repo), authorized=True)
    assert ".env" not in snapshot.files
    facts, _ = extract_files(snapshot)
    serialized = build_graph(snapshot, facts).model_dump_json()
    assert "do-not-disclose" not in serialized
    assert "secret-config-value" not in serialized


def test_authorization_and_resource_limits(repo):
    with pytest.raises(IngestionError):
        ingest(str(repo), authorized=False)
    with pytest.raises(IngestionError):
        ingest(str(repo), authorized=True, limits=Limits(max_file_bytes=10))


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",
        "https://localhost/a/b",
        "https://github.com@127.0.0.1/a/b",
        "https://github.com:443/a/b",
        "https://github.com/a/b?token=bad",
        "https://github.com/a/../b",
    ],
)
def test_rejects_remote_scope_bypass(url):
    with pytest.raises(IngestionError):
        github_archive_url(url)


def test_safe_github_archive_and_zip_slip():
    assert (
        github_archive_url("https://github.com/owner/repo.git")
        == "https://codeload.github.com/owner/repo/zip/HEAD"
    )
    data = BytesIO()
    with ZipFile(data, "w") as z:
        z.writestr("repo-HEAD/main.py", "def safe(): pass")
    snapshot = archive_snapshot("https://github.com/a/b", data.getvalue())
    assert list(snapshot.files) == ["main.py"]
    data = BytesIO()
    with ZipFile(data, "w") as z:
        z.writestr("repo/../../outside.py", "pass")
    with pytest.raises(IngestionError):
        archive_snapshot("https://github.com/a/b", data.getvalue())


def test_missing_iam_data_is_unknown_not_true(context):
    condition = next(c for c in context.attack.conditions if c.id == "condition:privileged_authority")
    assert condition.truth == "unknown"
    assert condition.status == "unknown"
    assert all(n.attributes.get("deployed_permissions", "unknown") == "unknown" for n in context.graph.nodes)


def test_only_changed_files_are_reextracted(repo):
    first = ingest(str(repo), authorized=True)
    old_facts, _ = extract_files(first)
    (repo / "app" / "agent.py").write_text(
        "from .tools import refund_tool\nsupport_agent = create_agent(tools=[])\n"
    )
    second = ingest(str(repo), authorized=True)
    new_facts, extracted = extract_files(second, old_facts, first.hashes)
    assert extracted == ["app/agent.py"]
    assert new_facts["app/payment.py"] is old_facts["app/payment.py"]
    graph = build_graph(second, new_facts)
    assert not any(e.type == "CAN_INVOKE" for e in graph.edges)
