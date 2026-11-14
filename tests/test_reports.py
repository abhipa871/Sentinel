from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.api.main import create_app
from sentinel.models.graph import OrganizationGraph
from sentinel.runtime.sandbox import verify_fixture
from sentinel.service import SentinelService


def test_mock_verifier_uses_synthetic_data():
    vulnerable = verify_fixture("refund_vulnerable")
    protected = verify_fixture("refund_safeguarded")
    assert vulnerable["status"] == "verified_within_fixture"
    assert protected["status"] == "blocked_within_fixture"
    assert vulnerable["synthetic_data"] and protected["synthetic_data"]
    assert vulnerable["backend_accepted"] and not protected["backend_accepted"]
    assert vulnerable["production_vulnerability"] == "not_established"
    assert vulnerable["isolation"]["arbitrary_code_supported"] is False
    with pytest.raises(ValueError):
        verify_fixture("../../unapproved.py")


def test_report_contains_all_required_fields(repo, tmp_path):
    service = SentinelService(tmp_path / "state")
    run = service.analyze(str(repo), authorized=True, allow_mock=True, use_agents=False)
    reports = service.artifact(run["id"], "scenarios")
    assert reports == []
    assert run["analysis_mode"] == "structure_only"
    OrganizationGraph.model_validate(service.artifact(run["id"], "organization_graph"))
    for artifact in [
        "organization_graph",
        "attack_graph",
        "scenarios",
        "compiled_workflows",
        "verification_results",
        "syntax_index",
        "agent_run_manifest",
    ]:
        assert (Path(run["artifact_directory"]) / (artifact + ".json")).exists()


def test_file_change_triggers_selective_recompilation(repo, tmp_path):
    service = SentinelService(tmp_path / "state")
    first = service.analyze(str(repo), authorized=True, use_agents=False)
    source = repo / "app" / "agent.py"
    source.write_text(source.read_text().replace("tools=[refund_tool]", "tools=[refund_tool, lookup_order]"))
    # Hash comparison detects all changes, even if caller omits the changed-files hint.
    second = service.reanalyze(first["id"])
    change = service.artifact(second["id"], "incremental")
    assert change["extracted_files"] == ["app/agent.py"]
    assert change["added_edges"]
    assert change["previous_workflow_ids"] == change["current_workflow_ids"] == []
    assert service.artifact(second["id"], "compiled_workflows") == []
    assert (service.run_dir(first["id"]) / "revisions" / "1" / "organization_graph.json").exists()


def test_deleted_file_drops_stale_graph_and_evidence(repo, tmp_path):
    service = SentinelService(tmp_path / "state")
    first = service.analyze(str(repo), authorized=True, use_agents=False)
    (repo / "app" / "agent.py").unlink()
    second = service.reanalyze(first["id"])
    graph = service.artifact(second["id"], "organization_graph")
    assert not any(n["path"] == "app/agent.py" for n in graph["nodes"])
    assert not any(e["path"] == "app/agent.py" for e in graph["evidence"])


def test_unrelated_repository_does_not_get_refund_scenarios(tmp_path):
    repo = tmp_path / "plain"
    repo.mkdir()
    (repo / "hello.py").write_text("def hello(): return 1")
    service = SentinelService(tmp_path / "state")
    run = service.analyze(str(repo), authorized=True, use_agents=False)
    assert service.artifact(run["id"], "scenarios") == []


def test_api_contract_and_scope(repo, tmp_path):
    service = SentinelService(tmp_path / "state", allowed_root=repo)
    with TestClient(create_app(service)) as client:
        assert client.post("/runs", json={"repo": str(repo), "authorized": False}).status_code == 400
        response = client.post("/runs", json={"repo": str(repo), "authorized": True, "use_agents": False})
        assert response.status_code == 201, response.text
        run_id = response.json()["id"]
        for suffix in ["", "/graph/organization", "/graph/attack", "/scenarios", "/workflows"]:
            assert client.get(f"/runs/{run_id}{suffix}").status_code == 200
        assert client.post(f"/runs/{run_id}/reanalyze", json={"changed_files": []}).status_code == 200
        assert client.post("/runs", json={"repo": str(tmp_path), "authorized": True}).status_code == 400
        assert (
            client.post(f"/runs/{run_id}/reanalyze", json={"changed_files": ["../outside.py"]}).status_code
            == 400
        )
        assert client.get("/runs/not-a-run-id").status_code == 400
        assert client.get("/runs/" + "f" * 32).status_code == 404


def test_repeated_approved_mock_proposals_preserve_unique_evidence(repo, tmp_path, monkeypatch):
    from sentinel.models.investigation import InvestigationQuestion, InvestigationRequest

    def proposal(context):
        return (
            InvestigationRequest(
                outcome_id=context.attack.outcome_id,
                questions=[
                    InvestigationQuestion(
                        hypothesis_id="agent-mock-question",
                        condition_id=context.attack.conditions[0].id,
                        analyzer="mock_verify",
                        fixture_id="refund_vulnerable",
                        reason="Compare synthetic fixture",
                    )
                ],
            ),
            [],
            [],
        )

    monkeypatch.setattr("sentinel.agents.supervisor.investigate", proposal)
    service = SentinelService(tmp_path / "state")
    run = service.analyze(str(repo), authorized=True, allow_mock=True, use_agents=True)
    graph = OrganizationGraph.model_validate(service.artifact(run["id"], "organization_graph"))
    assert len([e for e in graph.evidence if e.kind == "mock_test"]) == 2
    records = service.artifact(run["id"], "compiled_workflows")
    evidence_ids = {e.id for e in graph.evidence}
    assert all(
        r["data"]["evidence_id"] in evidence_ids
        for w in records
        for r in w["results"]
        if r["kind"] == "mock_verify"
    )
