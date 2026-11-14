import json
from pathlib import Path

import pytest
import yaml

from sentinel.agents.context import AgentContext, make_tools
from sentinel.agents.semantic import apply_graph_deltas, build_findings
from sentinel.ingest.repository import ingest


def test_single_file_ingestion_is_bounded_and_read_only(tmp_path):
    source = tmp_path / "one.py"
    source.write_text("def one():\n    return 1\n", encoding="utf-8")
    snapshot = ingest(str(source), authorized=True, allowed_root=tmp_path)
    assert snapshot.files["one.py"].splitlines() == ["def one():", "    return 1"]
    assert snapshot.source == str(source.resolve())


def test_source_slice_and_finding_proposal_require_real_evidence(context):
    state = AgentContext(context)
    tools = make_tools(state)
    schema = tools["submit_security_review"].args_schema.model_json_schema()
    assert "path" not in json.dumps(schema["properties"])
    assert {"review", "findings"} <= set(schema["properties"])
    path = next(
        path
        for path in sorted(context.snapshot.files)
        if path.endswith(".py") and context.snapshot.files[path]
    )
    end_line = min(2, len(context.snapshot.files[path].splitlines()))
    result = json.loads(
        tools["get_source_slice"].invoke({"path": path, "start_line": 1, "end_line": end_line})
    )
    evidence_id = result["evidence_id"]
    state.active_security_path = path
    proposal = {
        "cwe": "CWE-89",
        "title": "Potential SQL injection",
        "symbol": "example",
        "sink_start_line": 1,
        "sink_end_line": 1,
        "source_evidence_ids": [evidence_id],
        "sink_evidence_ids": [evidence_id],
        "interruption_points": ["Use a parameterized query"],
    }
    review = {
        "status": "finding_proposed",
        "evidence_ids": [evidence_id],
        "rationale": "A source-controlled value reaches a sensitive operation",
    }
    submitted = tools["submit_security_review"].invoke({"review": review, "findings": [proposal]})
    assert json.loads(submitted)["accepted_findings"] == 1
    generic = build_findings(state)[0]
    assert generic.cwe == "CWE-89" and generic.dangerous_outcome is None
    listed = json.loads(tools["list_finding_proposals"].invoke({}))
    tools["propose_outcome_mappings"].invoke(
        {
            "mappings": [
                {
                    "finding_id": listed["findings"][0]["finding_id"],
                    "outcome_id": context.attack.outcome_id,
                    "evidence_ids": [evidence_id],
                    "rationale": "The accepted finding can contribute to the authorized outcome",
                }
            ]
        }
    )
    finding = build_findings(state)[0]
    assert finding.epistemic_status == "inferred" and finding.dangerous_outcome == context.attack.outcome_id
    proposal["source_evidence_ids"] = ["evidence:fabricated"]
    other = AgentContext(context)
    other.active_security_path = path
    other_tools = make_tools(other)
    other_tools["get_source_slice"].invoke({"path": path, "start_line": 1, "end_line": end_line})
    with pytest.raises(ValueError):
        other_tools["submit_security_review"].invoke({"review": review, "findings": [proposal]})


def test_neutral_syntax_facts_support_agent_reasoning_without_classification(context):
    state = AgentContext(context)
    tools = make_tools(state)
    path = "app/database.py"
    result = json.loads(tools["get_syntax_facts"].invoke({"path": path}))
    assert result["semantics"] == "unclassified_syntax_only"
    assert all("cwe" not in item and "vulnerability" not in item for item in result["calls"])


def test_agent_graph_delta_is_typed_and_snapshot_scoped(context):
    state = AgentContext(context)
    tools = make_tools(state)
    path = sorted(context.snapshot.files)[0]
    evidence_id = json.loads(
        tools["get_source_slice"].invoke({"path": path, "start_line": 1, "end_line": 1})
    )["evidence_id"]
    nodes = [
        {
            "key": "agent-module",
            "type": "MODULE",
            "name": "Agent reviewed module",
            "path": path,
            "evidence_ids": [evidence_id],
        }
    ]
    assert json.loads(tools["propose_graph_delta"].invoke({"nodes": nodes, "edges": []}))["accepted"]
    apply_graph_deltas(state)
    assert any(node.attributes.get("producer") == "deepagents" for node in context.graph.nodes)
    nodes[0]["path"] = "../outside.py"
    with pytest.raises(ValueError):
        tools["propose_graph_delta"].invoke({"nodes": nodes, "edges": []})


def test_packaged_skills_and_charter_are_complete():
    root = Path(__file__).resolve().parents[1]
    index = (root / "SKILLS.md").read_text(encoding="utf-8")
    charter = (root / "AGENTS.md").read_text(encoding="utf-8")
    skill_root = root / "src" / "sentinel" / "skills"
    skills = []
    for path in sorted(skill_root.glob("*/SKILL.md")):
        text = path.read_text(encoding="utf-8")
        frontmatter = yaml.safe_load(text.split("---", 2)[1])
        assert frontmatter["name"] == path.parent.name
        assert frontmatter["name"] in index
        skills.append(frontmatter["name"])
    assert len(skills) == 11
    assert "LangChain Deep Agents is required" in charter
    assert "Ground-truth labels" in charter
