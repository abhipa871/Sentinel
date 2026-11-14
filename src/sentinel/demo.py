import shutil
from importlib.resources import files
from pathlib import Path
from uuid import uuid4


def run_demo(service, interactive=False):
    """Copy only the bundled synthetic fixture and demonstrate one incremental change."""
    source = Path(str(files("sentinel").joinpath("demo_fixture")))
    target = service.state_dir / "demos" / uuid4().hex
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    initial = service.analyze(str(target), authorized=True, allow_mock=True)
    print(f"Initial run: {initial['id']} | {initial['metrics']}")
    if interactive:
        input("Press Enter to add a declared lookup tool to the synthetic agent...")
    agent_file = target / "app" / "agent.py"
    content = agent_file.read_text(encoding="utf-8")
    agent_file.write_text(
        content.replace("tools=[refund_tool]", "tools=[refund_tool, lookup_order]"), encoding="utf-8"
    )
    updated = service.reanalyze(initial["id"], ["app/agent.py"])
    incremental = service.artifact(updated["id"], "incremental")
    print(f"Updated run: revision {updated['revision']} | {updated['metrics']}")
    print(f"Extracted: {incremental['extracted_files']}")
    print(
        f"Invalidated {len(incremental['invalidated_task_ids'])} cached tasks; reused {len(incremental['reused_cached_task_ids'])} results."
    )
    print(f"Added graph edges: {len(incremental['added_edges'])}")
    print(f"Artifacts: {updated['artifact_directory']}")
    if interactive:
        import json

        options = {
            "1": "scenarios",
            "2": "counterfactuals",
            "3": "shared_dependencies",
            "4": "compiled_workflows",
        }
        while True:
            choice = input(
                "Inspect 1=scenarios, 2=compromises, 3=shared conditions, 4=workflows, q=quit: "
            ).strip()
            if choice == "q":
                break
            if choice in options:
                print(json.dumps(service.artifact(updated["id"], options[choice]), indent=2))
    return updated
