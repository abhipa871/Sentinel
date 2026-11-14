from .prompts import TRUST_POLICY


def specialist_specs(tools, backend):
    from deepagents.middleware.filesystem import FilesystemMiddleware, FilesystemPermission
    from langchain.agents.middleware import ModelCallLimitMiddleware

    definitions = [
        (
            "graph-specialist",
            "Compatibility graph specialist using graph-evidence-validation and bounded retrieval.",
            ["get_graph_neighborhood"],
        ),
        (
            "source-intake-specialist",
            "Use source-ingestion. Inventory the authorized snapshot and select minimal relevant slices.",
            ["list_source_files", "get_source_slice"],
        ),
        (
            "file-dependency-specialist",
            "Use file-dependency-graph and graph-evidence-validation for intra-file relationships.",
            ["propose_graph_delta"],
        ),
        (
            "repository-dependency-specialist",
            "Use repository-dependency-graph and graph-evidence-validation for cross-file relationships.",
            ["propose_graph_delta"],
        ),
        (
            "security-finding-specialist",
            "Use vulnerability-analysis to make one independent per-file review before any outcome mapping.",
            ["get_syntax_facts", "get_source_slice", "submit_security_review"],
        ),
        (
            "attack-path-specialist",
            "Use attack-graph-reasoning to propose hypothetical AND/OR/NOT paths and counterevidence.",
            ["get_graph_neighborhood", "get_attack_conditions", "propose_hypotheses"],
        ),
        (
            "hypothetical-compromise-specialist",
            "Use hypothetical-compromise-evaluation; assumptions never become observed facts.",
            ["get_graph_neighborhood", "get_attack_conditions", "propose_hypotheses"],
        ),
        (
            "verification-planner",
            "Use jit-verification-planning to submit typed questions; do not invoke tests directly.",
            ["propose_investigation"],
        ),
        (
            "scenario-reporting-specialist",
            "Use scenario-reporting to identify evidence, assumptions, unknowns, and interruption points.",
            ["get_graph_neighborhood", "get_attack_conditions"],
        ),
        (
            "benchmark-analysis-specialist",
            "Use benchmark-evaluation and vulnerability-analysis for one named case; labels and expected CWEs are unavailable.",
            ["get_syntax_facts", "get_source_slice", "submit_security_review"],
        ),
        (
            "outcome-mapping-specialist",
            "Map accepted generic findings to only the authorized dangerous outcome as a separate inference.",
            ["list_finding_proposals", "get_attack_conditions", "propose_outcome_mappings"],
        ),
    ]
    return [
        {
            "name": name,
            "description": description,
            "system_prompt": TRUST_POLICY + description,
            "tools": [tools[k] for k in names],
            "skills": ["/skills"],
            "middleware": [
                FilesystemMiddleware(
                    backend=backend,
                    tools=["read_file"],
                    permissions=[
                        FilesystemPermission(operations=["read"], paths=["/skills/**"], mode="allow"),
                        FilesystemPermission(operations=["read"], paths=["/**"], mode="deny"),
                    ],
                ),
                ModelCallLimitMiddleware(run_limit=6, exit_behavior="end"),
            ],
        }
        for name, description, names in definitions
    ]
