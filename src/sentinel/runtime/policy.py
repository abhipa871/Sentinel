"""Mandatory deterministic checks, independent of prompts and compiler optimizations."""

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field

from sentinel.ingest.file_index import Snapshot
from sentinel.models.attack import AttackGraph
from sentinel.models.base import Model
from sentinel.models.graph import OrganizationGraph

POLICY_VERSION = "sentinel-policy-2"
TOOL_VERSION = "sentinel-tools-3"
ALLOWLIST = frozenset(
    {"inspect_source", "inspect_auth", "inspect_agent_tools", "retrieve_graph", "mock_verify"}
)
FIXTURES = frozenset({"refund_vulnerable", "refund_safeguarded"})


class PolicyError(ValueError):
    pass


class SourceInput(Model):
    path: str
    node_ids: list[str] = Field(default_factory=list, max_length=20)


class GraphInput(Model):
    node_ids: list[str] = Field(default_factory=list, max_length=20)
    depth: int = Field(default=2, ge=0, le=3)


class MockInput(Model):
    fixture_id: Literal["refund_vulnerable", "refund_safeguarded"]


@dataclass(frozen=True)
class RunContext:
    snapshot: Snapshot
    graph: OrganizationGraph
    attack: AttackGraph
    authorized: bool
    allow_mock: bool = False
    policy_version: str = POLICY_VERSION
    max_tasks: int = 64

    @property
    def policy_context(self):
        return {
            "repository": self.snapshot.repository_id,
            "authorized": self.authorized,
            "allow_mock": self.allow_mock,
            "policy_version": self.policy_version,
        }


def validate_task(task, context, scope):
    if not context.authorized or task.kind not in ALLOWLIST:
        raise PolicyError("Execution is not authorized")
    if not {"authorized_scope", "allowlisted_tool"} <= set(task.policy_rules):
        raise PolicyError("Mandatory policy rules cannot be removed")
    nodes = {n.id: n for n in context.graph.nodes}
    evidence = {e.id for e in context.graph.evidence}
    if not set(task.evidence_requirements) <= evidence or not set(task.node_dependencies) <= set(nodes):
        raise PolicyError("Unknown task evidence or graph node")
    if not set(task.file_dependencies) <= set(context.snapshot.files):
        raise PolicyError("Unknown file dependency")
    if task.kind == "mock_verify":
        inputs = MockInput.model_validate(task.inputs)
        if not context.allow_mock or scope != "mock_sandbox" or not task.sandbox_required or task.cacheable:
            raise PolicyError("Mock verification requires explicit opt-in, isolation, and fresh execution")
        if inputs.fixture_id not in FIXTURES:
            raise PolicyError("Unapproved synthetic fixture")
    else:
        if task.sandbox_required:
            raise PolicyError("Unexpected sandbox request")
        if task.kind == "retrieve_graph":
            inputs = GraphInput.model_validate(task.inputs)
        else:
            inputs = SourceInput.model_validate(task.inputs)
            path = PurePosixPath(inputs.path)
            if path.is_absolute() or ".." in path.parts or "\\" in inputs.path or ":" in inputs.path:
                raise PolicyError("Unsafe source path")
            if inputs.path not in context.snapshot.files or inputs.path not in task.file_dependencies:
                raise PolicyError("Source path outside authorized snapshot")
            if any(node_id not in nodes or nodes[node_id].path != inputs.path for node_id in inputs.node_ids):
                raise PolicyError("Node does not belong to the requested file")
        if not set(inputs.node_ids) <= set(nodes):
            raise PolicyError("Unknown graph node")
    return True


def validate_workflow(workflow, context):
    if (
        workflow.policy_version != context.policy_version
        or workflow.repository_commit != context.snapshot.commit
    ):
        raise PolicyError("Stale workflow or policy version")
    if len(workflow.tasks) > context.max_tasks:
        raise PolicyError("Task budget exceeded")
    ids = {t.id for t in workflow.tasks}
    if len(ids) != len(workflow.tasks) or not set(workflow.outputs) <= ids:
        raise PolicyError("Invalid task/output IDs")
    for task in workflow.tasks:
        if not set(task.depends_on) <= ids or task.id in task.depends_on:
            raise PolicyError("Invalid task dependency")
        validate_task(task, context, workflow.scope)
        if task.kind == "mock_verify":
            prerequisite_kinds = {t.kind for t in workflow.tasks if t.id in task.depends_on}
            required = {"retrieve_graph"}
            required.update(
                c.analyzer
                for c in context.attack.conditions
                if c.asset_ids and c.analyzer in {"inspect_auth", "inspect_agent_tools"}
            )
            if not required <= prerequisite_kinds:
                raise PolicyError("Mock verification is missing mandatory inspection prerequisites")
    from sentinel.compiler.passes import topological_schedule

    topological_schedule(workflow.tasks)
    return True
