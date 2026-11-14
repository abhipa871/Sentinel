from typing import Literal

from pydantic import Field

from .base import Model
from .investigation import Analyzer


class TaskIR(Model):
    id: str
    kind: Analyzer
    inputs: dict = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)
    evidence_requirements: list[str] = Field(default_factory=list)
    cacheable: bool = True
    sandbox_required: bool = False
    file_dependencies: list[str] = Field(default_factory=list)
    node_dependencies: list[str] = Field(default_factory=list)
    policy_rules: list[str] = Field(default_factory=lambda: ["authorized_scope", "allowlisted_tool"])


class WorkflowIR(Model):
    id: str
    hypothesis_id: str
    repository_commit: str
    tasks: list[TaskIR]
    outputs: list[str]
    scope: Literal["read_only", "mock_sandbox"] = "read_only"
    schedule: list[list[str]] = Field(default_factory=list)
    policy_version: str
    passes: list[str] = Field(default_factory=list)


class TaskResult(Model):
    task_id: str
    kind: Analyzer
    cache_hit: bool
    policy_checked: bool = True
    data: dict
    duration_ms: float
    cache_key: str
