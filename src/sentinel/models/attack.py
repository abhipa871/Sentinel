from typing import Literal

from pydantic import Field, model_validator

from .base import Model
from .evidence import Status

Truth = Literal["true", "false", "unknown"]


class Formula(Model):
    op: Literal["AND", "OR", "NOT"] | None = None
    condition_id: str | None = None
    children: list["Formula"] = Field(default_factory=list)

    @model_validator(mode="after")
    def structure(self):
        if self.condition_id is not None:
            if self.op is not None or self.children:
                raise ValueError("A leaf cannot also be a gate")
        elif self.op is None or not self.children or (self.op == "NOT" and len(self.children) != 1):
            raise ValueError("Invalid Boolean gate")
        return self


class Condition(Model):
    id: str
    description: str
    asset_ids: list[str] = Field(default_factory=list)
    status: Status = "unknown"
    truth: Truth = "unknown"
    evidence_ids: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    mechanism_id: str
    analyzer: Literal["inspect_source", "inspect_auth", "inspect_agent_tools", "retrieve_graph"]
    binding: str


class AttackGraph(Model):
    outcome_id: str
    formula: Formula
    conditions: list[Condition]
    paths: list[list[str]]
    bounds: dict
    applicable: bool = True
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def references(self):
        ids = {c.id for c in self.conditions}

        def visit(f):
            if f.condition_id and f.condition_id not in ids:
                raise ValueError("Unknown condition")
            for child in f.children:
                visit(child)

        visit(self.formula)
        return self
