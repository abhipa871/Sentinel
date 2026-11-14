from typing import Literal

from pydantic import Field, model_validator

from .base import Model


class SourceLocation(Model):
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    role: Literal["source", "propagation", "sink"]


class StaticFinding(Model):
    id: str
    rule_id: str
    cwe: str = Field(pattern=r"^CWE-[0-9]+$")
    title: str
    status: Literal["static_supported"] = "static_supported"
    epistemic_status: Literal["inferred"] = "inferred"
    path: str
    symbol: str
    sink: SourceLocation
    trace: list[SourceLocation] = Field(min_length=1, max_length=40)
    evidence_ids: list[str] = Field(min_length=1)
    confidence: Literal["medium", "high"] = "medium"
    dangerous_outcome: str | None = None
    assumptions: list[str]
    unknowns: list[str]
    interruption_points: list[str]

    @model_validator(mode="after")
    def consistent_path(self):
        if self.path != self.sink.path or self.sink.role != "sink":
            raise ValueError("Finding path must identify its sink")
        return self
