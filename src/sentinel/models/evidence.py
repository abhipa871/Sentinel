from typing import Literal

from pydantic import Field

from .base import Model

Status = Literal["observed", "inferred", "assumed", "verified", "refuted", "unknown"]


class Evidence(Model):
    id: str
    kind: Literal["source_span", "mock_test"] = "source_span"
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    commit: str
    claim: str
    status: Status = "observed"
    scope: str = "repository_snapshot"
    source_hash: str | None = None
