from typing import Literal

from pydantic import Field

from .base import Model

Analyzer = Literal["inspect_source", "inspect_auth", "inspect_agent_tools", "retrieve_graph", "mock_verify"]


class InvestigationQuestion(Model):
    hypothesis_id: str = Field(max_length=120)
    condition_id: str
    evidence_ids: list[str] = Field(default_factory=list, max_length=40)
    analyzer: Analyzer
    reason: str = Field(max_length=1000)
    fixture_id: Literal["refund_vulnerable", "refund_safeguarded"] | None = None


class InvestigationRequest(Model):
    outcome_id: str
    questions: list[InvestigationQuestion] = Field(default_factory=list, max_length=12)
    assumptions: list[str] = Field(default_factory=list, max_length=12)
