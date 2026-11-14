from typing import Literal

from pydantic import Field

from .base import Model


class ScenarioReport(Model):
    scenario_id: str
    title: str
    status: Literal["hypothetical", "refuted_within_model", "static_supported"] = "hypothetical"
    dangerous_outcome: str
    required_conditions: list[dict]
    possible_impact: str
    critical_dependencies: list[str]
    alternate_routes: list[str]
    interruption_points: list[dict]
    verified_facts: list[str]
    assumptions: list[str]
    unknowns: list[str]
    evidence_ids: list[str]
    confidence_evidence: dict
    verification: list[dict] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
