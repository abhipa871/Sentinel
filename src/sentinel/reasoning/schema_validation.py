from typing import Literal

from pydantic import Field

from sentinel.models.attack import Formula
from sentinel.models.base import Model
from sentinel.models.investigation import InvestigationRequest


class CandidateHypothesis(Model):
    id: str
    outcome_id: str
    formula: Formula
    status: Literal["hypothetical"] = "hypothetical"
    evidence_ids: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)


def validate_hypotheses(payload, graph, attack):
    if len(payload) > 12:
        raise ValueError("Hypothesis limit exceeded")
    known_evidence = {e.id for e in graph.evidence}
    known_conditions = {c.id for c in attack.conditions}
    result, seen = [], set()
    for raw in payload:
        candidate = CandidateHypothesis.model_validate(raw)
        if candidate.outcome_id != attack.outcome_id or not set(candidate.evidence_ids) <= known_evidence:
            raise ValueError("Untrusted hypothesis references")

        def check(formula):
            if formula.condition_id and formula.condition_id not in known_conditions:
                raise ValueError("Unknown condition reference")
            for child in formula.children:
                check(child)

        check(candidate.formula)
        signature = candidate.formula.model_dump_json()
        if signature not in seen:
            seen.add(signature)
            result.append(candidate)
    return result


def validate_request(payload, graph, attack):
    request = InvestigationRequest.model_validate(payload)
    evidence = {e.id for e in graph.evidence}
    conditions = {c.id for c in attack.conditions}
    if request.outcome_id != attack.outcome_id:
        raise ValueError("Unapproved outcome")
    for question in request.questions:
        if question.condition_id not in conditions or not set(question.evidence_ids) <= evidence:
            raise ValueError("Unknown condition or evidence ID")
        if question.analyzer == "mock_verify" and question.fixture_id is None:
            raise ValueError("An approved fixture ID is required")
        if question.analyzer != "mock_verify" and question.fixture_id is not None:
            raise ValueError("Fixture IDs are only accepted for mock verification")
    return request
