from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from sentinel.contracts import (
    ApprovalEvent,
    ApprovalScope,
    ProposalDecision,
    RemediationProposal,
)


def proposal_digest(proposal: RemediationProposal) -> str:
    data = proposal.model_dump(mode="json")
    data["human_decision"] = ProposalDecision.PENDING.value
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class ApprovalError(PermissionError):
    pass


class ApprovalLedger:
    """Append-only per-proposal approval history."""

    def __init__(self) -> None:
        self._events: list[ApprovalEvent] = []

    @property
    def events(self) -> tuple[ApprovalEvent, ...]:
        return tuple(self._events)

    def record(
        self,
        *,
        proposal: RemediationProposal,
        proposal_sha256: str,
        actor_id: UUID,
        actor_role: str,
        decision: ProposalDecision,
        scope: ApprovalScope | None = None,
        reason: str | None = None,
    ) -> ApprovalEvent:
        if actor_role != "Approver":
            raise ApprovalError("actor role cannot decide technical proposals")
        expected = proposal_digest(proposal)
        if proposal_sha256 != expected:
            raise ApprovalError("proposal digest or version is stale")
        if decision is ProposalDecision.ACCEPT:
            if scope is None:
                raise ApprovalError("acceptance requires immutable execution scope")
            if set(scope.paths) - set(proposal.allowed_paths):
                raise ApprovalError("approval scope expands the reviewed proposal")
            if scope.expires_at <= datetime.now(UTC):
                raise ApprovalError("approval scope is expired")
        elif scope is not None:
            raise ApprovalError("non-accept decisions cannot grant execution scope")
        event = ApprovalEvent(
            proposal_id=proposal.proposal_id,
            proposal_version=proposal.version,
            proposal_sha256=expected,
            actor_id=actor_id,
            actor_role=actor_role,
            decision=decision,
            scope=scope,
            reason=reason,
        )
        self._events.append(event)
        return event

    def latest(self, proposal_id: UUID, version: int) -> ApprovalEvent | None:
        matching = [
            event
            for event in self._events
            if event.proposal_id == proposal_id and event.proposal_version == version
        ]
        return matching[-1] if matching else None


class TextPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    path: str
    expected_sha256: str
    replacement_text: str = Field(max_length=2_000_000)


class WriteGateway:
    """Independent source-write gate. Disabled unless explicitly configured."""

    def __init__(self, *, enabled: bool = False) -> None:
        self.enabled = enabled

    def authorize(
        self,
        *,
        proposal: RemediationProposal,
        event: ApprovalEvent,
        repository_id: str,
        base_commit_sha: str,
        executor_actor_role: str,
        operation: str,
        path: str,
    ) -> None:
        if not self.enabled:
            raise ApprovalError("source writes are disabled")
        if executor_actor_role != "RepositoryMaintainer":
            raise ApprovalError("execution requires a separate RepositoryMaintainer")
        if event.decision is not ProposalDecision.ACCEPT or event.scope is None:
            raise ApprovalError("proposal is not accepted for execution")
        if event.proposal_id != proposal.proposal_id or event.proposal_version != proposal.version:
            raise ApprovalError("approval does not bind this proposal version")
        if event.proposal_sha256 != proposal_digest(proposal):
            raise ApprovalError("proposal content changed after approval")
        scope = event.scope
        if scope.expires_at <= datetime.now(UTC):
            raise ApprovalError("approval expired")
        if scope.repository_id != repository_id or scope.base_commit_sha != base_commit_sha:
            raise ApprovalError("repository or base commit drifted")
        if operation not in scope.permitted_operations:
            raise ApprovalError("operation is outside approved scope")
        if path not in scope.paths or path not in proposal.allowed_paths:
            raise ApprovalError("path is outside approved scope")

    def apply_text_patch(
        self,
        *,
        root: Path,
        proposal: RemediationProposal,
        event: ApprovalEvent,
        repository_id: str,
        base_commit_sha: str,
        executor_actor_role: str,
        patch: TextPatch,
    ) -> str:
        self.authorize(
            proposal=proposal,
            event=event,
            repository_id=repository_id,
            base_commit_sha=base_commit_sha,
            executor_actor_role=executor_actor_role,
            operation="patch_files",
            path=patch.path,
        )
        resolved_root = root.resolve()
        target = (resolved_root / patch.path).resolve()
        try:
            target.relative_to(resolved_root)
        except ValueError as exc:
            raise ApprovalError("patch path escapes repository root") from exc
        if target.is_symlink() or not target.is_file():
            raise ApprovalError("patch target must be an existing non-symlink file")
        current = target.read_bytes()
        if hashlib.sha256(current).hexdigest() != patch.expected_sha256:
            raise ApprovalError("patch target drifted")
        temporary = target.with_name(f".{target.name}.sentinel.tmp")
        temporary.write_text(patch.replacement_text, encoding="utf-8", newline="")
        temporary.replace(target)
        return hashlib.sha256(target.read_bytes()).hexdigest()
