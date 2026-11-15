from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.approval import (
    ApprovalError,
    ApprovalLedger,
    TextPatch,
    WriteGateway,
    proposal_digest,
)
from sentinel.contracts import ApprovalScope, ProposalDecision
from tests.test_module3 import _plan


def test_approval_is_digest_version_and_scope_bound(sample_graph):
    _, planning = _plan(sample_graph)
    proposal = planning.remediations[0]
    scope = ApprovalScope(
        repository_id="repo-1",
        base_commit_sha=sample_graph.snapshot.commit_sha,
        paths=proposal.allowed_paths,
        permitted_operations=("patch_files",),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    event = ApprovalLedger().record(
        proposal=proposal,
        proposal_sha256=proposal_digest(proposal),
        actor_id=uuid4(),
        actor_role="Approver",
        decision=ProposalDecision.ACCEPT,
        scope=scope,
    )
    assert event.scope == scope


def test_scope_expansion_and_disabled_writes_are_denied(sample_graph):
    _, planning = _plan(sample_graph)
    proposal = planning.remediations[0]
    scope = ApprovalScope(
        repository_id="repo-1",
        base_commit_sha=sample_graph.snapshot.commit_sha,
        paths=("other.py",),
        permitted_operations=("patch_files",),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    with pytest.raises(ApprovalError):
        ApprovalLedger().record(
            proposal=proposal,
            proposal_sha256=proposal_digest(proposal),
            actor_id=uuid4(),
            actor_role="Approver",
            decision=ProposalDecision.ACCEPT,
            scope=scope,
        )
    gateway = WriteGateway(enabled=False)
    with pytest.raises(ApprovalError, match="disabled"):
        gateway.authorize(
            proposal=proposal,
            event=proposal.model_copy(),  # type: ignore[arg-type]
            repository_id="repo-1",
            base_commit_sha=sample_graph.snapshot.commit_sha,
            executor_actor_role="RepositoryMaintainer",
            operation="patch_files",
            path=proposal.allowed_paths[0],
        )


def test_enabled_gateway_applies_only_exact_approved_patch(sample_graph, sample_repo: Path):
    _, planning = _plan(sample_graph)
    proposal = planning.remediations[0]
    scope = ApprovalScope(
        repository_id="repo-1",
        base_commit_sha=sample_graph.snapshot.commit_sha,
        paths=proposal.allowed_paths,
        permitted_operations=("patch_files",),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    event = ApprovalLedger().record(
        proposal=proposal,
        proposal_sha256=proposal_digest(proposal),
        actor_id=uuid4(),
        actor_role="Approver",
        decision=ProposalDecision.ACCEPT,
        scope=scope,
    )
    target = sample_repo / proposal.allowed_paths[0]
    import hashlib

    original_hash = hashlib.sha256(target.read_bytes()).hexdigest()
    new_hash = WriteGateway(enabled=True).apply_text_patch(
        root=sample_repo,
        proposal=proposal,
        event=event,
        repository_id="repo-1",
        base_commit_sha=sample_graph.snapshot.commit_sha,
        executor_actor_role="RepositoryMaintainer",
        patch=TextPatch(
            path=proposal.allowed_paths[0],
            expected_sha256=original_hash,
            replacement_text="def load(data):\n    raise ValueError('disabled in fixture')\n",
        ),
    )
    assert new_hash != original_hash
    with pytest.raises(ApprovalError, match="commit"):
        WriteGateway(enabled=True).authorize(
            proposal=proposal,
            event=event,
            repository_id="repo-1",
            base_commit_sha="0" * 40,
            executor_actor_role="RepositoryMaintainer",
            operation="patch_files",
            path=proposal.allowed_paths[0],
        )
