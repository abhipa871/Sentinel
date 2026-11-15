from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from sentinel.agents.runtime import DeepAgentsRuntime
from sentinel.approval import ApprovalLedger, proposal_digest
from sentinel.config import get_settings
from sentinel.contracts import ApprovalScope, ProposalDecision
from sentinel.knowledge_graph import KnowledgeGraphIndex
from sentinel.pipeline import SentinelPipeline
from sentinel.secrets import redact_secrets
from sentinel.store import MemoryStore


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True)
    actor_id: UUID
    role: str


def principal(
    actor: Annotated[UUID, Header(alias="X-Sentinel-Actor")],
    role: Annotated[str, Header(alias="X-Sentinel-Role")],
) -> Principal:
    return Principal(actor_id=actor, role=role)


def require(*roles: str):
    def dependency(value: Annotated[Principal, Depends(principal)]) -> Principal:
        if value.role not in roles:
            raise HTTPException(status_code=403, detail="role is not authorized")
        return value

    return dependency


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_url: str
    ref: str = "HEAD"
    scan_profile: Literal["fast", "balanced", "deep"] = "balanced"
    allow_sandbox_tests: bool = False
    max_candidates: int = Field(default=500, ge=1, le=10_000)
    requested_modules: tuple[Literal["phase0", "module1", "module2", "module3"], ...] = (
        "phase0",
        "module1",
    )


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_version: int
    proposal_sha256: str
    decision: ProposalDecision
    scope: ApprovalScope | None = None
    comment: str | None = None


def create_app(
    *,
    pipeline: SentinelPipeline | None = None,
    store: MemoryStore | None = None,
) -> FastAPI:
    settings = get_settings()
    if pipeline is None:
        runtime = (
            DeepAgentsRuntime(
                settings.model_id_supervisor,
                code_model=settings.model_id_code_analysis,
                review_model=settings.model_id_review,
            )
            if settings.model_id_supervisor
            else None
        )
        pipeline = SentinelPipeline(runtime=runtime)
    store = store or MemoryStore()
    ledger = ApprovalLedger()
    app = FastAPI(title="SENTINEL API", version="1.0.0")
    app.state.pipeline = pipeline
    app.state.store = store
    app.state.approval_ledger = ledger

    def execute(scan_id: UUID, request: ScanRequest) -> None:
        requested = set(request.requested_modules)
        through: Literal["module1", "module2", "module3"] = (
            "module3"
            if "module3" in requested
            else "module2"
            if "module2" in requested
            else "module1"
        )
        try:
            bundle = pipeline.scan(
                request.repository_url,
                ref=request.ref,
                through=through,
                max_candidates=request.max_candidates,
            )
            store.complete(scan_id, bundle)
        except Exception as exc:
            store.fail(scan_id, type(exc).__name__.upper(), redact_secrets(str(exc)))

    @app.post("/v1/repositories/scan", status_code=status.HTTP_202_ACCEPTED)
    def start_scan(
        request: ScanRequest,
        background: BackgroundTasks,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        _: Annotated[Principal, Depends(require("Analyst", "SecurityReviewer", "TenantAdmin"))],
    ) -> dict[str, object]:
        record, created = store.create_scan(
            key=idempotency_key,
            source=request.repository_url,
            ref=request.ref,
            through=max(request.requested_modules),
        )
        if created:
            background.add_task(execute, record.scan_id, request)
        return {
            "job_id": record.scan_id,
            "state": record.state,
            "status_url": f"/v1/scans/{record.scan_id}",
            "idempotent_replay": not created,
        }

    @app.get("/v1/scans/{scan_id}")
    def get_scan(
        scan_id: UUID,
        _: Annotated[
            Principal,
            Depends(
                require(
                    "Viewer", "Analyst", "SecurityReviewer", "Approver", "Auditor", "TenantAdmin"
                )
            ),
        ],
    ) -> dict[str, object]:
        try:
            record = store.get_scan(scan_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        result: dict[str, object] = {
            "scan_id": scan_id,
            "state": record.state,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "error": (
                {"code": record.error_code, "message": record.error_message}
                if record.error_code
                else None
            ),
        }
        if record.bundle:
            result["snapshot_id"] = record.bundle.graph.snapshot.snapshot_id
            result["commit_sha"] = record.bundle.graph.snapshot.commit_sha
            result["coverage_warnings"] = record.bundle.graph.snapshot.warnings
        return result

    def bundle(scan_id: UUID):
        try:
            record = store.get_scan(scan_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if record.bundle is None:
            raise HTTPException(status_code=409, detail="scan output is not ready")
        return record.bundle

    @app.get("/v1/scans/{scan_id}/graph")
    def get_graph(
        scan_id: UUID,
        _: Annotated[
            Principal,
            Depends(require("Viewer", "Analyst", "SecurityReviewer", "Auditor", "TenantAdmin")),
        ],
    ) -> dict[str, object]:
        graph = bundle(scan_id).graph
        return {
            "snapshot": graph.snapshot,
            "assets": graph.assets,
            "edges": graph.edges,
            "unresolved": graph.unresolved,
            "digest": graph.digest,
        }

    @app.get("/v1/scans/{scan_id}/potential-vulnerabilities")
    def get_candidates(
        scan_id: UUID,
        _: Annotated[
            Principal,
            Depends(require("Viewer", "Analyst", "SecurityReviewer", "Auditor", "TenantAdmin")),
        ],
    ):
        return bundle(scan_id).candidates

    @app.get("/v1/scans/{scan_id}/findings")
    def get_findings(
        scan_id: UUID,
        _: Annotated[
            Principal,
            Depends(require("Viewer", "Analyst", "SecurityReviewer", "Auditor", "TenantAdmin")),
        ],
    ):
        return bundle(scan_id).findings

    @app.get("/v1/scans/{scan_id}/plans")
    def get_plan(
        scan_id: UUID,
        _: Annotated[
            Principal,
            Depends(require("Viewer", "SecurityReviewer", "Approver", "Auditor", "TenantAdmin")),
        ],
    ):
        value = bundle(scan_id)
        if value.planning is None:
            raise HTTPException(status_code=404, detail="no Module III plan exists")
        return {"planning": value.planning, "optimization": value.optimization}

    @app.post("/v1/scans/{scan_id}/proposals/{proposal_id}/decisions")
    def decide(
        scan_id: UUID,
        proposal_id: UUID,
        request: DecisionRequest,
        response: Response,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        actor: Annotated[Principal, Depends(require("Approver"))],
    ):
        del idempotency_key
        value = bundle(scan_id)
        if value.planning is None:
            raise HTTPException(status_code=404, detail="no plan exists")
        proposal = next(
            (item for item in value.planning.remediations if item.proposal_id == proposal_id),
            None,
        )
        if proposal is None:
            raise HTTPException(status_code=404, detail="proposal not found")
        if proposal.version != request.proposal_version:
            raise HTTPException(status_code=409, detail="proposal version is stale")
        try:
            event = ledger.record(
                proposal=proposal,
                proposal_sha256=request.proposal_sha256,
                actor_id=actor.actor_id,
                actor_role=actor.role,
                decision=request.decision,
                scope=request.scope,
                reason=request.comment,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        store.approvals.append(event)
        response.headers["ETag"] = proposal_digest(proposal)
        return event

    @app.get("/v1/audit-events")
    def audit(
        _: Annotated[Principal, Depends(require("Auditor", "TenantAdmin"))],
    ):
        return tuple(store.approvals)

    @app.get("/v1/knowledge-graph")
    def knowledge_graph_summary(
        _: Annotated[
            Principal,
            Depends(require("Viewer", "Analyst", "SecurityReviewer", "Auditor", "TenantAdmin")),
        ],
    ) -> dict[str, object]:
        graph = pipeline.vulnerability_graph
        return {
            "kb_snapshot_id": graph.kb_snapshot_id,
            "version": graph.version,
            "graph_schema_version": graph.graph_schema_version,
            "parser_version": graph.parser_version,
            "digest": graph.digest,
            "source_manifest": graph.source_manifest,
            "statistics": graph.statistics,
        }

    @app.get("/v1/knowledge-graph/entities/{entity_id}")
    def knowledge_graph_entity(
        entity_id: str,
        _: Annotated[
            Principal,
            Depends(require("Viewer", "Analyst", "SecurityReviewer", "Auditor", "TenantAdmin")),
        ],
    ) -> dict[str, object]:
        index = KnowledgeGraphIndex(pipeline.vulnerability_graph)
        entity = index.entity(entity_id)
        if entity is None:
            raise HTTPException(status_code=404, detail="knowledge entity not found")
        return {"entity": entity, "relations": index.neighborhood(entity_id)}

    return app


app = create_app()
