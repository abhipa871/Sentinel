"""Local-only API. Run with uvicorn sentinel.api.main:app --host 127.0.0.1."""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from sentinel.models.base import Model
from sentinel.service import SentinelService


class CreateRun(Model):
    repo: str = Field(max_length=2048)
    authorized: bool
    outcome: Literal["unauthorized_refund", "sensitive_data_exposure", "unauthorized_agent_tool_action"] = (
        "unauthorized_refund"
    )
    allow_mock: bool = False
    use_agents: bool = True
    analysis_targets: list[str] | None = Field(default=None, max_length=64)


class ReanalyzeRun(Model):
    changed_files: list[str] = Field(default_factory=list, max_length=2000)


def create_app(service=None):
    @asynccontextmanager
    async def lifespan(application):
        if application.state.service is None:
            application.state.service = SentinelService(
                allowed_root=Path(os.environ.get("SENTINEL_REPO_ROOT", "."))
            )
        yield

    application = FastAPI(title="SENTINEL", version="0.1.0", lifespan=lifespan)
    application.state.service = service
    application.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"]
    )

    @application.middleware("http")
    async def local_only(request: Request, call_next):
        from starlette.responses import JSONResponse

        if request.client and request.client.host not in {"127.0.0.1", "::1", "testclient"}:
            return JSONResponse({"detail": "This API accepts loopback clients only"}, status_code=403)
        return await call_next(request)

    def call(action):
        try:
            return action(application.state.service)
        except FileNotFoundError:
            raise HTTPException(404, "Run or repository not found") from None
        except (ValueError, OSError, RuntimeError, ImportError):
            raise HTTPException(
                400, "Request rejected: check scope, IDs, limits, and provider configuration"
            ) from None

    @application.post("/runs", status_code=201)
    def create_run(body: CreateRun):
        return call(
            lambda svc: svc.analyze(
                body.repo,
                body.outcome,
                authorized=body.authorized,
                allow_mock=body.allow_mock,
                use_agents=body.use_agents,
                analysis_targets=body.analysis_targets,
            )
        )

    @application.get("/runs/{run_id}")
    def get_run(run_id: str):
        return call(lambda svc: svc.get_run(run_id))

    @application.get("/runs/{run_id}/graph/{kind}")
    def get_graph(run_id: str, kind: Literal["organization", "attack"]):
        return call(lambda svc: svc.artifact(run_id, kind + "_graph"))

    @application.get("/runs/{run_id}/scenarios")
    def get_scenarios(run_id: str):
        return call(lambda svc: svc.artifact(run_id, "scenarios"))

    @application.get("/runs/{run_id}/findings")
    def get_findings(run_id: str):
        return call(lambda svc: svc.artifact(run_id, "findings"))

    @application.get("/runs/{run_id}/workflows")
    def get_workflows(run_id: str):
        return call(lambda svc: svc.artifact(run_id, "compiled_workflows"))

    @application.post("/runs/{run_id}/reanalyze")
    def reanalyze(run_id: str, body: ReanalyzeRun):
        return call(lambda svc: svc.reanalyze(run_id, body.changed_files))

    return application


app = create_app()
