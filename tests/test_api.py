from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel.api import create_app
from sentinel.pipeline import SentinelPipeline
from sentinel.store import MemoryStore


def _headers(role: str = "Analyst") -> dict[str, str]:
    return {
        "X-Sentinel-Actor": str(uuid4()),
        "X-Sentinel-Role": role,
        "Idempotency-Key": str(uuid4()),
    }


def test_scan_api_is_idempotent_and_exposes_module_one(sample_repo):
    store = MemoryStore()
    app = create_app(pipeline=SentinelPipeline(), store=store)
    client = TestClient(app)
    headers = _headers()
    response = client.post(
        "/v1/repositories/scan",
        headers=headers,
        json={"repository_url": str(sample_repo), "requested_modules": ["phase0", "module1"]},
    )
    assert response.status_code == 202
    scan_id = response.json()["job_id"]
    replay = client.post(
        "/v1/repositories/scan",
        headers=headers,
        json={"repository_url": str(sample_repo), "requested_modules": ["phase0", "module1"]},
    )
    assert replay.json()["job_id"] == scan_id
    read_headers = {
        "X-Sentinel-Actor": headers["X-Sentinel-Actor"],
        "X-Sentinel-Role": "Viewer",
    }
    status = client.get(f"/v1/scans/{scan_id}", headers=read_headers)
    assert status.json()["state"] == "completed"
    candidates = client.get(f"/v1/scans/{scan_id}/potential-vulnerabilities", headers=read_headers)
    assert candidates.status_code == 200
    assert all(item["candidate_status"] == "potential" for item in candidates.json())


def test_api_enforces_roles(sample_repo):
    client = TestClient(create_app(pipeline=SentinelPipeline(), store=MemoryStore()))
    response = client.post(
        "/v1/repositories/scan",
        headers=_headers(role="Viewer"),
        json={"repository_url": str(sample_repo)},
    )
    assert response.status_code == 403


def test_api_exposes_versioned_knowledge_graph():
    pipeline = SentinelPipeline()
    client = TestClient(create_app(pipeline=pipeline, store=MemoryStore()))
    headers = {
        "X-Sentinel-Actor": str(uuid4()),
        "X-Sentinel-Role": "Viewer",
    }
    summary = client.get("/v1/knowledge-graph", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["statistics"]["entities_total"] >= 4_800
    entity = client.get("/v1/knowledge-graph/entities/CWE-89", headers=headers)
    assert entity.status_code == 200
    assert entity.json()["entity"]["entity_id"] == "CWE-89"
    assert entity.json()["relations"]
