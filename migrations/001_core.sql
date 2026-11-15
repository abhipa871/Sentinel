-- SENTINEL PostgreSQL 16 core. Tenant-owned rows carry tenant_id for direct RLS.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE tenants (
  tenant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE repositories (
  tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
  repo_id UUID NOT NULL,
  provider TEXT NOT NULL,
  provider_repository_id TEXT,
  canonical_url TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, repo_id)
);

CREATE TABLE repository_snapshots (
  tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
  snapshot_id UUID NOT NULL,
  repo_id UUID NOT NULL,
  commit_sha CHAR(40) NOT NULL,
  ref_requested TEXT,
  graph_schema_version INT NOT NULL,
  acquisition_mode TEXT NOT NULL,
  status TEXT NOT NULL,
  artifact_uri TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, snapshot_id),
  FOREIGN KEY (tenant_id, repo_id) REFERENCES repositories(tenant_id, repo_id),
  UNIQUE (tenant_id, repo_id, commit_sha, graph_schema_version)
);

CREATE TABLE assets (
  tenant_id UUID NOT NULL,
  snapshot_id UUID NOT NULL,
  asset_id TEXT NOT NULL,
  path TEXT NOT NULL,
  node_type TEXT NOT NULL,
  language TEXT,
  content_sha256 CHAR(64) NOT NULL,
  parser_status TEXT NOT NULL,
  features JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (tenant_id, snapshot_id, asset_id),
  UNIQUE (tenant_id, snapshot_id, path),
  FOREIGN KEY (tenant_id, snapshot_id)
    REFERENCES repository_snapshots(tenant_id, snapshot_id)
);

CREATE TABLE asset_edges (
  tenant_id UUID NOT NULL,
  snapshot_id UUID NOT NULL,
  edge_id TEXT NOT NULL,
  src_asset_id TEXT NOT NULL,
  dst_asset_id TEXT NOT NULL,
  edge_type TEXT NOT NULL,
  confidence TEXT NOT NULL,
  resolution_method TEXT NOT NULL,
  evidence JSONB NOT NULL,
  PRIMARY KEY (tenant_id, snapshot_id, edge_id),
  FOREIGN KEY (tenant_id, snapshot_id, src_asset_id)
    REFERENCES assets(tenant_id, snapshot_id, asset_id),
  FOREIGN KEY (tenant_id, snapshot_id, dst_asset_id)
    REFERENCES assets(tenant_id, snapshot_id, asset_id)
);
CREATE INDEX asset_edges_src ON asset_edges(tenant_id, snapshot_id, src_asset_id, edge_type);
CREATE INDEX asset_edges_dst ON asset_edges(tenant_id, snapshot_id, dst_asset_id, edge_type);

CREATE TABLE kb_snapshots (
  kb_snapshot_id UUID PRIMARY KEY,
  version TEXT NOT NULL,
  source_manifest JSONB NOT NULL,
  immutable_sha256 CHAR(64) NOT NULL,
  promoted_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE asset_weakness_rules (
  kb_snapshot_id UUID NOT NULL REFERENCES kb_snapshots(kb_snapshot_id),
  rule_id TEXT NOT NULL,
  rule_version INT NOT NULL,
  vulnerability_id TEXT NOT NULL,
  rule_json JSONB NOT NULL,
  derivation_kind TEXT NOT NULL,
  source_refs JSONB NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (kb_snapshot_id, rule_id, rule_version)
);

CREATE TABLE potential_vulnerabilities (
  tenant_id UUID NOT NULL,
  candidate_id TEXT NOT NULL,
  snapshot_id UUID NOT NULL,
  kb_snapshot_id UUID NOT NULL REFERENCES kb_snapshots(kb_snapshot_id),
  asset_id TEXT NOT NULL,
  vulnerability_id TEXT NOT NULL,
  hypothesis TEXT NOT NULL,
  investigation_priority NUMERIC NOT NULL,
  priority_features JSONB NOT NULL,
  status TEXT NOT NULL CHECK (status = 'potential'),
  evidence_refs JSONB NOT NULL,
  PRIMARY KEY (tenant_id, candidate_id),
  FOREIGN KEY (tenant_id, snapshot_id, asset_id)
    REFERENCES assets(tenant_id, snapshot_id, asset_id)
);

CREATE TABLE evidence_artifacts (
  tenant_id UUID NOT NULL,
  evidence_id UUID NOT NULL,
  snapshot_id UUID NOT NULL,
  producer TEXT NOT NULL,
  producer_version TEXT,
  source_path TEXT,
  source_range JSONB,
  content_sha256 CHAR(64) NOT NULL,
  object_uri TEXT,
  assertion_origin TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, evidence_id),
  FOREIGN KEY (tenant_id, snapshot_id)
    REFERENCES repository_snapshots(tenant_id, snapshot_id)
);

CREATE TABLE detected_findings (
  tenant_id UUID NOT NULL,
  finding_id UUID NOT NULL,
  snapshot_id UUID NOT NULL,
  primary_asset_id TEXT NOT NULL,
  vulnerability_id TEXT NOT NULL,
  verification_status TEXT NOT NULL,
  criticality TEXT NOT NULL,
  criticality_basis TEXT NOT NULL,
  summary TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, finding_id),
  FOREIGN KEY (tenant_id, snapshot_id, primary_asset_id)
    REFERENCES assets(tenant_id, snapshot_id, asset_id)
);

CREATE TABLE remediation_proposals (
  tenant_id UUID NOT NULL,
  proposal_id UUID NOT NULL,
  version INT NOT NULL CHECK (version > 0),
  snapshot_id UUID NOT NULL,
  immutable_sha256 CHAR(64) NOT NULL,
  proposal_json JSONB NOT NULL,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, proposal_id, version),
  FOREIGN KEY (tenant_id, snapshot_id)
    REFERENCES repository_snapshots(tenant_id, snapshot_id)
);

CREATE TABLE approval_events (
  tenant_id UUID NOT NULL,
  approval_event_id UUID NOT NULL,
  proposal_id UUID NOT NULL,
  proposal_version INT NOT NULL,
  actor_id UUID NOT NULL,
  actor_role TEXT NOT NULL,
  decision TEXT NOT NULL,
  scope_json JSONB,
  reason TEXT,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, approval_event_id),
  FOREIGN KEY (tenant_id, proposal_id, proposal_version)
    REFERENCES remediation_proposals(tenant_id, proposal_id, version)
);

CREATE TABLE audit_events (
  tenant_id UUID NOT NULL,
  id UUID NOT NULL,
  event_type TEXT NOT NULL,
  actor_id UUID,
  resource_ref TEXT NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  payload_hash CHAR(64) NOT NULL,
  payload_uri TEXT,
  PRIMARY KEY (tenant_id, id)
);

ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE repository_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE potential_vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE detected_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

