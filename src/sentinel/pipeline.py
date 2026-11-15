from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from sentinel.agentic_graph import AgenticRepositoryGraphBuilder
from sentinel.agents.runtime import SemanticRuntime
from sentinel.contracts import RepositoryAssetGraph, ScanBundle
from sentinel.github import PinnedGitHubArchiveAcquirer
from sentinel.knowledge import curated_mvp_knowledge
from sentinel.knowledge_graph import load_predefined_graph
from sentinel.module1 import AgenticModuleOne, ModuleOne
from sentinel.module2 import ModuleTwo
from sentinel.module3 import ModuleThree
from sentinel.phase0 import RepositoryExtractor


class SentinelPipeline:
    def __init__(
        self,
        *,
        runtime: SemanticRuntime | None = None,
        cache_root: Path | None = None,
        agent_cache_root: Path | None = None,
    ) -> None:
        self.runtime = runtime
        self.extractor = RepositoryExtractor()
        self.vulnerability_graph = load_predefined_graph()
        self.knowledge = curated_mvp_knowledge(self.vulnerability_graph)
        self.cache_root = cache_root or Path(".sentinel/snapshots")
        self.agent_cache_root = agent_cache_root or Path(".sentinel/agent-runs")

    def _agent_graph_checkpoint(self, observations: RepositoryAssetGraph) -> Path:
        model_id = str(getattr(self.runtime, "model", "unknown"))
        key = hashlib.sha256(
            # v2: agents cite exact short asset/evidence handles; v1 graphs were built from
            # error-prone 64-hex IDs and are not reused.
            f"agentic-graph-v2:{observations.digest}:{model_id}".encode()
        ).hexdigest()
        return self.agent_cache_root / key / "repository-graph.json"

    def _load_agent_graph_checkpoint(
        self, observations: RepositoryAssetGraph
    ) -> RepositoryAssetGraph | None:
        path = self._agent_graph_checkpoint(observations)
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1:
            return None
        if payload.get("observation_digest") != observations.digest:
            return None
        return RepositoryAssetGraph.model_validate(payload["graph"])

    def _save_agent_graph_checkpoint(
        self, observations: RepositoryAssetGraph, graph: RepositoryAssetGraph
    ) -> None:
        path = self._agent_graph_checkpoint(observations)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "observation_digest": observations.digest,
                    "model": str(getattr(self.runtime, "model", "unknown")),
                    "graph": graph.model_dump(mode="json"),
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        temporary.replace(path)

    def scan(
        self,
        source: str | Path,
        *,
        ref: str = "HEAD",
        through: Literal["module1", "module2", "module3"] = "module1",
        max_candidates: int = 500,
    ) -> ScanBundle:
        source_text = str(source)
        if source_text.startswith("https://github.com/"):
            acquired = PinnedGitHubArchiveAcquirer(self.cache_root).acquire(source_text, ref)
            observation_graph = self.extractor.extract(
                acquired.local_root,
                pinned_commit_sha=acquired.commit_sha,
                repository_identity=f"github:{acquired.owner}/{acquired.repository}",
                acquisition_mode="API_ONLY",
            )
        else:
            observation_graph = self.extractor.extract(source)
        if self.runtime is None:
            graph = observation_graph
        else:
            cached_graph = self._load_agent_graph_checkpoint(observation_graph)
            if cached_graph is None:
                graph = AgenticRepositoryGraphBuilder(self.runtime).run(observation_graph)
                self._save_agent_graph_checkpoint(observation_graph, graph)
            else:
                graph = cached_graph
        candidates = (
            AgenticModuleOne(self.runtime).run(
                graph,
                self.knowledge,
                self.vulnerability_graph,
                max_candidates=max_candidates,
            )
            if self.runtime is not None
            else ModuleOne().run(
                graph,
                self.knowledge,
                vulnerability_graph=self.vulnerability_graph,
                max_candidates=max_candidates,
            )
        )
        if through == "module1":
            return ScanBundle(graph=graph, candidates=candidates)
        if self.runtime is None:
            raise RuntimeError(
                "Module II and III require a configured LangChain Deep Agents runtime"
            )
        findings = ModuleTwo(self.runtime).run(candidates, graph)
        if through == "module2":
            return ScanBundle(graph=graph, candidates=candidates, findings=findings)
        planning, optimization = ModuleThree(self.runtime).run(findings, graph)
        return ScanBundle(
            graph=graph,
            candidates=candidates,
            findings=findings,
            planning=planning,
            optimization=optimization,
        )
