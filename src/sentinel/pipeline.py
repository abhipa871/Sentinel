from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Literal

from sentinel.agentic_graph import AgenticRepositoryGraphBuilder
from sentinel.agents.runtime import SemanticRuntime
from sentinel.config import get_settings
from sentinel.contracts import CoverageChecklistItem, RepositoryAssetGraph, ScanBundle
from sentinel.github import PinnedGitHubArchiveAcquirer
from sentinel.knowledge import curated_mvp_knowledge
from sentinel.knowledge_graph import load_predefined_graph
from sentinel.module1 import AgenticModuleOne, ModuleOne
from sentinel.module2 import ModuleTwo
from sentinel.module3 import ModuleThree
from sentinel.partitions import partition_assets
from sentinel.phase0 import RepositoryExtractor
from sentinel.profiles import ScanProfile, get_profile
from sentinel.telemetry import RunTelemetry, collecting


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

    def _agent_graph_checkpoint(
        self, observations: RepositoryAssetGraph, profile: ScanProfile | None = None
    ) -> Path:
        model_id = str(getattr(self.runtime, "model", "unknown"))
        effort = getattr(self.runtime, "reasoning_effort", "auto")
        if effort != "auto":
            model_id = f"{model_id}|reasoning_effort={effort}"
        # v5: keyed by the profile fields that affect the graph, so a discovery-budget change
        # builds a fresh graph while Module II budgets and concurrency do not.
        profile_key = json.dumps(profile.discovery_identity() if profile else None, sort_keys=True)
        key = hashlib.sha256(
            f"agentic-graph-v5:{observations.digest}:{model_id}:{profile_key}".encode()
        ).hexdigest()
        return self.agent_cache_root / key / "repository-graph.json"

    def _load_agent_graph_checkpoint(
        self, observations: RepositoryAssetGraph, profile: ScanProfile | None = None
    ) -> RepositoryAssetGraph | None:
        path = self._agent_graph_checkpoint(observations, profile)
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1:
            return None
        if payload.get("observation_digest") != observations.digest:
            return None
        return RepositoryAssetGraph.model_validate(payload["graph"])

    def _save_agent_graph_checkpoint(
        self,
        observations: RepositoryAssetGraph,
        graph: RepositoryAssetGraph,
        profile: ScanProfile | None = None,
    ) -> None:
        path = self._agent_graph_checkpoint(observations, profile)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "observation_digest": observations.digest,
                    "model": str(getattr(self.runtime, "model", "unknown")),
                    # Provenance: the profile this graph was actually built with.
                    "built_with_profile": asdict(profile) if profile else None,
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
        max_candidates: int | None = None,
        profile: ScanProfile | str | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> ScanBundle:
        """Run the immutable pipeline. `max_candidates` defaults to the profile's budget.

        Per-stage usage and run events are recorded on the returned bundle; `progress`, when
        given, receives one human-readable line per stage and event as they happen.
        """
        telemetry = RunTelemetry(progress)
        with collecting(telemetry):
            bundle = self._scan(
                source,
                ref=ref,
                through=through,
                max_candidates=max_candidates,
                profile=profile,
            )
        metrics, events = telemetry.snapshot()
        return bundle.model_copy(update={"run_metrics": metrics, "run_events": events})

    def _scan(
        self,
        source: str | Path,
        *,
        ref: str,
        through: Literal["module1", "module2", "module3"],
        max_candidates: int | None,
        profile: ScanProfile | str | None,
    ) -> ScanBundle:
        selected = get_profile(
            profile
            if profile is not None
            else getattr(self.runtime, "profile", None) or get_settings().default_scan_profile
        )
        budget = max_candidates if max_candidates is not None else selected.max_candidates
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
        partitions = (
            partition_assets(observation_graph, max_hints=selected.partition_max_hints)
            if selected.partitioned
            else None
        )
        coverage: tuple[CoverageChecklistItem, ...] = ()
        if self.runtime is None:
            graph = observation_graph
            candidates = ModuleOne().run(
                graph,
                self.knowledge,
                vulnerability_graph=self.vulnerability_graph,
                max_candidates=budget,
                graph_depth=selected.graph_hop_depth,
            )
        else:
            cached_graph = self._load_agent_graph_checkpoint(observation_graph, selected)
            if cached_graph is None:
                graph = AgenticRepositoryGraphBuilder(self.runtime).run(
                    observation_graph, partitions=partitions, profile=selected
                )
                self._save_agent_graph_checkpoint(observation_graph, graph, selected)
            else:
                graph = cached_graph
            module_one = AgenticModuleOne(self.runtime)
            candidates = module_one.run(
                graph,
                self.knowledge,
                self.vulnerability_graph,
                max_candidates=budget,
                partitions=partitions,
                profile=selected,
            )
            coverage = module_one.coverage_checklist
        bundle = ScanBundle(
            graph=graph,
            candidates=candidates,
            scan_profile=selected.name,
            module1_coverage=coverage,
        )
        if through == "module1":
            return bundle
        if self.runtime is None:
            raise RuntimeError(
                "Module II and III require a configured LangChain Deep Agents runtime"
            )
        module_two = ModuleTwo(self.runtime)
        findings = module_two.run(candidates, graph, profile=selected)
        if module_two.cited_evidence:
            # Publish the source spans findings cite; Module III and consumers can resolve them.
            graph = graph.model_copy(
                update={"evidence": (*graph.evidence, *module_two.cited_evidence)}
            )
        bundle = bundle.model_copy(update={"graph": graph, "findings": findings})
        if through == "module2":
            return bundle
        planning, optimization = ModuleThree(self.runtime).run(findings, graph, profile=selected)
        return bundle.model_copy(update={"planning": planning, "optimization": optimization})
