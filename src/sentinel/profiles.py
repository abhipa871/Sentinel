"""Scan profiles (technical specification section 15.1).

Budgets are enforced by the runtime (a tool-call budget middleware on every agent), not by prompt
text. Values are initial ceilings to tune against measured repositories, not guarantees.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ProfileName = Literal["fast", "balanced", "deep"]


@dataclass(frozen=True)
class ScanProfile:
    name: ProfileName
    # Tool calls one Module I / graph specialist or synthesis transaction may execute.
    specialist_tool_calls: int
    # Tool and delegation calls for a Module II review or Module III planning supervisor.
    supervisor_tool_calls: int
    # Tool calls each Module II / III specialist subagent may execute per review.
    subagent_tool_calls: int
    # Final Module I candidates sent to Module II.
    max_candidates: int
    # Run the graph and Module I agents once per repository component instead of once overall.
    partitioned: bool
    # Module I candidates one partition may contribute.
    partition_candidate_cap: int
    # Graph hops used for deterministic lead context.
    graph_hop_depth: int
    # A partition with more parser edge hints than this is split by path.
    partition_max_hints: int = 300
    # Independent agent transactions run concurrently (they share no state). These change wall
    # time only, never results, so they are not part of any cache identity.
    partition_concurrency: int = 1
    review_concurrency: int = 1

    def discovery_identity(self) -> dict[str, object]:
        """Fields that can change graph and Module I outputs."""
        return {
            "specialist_tool_calls": self.specialist_tool_calls,
            "partitioned": self.partitioned,
            "partition_candidate_cap": self.partition_candidate_cap,
            "graph_hop_depth": self.graph_hop_depth,
            "partition_max_hints": self.partition_max_hints,
        }

    def review_identity(self) -> dict[str, object]:
        """Fields that can change Module II and III outputs."""
        return {
            "supervisor_tool_calls": self.supervisor_tool_calls,
            "subagent_tool_calls": self.subagent_tool_calls,
        }


PROFILES: dict[ProfileName, ScanProfile] = {
    "fast": ScanProfile(
        name="fast",
        specialist_tool_calls=8,
        supervisor_tool_calls=8,
        subagent_tool_calls=6,
        max_candidates=100,
        partitioned=False,
        partition_candidate_cap=100,
        graph_hop_depth=1,
    ),
    "balanced": ScanProfile(
        name="balanced",
        specialist_tool_calls=50,
        supervisor_tool_calls=50,
        subagent_tool_calls=50,
        max_candidates=500,
        partitioned=True,
        partition_candidate_cap=40,
        graph_hop_depth=2,
        partition_concurrency=8,
        review_concurrency=8,
    ),
    "deep": ScanProfile(
        name="deep",
        specialist_tool_calls=50,
        supervisor_tool_calls=50,
        subagent_tool_calls=50,
        max_candidates=2_000,
        partitioned=True,
        partition_candidate_cap=80,
        graph_hop_depth=3,
        partition_concurrency=8,
        review_concurrency=8,
    ),
}


def get_profile(name: str | ScanProfile | None) -> ScanProfile:
    if isinstance(name, ScanProfile):
        return name
    if name is None:
        return PROFILES["balanced"]
    if name not in PROFILES:
        raise ValueError(f"unknown scan profile {name!r}; expected one of {sorted(PROFILES)}")
    return PROFILES[name]  # type: ignore[index]
