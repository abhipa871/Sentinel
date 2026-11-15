"""Deterministic repository partitioning for per-component agent transactions.

A partition is a set of file assets, derived only from paths and file types (no semantics): each
asset belongs to the shallowest ancestor directory that holds a manifest or Dockerfile (a
service/component root), otherwise to its top-level directory. Partitions without any source file
are pooled into one supporting partition so configuration and deployment files are still reviewed.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass

from sentinel.contracts import AssetType, RepositoryAssetGraph

SUPPORTING_PARTITION = "(supporting)"
ROOT_PARTITION = "(root)"


@dataclass(frozen=True)
class Partition:
    partition_id: str
    asset_ids: frozenset[str]
    source_file_count: int

    def __contains__(self, asset_id: object) -> bool:
        return asset_id in self.asset_ids


def _component_roots(graph: RepositoryAssetGraph) -> set[str]:
    roots: set[str] = set()
    for asset in graph.assets:
        is_marker = asset.node_type is AssetType.MANIFEST_FILE or (
            asset.node_type is AssetType.INFRA_FILE and asset.language == "dockerfile"
        )
        directory = posixpath.dirname(asset.path)
        if is_marker and directory:
            roots.add(directory)
    return roots


def _partition_key(path: str, roots: set[str]) -> str:
    parts = path.split("/")[:-1]
    for depth in range(1, len(parts) + 1):
        candidate = "/".join(parts[:depth])
        if candidate in roots:
            return candidate
    return parts[0] if parts else ROOT_PARTITION


def _split(
    key: str,
    members: set[str],
    paths: dict[str, str],
    hints: dict[str, int],
    max_hints: int,
) -> list[tuple[str, set[str]]]:
    """Split an oversized component by its next path level, then pack siblings up to the cap.

    Files directly under `key` stay with the first bin. A group that alone exceeds the cap is
    split recursively; a single child directory that holds everything is descended into.
    """
    total = sum(hints.get(asset_id, 0) for asset_id in members)
    if total <= max_hints:
        return [(key, members)]
    prefix = f"{key}/"
    groups: dict[str, set[str]] = {}
    direct: set[str] = set()
    for asset_id in members:
        rest = paths[asset_id][len(prefix) :]
        if "/" in rest:
            groups.setdefault(f"{prefix}{rest.split('/', 1)[0]}", set()).add(asset_id)
        else:
            direct.add(asset_id)
    if not groups:
        return [(key, members)]  # nothing deeper to split on
    if len(groups) == 1 and not direct:
        ((child, only),) = groups.items()
        return _split(child, only, paths, hints, max_hints)
    pieces: list[tuple[str, set[str]]] = []
    for child in sorted(groups):
        pieces.extend(_split(child, groups[child], paths, hints, max_hints))
    bins: list[tuple[list[str], set[str], int]] = []
    pending: tuple[list[str], set[str], int] = ([key] if direct else [], set(direct), 0)
    pending = (pending[0], pending[1], sum(hints.get(asset_id, 0) for asset_id in direct))
    for label, piece in pieces:
        weight = sum(hints.get(asset_id, 0) for asset_id in piece)
        if pending[1] and pending[2] + weight > max_hints:
            bins.append(pending)
            pending = ([], set(), 0)
        pending = ([*pending[0], label], pending[1] | piece, pending[2] + weight)
    if pending[1]:
        bins.append(pending)
    result = []
    for labels, assets, _ in bins:
        names = [label[len(prefix) :] if label.startswith(prefix) else "." for label in labels]
        result.append((labels[0] if len(labels) == 1 else f"{key}/{{{','.join(names)}}}", assets))
    return result


def partition_assets(
    graph: RepositoryAssetGraph, *, max_hints: int | None = None
) -> tuple[Partition, ...]:
    """Partition by component root; components with more than `max_hints` parser hints are split
    by path (deterministically) so each agent transaction stays bounded."""
    roots = _component_roots(graph)
    members: dict[str, set[str]] = {}
    for asset in graph.assets:
        members.setdefault(_partition_key(asset.path, roots), set()).add(asset.asset_id)
    paths = {asset.asset_id: asset.path for asset in graph.assets}
    is_source = {asset.asset_id: asset.node_type is AssetType.SOURCE_FILE for asset in graph.assets}
    hints: dict[str, int] = {}
    for edge in graph.edges:
        hints[edge.source_asset_id] = hints.get(edge.source_asset_id, 0) + 1
    partitions: list[Partition] = []
    supporting: set[str] = set()
    for key in sorted(members):
        if not any(is_source[asset_id] for asset_id in members[key]):
            supporting |= members[key]
            continue
        pieces = (
            _split(key, members[key], paths, hints, max_hints)
            if max_hints and key != ROOT_PARTITION
            else [(key, members[key])]
        )
        for label, assets in pieces:
            partitions.append(
                Partition(label, frozenset(assets), sum(is_source[item] for item in assets))
            )
    if supporting:
        partitions.append(Partition(SUPPORTING_PARTITION, frozenset(supporting), 0))
    return tuple(partitions)


def whole_repository(graph: RepositoryAssetGraph) -> Partition:
    return Partition(
        "(repository)",
        frozenset(asset.asset_id for asset in graph.assets),
        sum(asset.node_type is AssetType.SOURCE_FILE for asset in graph.assets),
    )
