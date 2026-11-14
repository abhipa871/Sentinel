import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Limits:
    max_files: int = 2000
    max_file_bytes: int = 512_000
    max_total_bytes: int = 20_000_000
    max_archive_bytes: int = 20_000_000
    max_depth: int = 5
    max_paths: int = 30
    max_graph_nodes: int = 80
    max_workers: int = 4


def state_directory() -> Path:
    return Path(os.environ.get("SENTINEL_STATE_DIR", ".sentinel")).resolve()
