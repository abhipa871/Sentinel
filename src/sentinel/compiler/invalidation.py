"""SQLite cache with file dependencies; source text is never persisted."""

import json
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path

from sentinel.models.base import digest
from sentinel.runtime.policy import TOOL_VERSION

# Source analysis uses the host ``ast`` grammar (e.g. PEP 701 f-strings parse only on 3.12+),
# so a result cached under one interpreter must not be reused under another.
PARSER_VERSION = f"cpython-ast-{sys.version_info.major}.{sys.version_info.minor}"


def task_cache_key(task, context):
    return digest(
        {
            "tool": task.kind,
            "inputs": task.inputs,
            "files": {p: context.snapshot.hashes[p] for p in sorted(task.file_dependencies)},
            "graph_nodes": task.node_dependencies,
            "tool_version": TOOL_VERSION,
            "parser_version": PARSER_VERSION,
            "policy": context.policy_context,
        }
    )


class AnalysisCache:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, repository TEXT NOT NULL, task_id TEXT NOT NULL, files TEXT NOT NULL, result TEXT NOT NULL)"
            )

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=15)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def get(self, key):
        with self.connect() as db:
            row = db.execute("SELECT result FROM cache WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key, task, context, result):
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO cache VALUES (?, ?, ?, ?, ?)",
                (
                    key,
                    context.snapshot.repository_id,
                    task.id,
                    json.dumps(task.file_dependencies),
                    json.dumps(result),
                ),
            )

    def invalidate(self, repository_id, changed_files):
        invalidated = []
        with self.connect() as db:
            rows = db.execute(
                "SELECT key, task_id, files FROM cache WHERE repository=?", (repository_id,)
            ).fetchall()
            for key, task_id, files in rows:
                if set(json.loads(files)).intersection(changed_files):
                    db.execute("DELETE FROM cache WHERE key=?", (key,))
                    invalidated.append(task_id)
        return sorted(set(invalidated))
