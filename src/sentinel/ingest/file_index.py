from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import PurePosixPath

from sentinel.models.base import digest

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".sentinel",
    ".pytest_cache",
    "dist",
    "build",
}
SUFFIXES = {".py", ".json", ".yaml", ".yml", ".toml"}


def allowed_file(path: str) -> bool:
    p = PurePosixPath(path)
    if any(part in SKIP_DIRS for part in p.parts):
        return False
    name = p.name.lower()
    if any(word in name for word in ("secret", "credential", "private_key", "id_rsa", "token")):
        return False
    if name.startswith(".env"):
        return name in {".env.example", ".env.template"}
    return p.suffix.lower() in SUFFIXES or name == "requirements.txt"


@dataclass
class Snapshot:
    repository_id: str
    source: str
    files: dict[str, str]
    hashes: dict[str, str]
    commit: str
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def create(cls, repository_id, source, files, warnings=None):
        hashes = {p: sha256(s.encode()).hexdigest() for p, s in files.items()}
        return cls(repository_id, source, files, hashes, "snapshot:" + digest(hashes), warnings or [])
