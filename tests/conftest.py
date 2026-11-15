from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.phase0 import RepositoryExtractor


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    (tmp_path / "api").mkdir()
    (tmp_path / "services").mkdir()
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (tmp_path / "api" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "services" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "api" / "routes.py").write_text(
        "from services.loader import load\n"
        "@app.post('/load')\n"
        "def upload(data):\n"
        "    return load(data)\n",
        encoding="utf-8",
    )
    (tmp_path / "services" / "loader.py").write_text(
        "import pickle\ndef load(data):\n    return pickle.loads(data)\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def sample_graph(sample_repo: Path):
    return RepositoryExtractor().extract(sample_repo)
