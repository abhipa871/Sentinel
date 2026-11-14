"""Download fixed public benchmark revisions as data. Never run their code."""

import json
import stat
from io import BytesIO
from pathlib import Path, PurePosixPath
from urllib.request import Request, urlopen
from zipfile import ZipFile

PINS = {
    "owasp-python": ("OWASP-Benchmark/BenchmarkPython", "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"),
    "cve-bench": ("uiuc-kang-lab/cve-bench", "9fb3e068f260b00dd899ef87951b88e9c60061f1"),
}


def fetch(url, limit=10_000_000):
    with urlopen(Request(url, headers={"User-Agent": "Sentinel-Benchmark/0.1"}), timeout=45) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Benchmark download limit exceeded")
    return data


def main():
    base = Path(__file__).resolve().parents[1] / "benchmarks" / "vendor"
    base.mkdir(parents=True, exist_ok=True)
    for name, (repo, commit) in PINS.items():
        target = base / name / commit
        target.mkdir(parents=True, exist_ok=True)
        metadata = {"repository": "https://github.com/" + repo, "commit": commit, "directory": str(target)}
        if name == "owasp-python":
            archive = fetch(f"https://codeload.github.com/{repo}/zip/{commit}")
            total = 0
            with ZipFile(BytesIO(archive)) as zipped:
                if len(zipped.infolist()) > 30000:
                    raise ValueError("Archive entry limit exceeded")
                for entry in zipped.infolist():
                    path = PurePosixPath(entry.filename)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or "\\" in entry.filename
                        or ":" in entry.filename
                        or stat.S_ISLNK(entry.external_attr >> 16)
                    ):
                        raise ValueError("Unsafe archive path")
                    if entry.is_dir() or len(path.parts) < 2:
                        continue
                    total += entry.file_size
                    if total > 30_000_000 or entry.file_size > 2_000_000:
                        raise ValueError("Archive expansion limit exceeded")
                    output = target.joinpath(*path.parts[1:])
                    if not output.resolve().is_relative_to(target.resolve()):
                        raise ValueError("Path escaped benchmark directory")
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(zipped.read(entry))
            metadata.update(archive_bytes=len(archive), expanded_bytes=total)
        else:
            tree = json.loads(fetch(f"https://api.github.com/repos/{repo}/git/trees/{commit}?recursive=1"))
            (target / "repository_tree.json").write_text(json.dumps(tree, indent=2), encoding="utf-8")
            selected = ["README.md", "pyproject.toml", "src/cvebench/cvebench.py"]
            for relative in selected:
                output = target / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(
                    fetch(f"https://raw.githubusercontent.com/{repo}/{commit}/{relative}", 500000)
                )
            metadata.update(
                download_scope="preflight metadata and harness only; no vulnerable app containers",
                tree_truncated=tree.get("truncated"),
                paths=selected,
            )
        (base / (name + ".json")).write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        print(f"Prepared {name} at {commit}")


if __name__ == "__main__":
    main()
