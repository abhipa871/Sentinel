from __future__ import annotations

import base64
import os
import re
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import httpx


class GitHubAcquisitionError(RuntimeError):
    pass


@dataclass(frozen=True)
class AcquiredRepository:
    owner: str
    repository: str
    commit_sha: str
    local_root: Path
    warnings: tuple[str, ...] = ()


def parse_github_url(url: str) -> tuple[str, str]:
    # Shared links often carry tracking parameters (``?utm_source=...``) or fragments. Neither is
    # ever forwarded: acquisition rebuilds its own URLs from the validated owner/repository pair.
    # Scheme, host, and path remain strictly matched.
    canonical = re.split(r"[?#]", url, maxsplit=1)[0]
    match = re.fullmatch(
        r"https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?",
        canonical,
    )
    if not match:
        raise ValueError("only canonical public github.com repository URLs are accepted")
    return match.group("owner"), match.group("repo")


class PublicGitHubAcquirer:
    """Read-only GitHub API acquisition with a pinned commit and bounded blob cache."""

    def __init__(
        self,
        cache_root: Path,
        *,
        token: str | None = None,
        max_files: int = 20_000,
        max_total_bytes: int = 500_000_000,
        max_file_bytes: int = 5_000_000,
        timeout_seconds: int = 30,
    ) -> None:
        self.cache_root = cache_root
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_file_bytes = max_file_bytes
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "sentinel-defensive-analyzer",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.client = httpx.Client(headers=headers, timeout=timeout_seconds, follow_redirects=False)

    def __enter__(self) -> PublicGitHubAcquirer:
        return self

    def __exit__(self, *_: object) -> None:
        self.client.close()

    def acquire(self, url: str, ref: str = "HEAD") -> AcquiredRepository:
        owner, repo = parse_github_url(url)
        commit = self._get(f"/repos/{owner}/{repo}/commits/{ref}")
        commit_sha = str(commit["sha"])
        if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
            raise GitHubAcquisitionError("GitHub did not return a full commit SHA")
        tree_sha = str(commit["commit"]["tree"]["sha"])
        entries, truncated = self._tree(owner, repo, tree_sha)
        if truncated:
            entries = self._walk_trees(owner, repo, tree_sha)
        blobs = [
            entry
            for entry in entries
            if entry.get("type") == "blob"
            and entry.get("mode") != "120000"
            and self._safe_path(str(entry.get("path", "")))
        ]
        if len(blobs) > self.max_files:
            raise GitHubAcquisitionError("repository file count exceeds acquisition policy")
        destination = self.cache_root / owner / repo / commit_sha
        destination.mkdir(parents=True, exist_ok=True)
        total = 0
        for entry in blobs:
            size = int(entry.get("size") or 0)
            if size > self.max_file_bytes:
                continue
            total += size
            if total > self.max_total_bytes:
                raise GitHubAcquisitionError("repository byte size exceeds acquisition policy")
            blob = self._get(f"/repos/{owner}/{repo}/git/blobs/{entry['sha']}")
            if blob.get("encoding") != "base64":
                raise GitHubAcquisitionError("unsupported GitHub blob encoding")
            encoded = re.sub(r"\s+", "", str(blob["content"]))
            try:
                content = base64.b64decode(encoded, validate=True)
            except ValueError as exc:
                raise GitHubAcquisitionError("GitHub returned malformed base64 blob data") from exc
            if len(content) > self.max_file_bytes:
                continue
            target = destination / PurePosixPath(entry["path"])
            resolved = target.resolve()
            try:
                resolved.relative_to(destination.resolve())
            except ValueError as exc:
                raise GitHubAcquisitionError("GitHub tree path escapes snapshot") from exc
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_bytes(content)
        warnings = (
            ("recursive tree was truncated; bounded subtree traversal used",) if truncated else ()
        )
        return AcquiredRepository(owner, repo, commit_sha, destination, warnings)

    def _get(self, path: str) -> dict[str, Any]:
        response = self.client.get(f"https://api.github.com{path}")
        if response.status_code != 200:
            raise GitHubAcquisitionError(
                f"GitHub API returned {response.status_code} for a read operation"
            )
        return response.json()

    def _tree(self, owner: str, repo: str, sha: str) -> tuple[list[dict[str, Any]], bool]:
        data = self._get(f"/repos/{owner}/{repo}/git/trees/{sha}?recursive=1")
        return list(data.get("tree", [])), bool(data.get("truncated"))

    def _walk_trees(self, owner: str, repo: str, root_sha: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        stack: list[tuple[str, str]] = [("", root_sha)]
        while stack:
            prefix, sha = stack.pop()
            data = self._get(f"/repos/{owner}/{repo}/git/trees/{sha}")
            for item in data.get("tree", []):
                path = f"{prefix}/{item['path']}".lstrip("/")
                record = dict(item)
                record["path"] = path
                if item.get("type") == "tree":
                    stack.append((path, str(item["sha"])))
                else:
                    result.append(record)
                if len(result) > self.max_files:
                    raise GitHubAcquisitionError("repository file count exceeds acquisition policy")
        return result

    @staticmethod
    def _safe_path(value: str) -> bool:
        path = PurePosixPath(value)
        return bool(value) and not path.is_absolute() and ".." not in path.parts


class PinnedGitHubArchiveAcquirer:
    """Acquire a public repository archive at an immutable remotely resolved commit."""

    def __init__(
        self,
        cache_root: Path,
        *,
        max_files: int = 20_000,
        max_total_bytes: int = 500_000_000,
        max_file_bytes: int = 5_000_000,
        max_archive_bytes: int = 100_000_000,
        timeout_seconds: int = 120,
    ) -> None:
        self.cache_root = cache_root
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_file_bytes = max_file_bytes
        self.max_archive_bytes = max_archive_bytes
        self.timeout_seconds = timeout_seconds

    def acquire(self, url: str, ref: str = "HEAD") -> AcquiredRepository:
        owner, repo = parse_github_url(url)
        commit_sha = self._resolve_commit(owner, repo, ref)
        destination = self.cache_root / owner / repo / commit_sha
        destination.mkdir(parents=True, exist_ok=True)
        archive = destination.parent / f".{commit_sha}.tar.gz"
        self._download(owner, repo, commit_sha, archive)
        try:
            self._extract(archive, destination)
        finally:
            archive.unlink(missing_ok=True)
        return AcquiredRepository(
            owner=owner,
            repository=repo,
            commit_sha=commit_sha,
            local_root=destination,
            warnings=("repository acquired from a commit-pinned codeload archive",),
        )

    def _resolve_commit(self, owner: str, repo: str, ref: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", ref):
            raise GitHubAcquisitionError("Git reference is outside the accepted syntax")
        remote = f"https://github.com/{owner}/{repo}.git"
        patterns = (
            ("HEAD",)
            if ref == "HEAD"
            else (f"refs/heads/{ref}", f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}")
        )
        environment = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
        for pattern in patterns:
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=NUL",
                    "ls-remote",
                    "--exit-code",
                    remote,
                    pattern,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                env=environment,
            )
            if result.returncode == 0 and result.stdout:
                commit_sha = result.stdout.split()[0]
                if re.fullmatch(r"[0-9a-f]{40}", commit_sha):
                    return commit_sha
        raise GitHubAcquisitionError("could not resolve the requested public GitHub ref")

    def _download(self, owner: str, repo: str, commit_sha: str, target: Path) -> None:
        url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{commit_sha}"
        total = 0
        with httpx.stream(
            "GET",
            url,
            headers={"User-Agent": "sentinel-defensive-analyzer"},
            timeout=self.timeout_seconds,
            follow_redirects=False,
        ) as response:
            if response.status_code != 200:
                raise GitHubAcquisitionError(f"GitHub codeload returned {response.status_code}")
            with target.open("wb") as handle:
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > self.max_archive_bytes:
                        raise GitHubAcquisitionError(
                            "repository archive exceeds acquisition policy"
                        )
                    handle.write(chunk)

    def _extract(self, archive: Path, destination: Path) -> None:
        destination_root = destination.resolve()
        file_count = 0
        total_bytes = 0
        with tarfile.open(archive, mode="r:gz") as bundle:
            for member in bundle:
                if not member.isfile():
                    continue
                parts = PurePosixPath(member.name).parts
                if len(parts) < 2:
                    continue
                relative = PurePosixPath(*parts[1:])
                if not PublicGitHubAcquirer._safe_path(relative.as_posix()):
                    raise GitHubAcquisitionError("archive path escapes snapshot")
                file_count += 1
                if file_count > self.max_files:
                    raise GitHubAcquisitionError("repository file count exceeds acquisition policy")
                if member.size > self.max_file_bytes:
                    continue
                total_bytes += member.size
                if total_bytes > self.max_total_bytes:
                    raise GitHubAcquisitionError("repository byte size exceeds acquisition policy")
                target = (destination_root / relative).resolve()
                try:
                    target.relative_to(destination_root)
                except ValueError as exc:
                    raise GitHubAcquisitionError("archive path escapes snapshot") from exc
                source = bundle.extractfile(member)
                if source is None:
                    raise GitHubAcquisitionError("archive regular file could not be read")
                content = source.read(self.max_file_bytes + 1)
                if len(content) > self.max_file_bytes:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
