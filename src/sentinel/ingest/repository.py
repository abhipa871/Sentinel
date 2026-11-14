"""Ingestion never imports, builds, installs, or executes repository code."""

import os
import re
import stat
from io import BytesIO
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from zipfile import BadZipFile, ZipFile

from sentinel.config import Limits
from sentinel.models.base import stable_id

from .file_index import SKIP_DIRS, Snapshot, allowed_file

DEFAULT_LIMITS = Limits()


def _is_link(path):
    return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)


class IngestionError(ValueError):
    pass


def _decode(data: bytes) -> str:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        raise IngestionError("Supported source files must be UTF-8") from None
    if "\0" in text:
        raise IngestionError("Binary content in a source file")
    return text


def local_snapshot(
    source: str, limits: Limits = DEFAULT_LIMITS, allowed_root: Path | None = None
) -> Snapshot:
    root = Path(source).resolve(strict=True)
    if allowed_root and not root.is_relative_to(allowed_root.resolve()):
        raise IngestionError("Source must be inside the authorized root")
    if root.is_file():
        if not allowed_file(root.name):
            raise IngestionError("Unsupported source file")
        if _is_link(root) or root.stat().st_size > limits.max_file_bytes:
            raise IngestionError("Source file is linked or exceeds the size limit")
        with root.open("rb") as handle:
            data = handle.read(limits.max_file_bytes + 1)
        if len(data) > limits.max_file_bytes:
            raise IngestionError("Source file size limit exceeded")
        return Snapshot.create(stable_id("file", str(root)), str(root), {root.name: _decode(data)})
    if not root.is_dir():
        raise IngestionError("Source must be a directory or supported source file")
    files, warnings, total, scanned = {}, [], 0, 0
    for parent, dirs, names in os.walk(root, followlinks=False):
        scanned += len(dirs) + len(names)
        if scanned > limits.max_files * 10:
            raise IngestionError("Directory traversal budget exceeded")
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in SKIP_DIRS
            and not _is_link(Path(parent) / d)
            and (Path(parent) / d).resolve().is_relative_to(root)
        )
        for name in sorted(names):
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            if not allowed_file(relative):
                continue
            if _is_link(path) or not path.resolve().is_relative_to(root) or not path.is_file():
                warnings.append(f"Skipped non-regular or linked file: {relative}")
                continue
            if path.stat().st_size > limits.max_file_bytes:
                raise IngestionError(f"File size limit exceeded: {relative}")
            with path.open("rb") as handle:
                data = handle.read(limits.max_file_bytes + 1)
            total += len(data)
            if (
                len(data) > limits.max_file_bytes
                or total > limits.max_total_bytes
                or len(files) >= limits.max_files
            ):
                raise IngestionError("Repository resource limit exceeded")
            files[relative] = _decode(data)
    return Snapshot.create(stable_id("repo", str(root)), str(root), files, warnings)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise IngestionError("Archive redirects are disabled")


def github_archive_url(source: str) -> str:
    parsed = urlsplit(source)
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment:
        raise IngestionError("Only public https://github.com/OWNER/REPO URLs are supported")
    match = re.fullmatch(r"/([A-Za-z0-9_-]+)/([A-Za-z0-9_.-]+)/?", parsed.path)
    if not match or match.group(2) in {".", ".."}:
        raise IngestionError("Expected a GitHub repository URL without credentials or a ref")
    owner, repo = match.groups()
    repo = repo.removesuffix(".git")
    return f"https://codeload.github.com/{owner}/{repo}/zip/HEAD"


def archive_snapshot(source: str, archive: bytes, limits: Limits = DEFAULT_LIMITS) -> Snapshot:
    if len(archive) > limits.max_archive_bytes:
        raise IngestionError("Archive size limit exceeded")
    files, total = {}, 0
    try:
        with ZipFile(BytesIO(archive)) as zipped:
            entries = zipped.infolist()
            if len(entries) > limits.max_files * 5:
                raise IngestionError("Archive entry limit exceeded")
            for entry in entries:
                name = entry.filename
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
                    raise IngestionError("Unsafe archive path")
                if stat.S_ISLNK(entry.external_attr >> 16):
                    raise IngestionError("Archive symlinks are not allowed")
                if entry.is_dir() or len(path.parts) < 2:
                    continue
                relative = PurePosixPath(*path.parts[1:]).as_posix()
                if not allowed_file(relative):
                    continue
                total += entry.file_size
                if (
                    entry.file_size > limits.max_file_bytes
                    or total > limits.max_total_bytes
                    or len(files) >= limits.max_files
                ):
                    raise IngestionError("Archive expansion limit exceeded")
                if relative in files:
                    raise IngestionError("Duplicate archive path")
                files[relative] = _decode(zipped.read(entry))
    except BadZipFile:
        raise IngestionError("Invalid repository archive") from None
    return Snapshot.create(stable_id("repo", source), source, files)


def ingest(
    source: str, *, authorized: bool, limits: Limits = DEFAULT_LIMITS, allowed_root: Path | None = None
) -> Snapshot:
    if not authorized:
        raise IngestionError("Operator authorization is required")
    if "://" not in source:
        return local_snapshot(source, limits, allowed_root)
    url = github_archive_url(source)
    # Fixed HTTPS host, no credentials, no inherited proxy, no redirects, bounded body.
    opener = build_opener(NoRedirect(), ProxyHandler({}))
    with opener.open(Request(url, headers={"User-Agent": "Sentinel-ReadOnly/0.1"}), timeout=20) as response:
        archive = response.read(limits.max_archive_bytes + 1)
    return archive_snapshot(source, archive, limits)
