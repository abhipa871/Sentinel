import base64

import pytest

from sentinel.github import PinnedGitHubArchiveAcquirer, PublicGitHubAcquirer, parse_github_url


def test_only_canonical_github_urls_are_accepted():
    assert parse_github_url("https://github.com/example/project") == ("example", "project")
    with pytest.raises(ValueError):
        parse_github_url("https://evil.example/example/project")
    with pytest.raises(ValueError):
        parse_github_url("file:///etc/passwd")


def test_tracking_query_and_fragment_are_dropped_but_host_stays_strict():
    assert parse_github_url("https://github.com/OWASP/crAPI?utm_source=chatgpt.com") == (
        "OWASP",
        "crAPI",
    )
    assert parse_github_url("https://github.com/OWASP/crAPI.git#readme") == ("OWASP", "crAPI")
    with pytest.raises(ValueError):
        parse_github_url("https://evil.example/?x=https://github.com/OWASP/crAPI")
    with pytest.raises(ValueError):
        parse_github_url("https://github.com.evil.example/OWASP/crAPI?utm_source=x")


def test_github_wrapped_base64_is_accepted(tmp_path, monkeypatch):
    content = b"hello\n"
    encoded = base64.b64encode(content).decode()
    wrapped = encoded[:4] + "\n" + encoded[4:]
    acquirer = PublicGitHubAcquirer(tmp_path)
    responses = {
        "/repos/example/project/commits/main": {
            "sha": "a" * 40,
            "commit": {"tree": {"sha": "b" * 40}},
        },
        f"/repos/example/project/git/trees/{'b' * 40}?recursive=1": {
            "tree": [
                {
                    "path": "README.md",
                    "mode": "100644",
                    "type": "blob",
                    "sha": "c" * 40,
                    "size": len(content),
                }
            ],
            "truncated": False,
        },
        f"/repos/example/project/git/blobs/{'c' * 40}": {
            "encoding": "base64",
            "content": wrapped,
        },
    }
    monkeypatch.setattr(acquirer, "_get", lambda path: responses[path])
    acquired = acquirer.acquire("https://github.com/example/project", "main")
    assert (acquired.local_root / "README.md").read_bytes() == content
    acquirer.client.close()


def test_archive_extraction_rejects_links_and_keeps_regular_files(tmp_path):
    import io
    import tarfile

    archive = tmp_path / "repo.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        regular = tarfile.TarInfo("repo-sha/src/app.py")
        payload = b"print('data only')\n"
        regular.size = len(payload)
        bundle.addfile(regular, io.BytesIO(payload))
        link = tarfile.TarInfo("repo-sha/escape")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        bundle.addfile(link)
    destination = tmp_path / "snapshot"
    destination.mkdir()
    PinnedGitHubArchiveAcquirer(tmp_path)._extract(archive, destination)
    assert (destination / "src" / "app.py").read_bytes() == payload
    assert not (destination / "escape").exists()
