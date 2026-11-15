from sentinel.cli import main


def test_cli_loads_local_env_before_model_and_preserves_existing_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    (tmp_path / ".env").write_text("OPENAI_API_KEY=test-file-key\n")
    observed = []

    def capture_runtime(model):
        import os

        observed.append(os.environ["OPENAI_API_KEY"])
        raise RuntimeError("stop before network")

    import pytest

    monkeypatch.setattr("sentinel.cli.DeepAgentsRuntime", capture_runtime)
    with pytest.raises(RuntimeError, match="stop before network"):
        main(["scan", ".", "--model", "openai:test-model"])
    monkeypatch.setenv("OPENAI_API_KEY", "test-shell-key")
    with pytest.raises(RuntimeError, match="stop before network"):
        main(["scan", ".", "--model", "openai:test-model"])
    assert observed == ["test-file-key", "test-shell-key"]
