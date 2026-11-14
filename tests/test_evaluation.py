import pytest

from sentinel.evaluation.owasp import load_labels, native_predictions, score


def test_confusion_matrix_and_undefined_precision():
    labels = [
        {"case_id": f"BenchmarkTest{i:05}", "category": "sqli", "cwe": "CWE-89", "vulnerable": i < 3}
        for i in range(1, 5)
    ]
    predictions = {
        row["case_id"]: {
            "reported_cwes": ["CWE-89"] if i % 2 == 0 else [],
            "abstained": False,
            "reason": "test",
        }
        for i, row in enumerate(labels)
    }
    result = score(labels, predictions)["overall"]
    assert (
        result["true_positives"],
        result["false_positives"],
        result["false_negatives"],
        result["true_negatives"],
    ) == (1, 1, 1, 1)
    assert result["precision"] == result["recall"] == result["f1"] == 0.5
    abstentions = native_predictions([row["case_id"] for row in labels], [{"status": "hypothetical"}])
    result = score(labels, abstentions)["overall"]
    assert result["precision"] is None and result["recall"] == 0 and result["f1"] == 0
    assert result["abstentions"] == 4


def test_scoring_requires_exact_case_coverage():
    labels = [{"case_id": "BenchmarkTest00001", "category": "sqli", "cwe": "CWE-89", "vulnerable": True}]
    with pytest.raises(ValueError):
        score(labels, {})


def test_hypothetical_conditions_are_not_vulnerability_predictions():
    report = {"status": "hypothetical", "required_conditions": [{"mechanism_id": "CWE-89"}]}
    assert native_predictions(["BenchmarkTest00001"], [report])["BenchmarkTest00001"]["reported_cwes"] == []
    with pytest.raises(ValueError):
        native_predictions(["BenchmarkTest00001"], [{"status": "new-schema-needs-review"}])


def test_only_a_completed_dedicated_agent_review_counts_as_coverage():
    case = "BenchmarkTest00001"
    incomplete = native_predictions(
        [case], [], coverage=[{"analyzed_file": f"testcode/{case}.py", "status": "inconclusive"}]
    )
    assert incomplete[case]["abstained"] is True
    completed = native_predictions(
        [case],
        [],
        coverage=[{"analyzed_file": f"testcode/{case}.py", "status": "agent_analysis_completed"}],
    )
    assert completed[case]["abstained"] is False


def test_label_validation(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text("# header\nBenchmarkTest00001,sqli,true,89\n")
    assert load_labels(path)[0]["vulnerable"]
    path.write_text("BenchmarkTest00001,sqli,unknown,89\n")
    with pytest.raises(ValueError):
        load_labels(path)


def test_openrouter_uses_trusted_endpoint_and_explicit_model(monkeypatch):
    pytest.importorskip("langchain_openai")
    import langchain_openai

    from sentinel.agents.providers import build_model

    monkeypatch.setenv("SENTINEL_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "unit-test-placeholder-not-a-credential")
    monkeypatch.setenv("SENTINEL_MODEL", "nvidia/nemotron-3-ultra-550b-a55b:free")
    monkeypatch.setattr(langchain_openai, "ChatOpenAI", lambda **kwargs: kwargs)
    settings = build_model()
    assert settings["base_url"] == "https://openrouter.ai/api/v1"
    assert settings["model"].endswith(":free")
    assert settings["max_retries"] == 0 and settings["use_responses_api"] is False


def test_gemini_uses_native_api_and_configured_flash_model(monkeypatch):
    google = pytest.importorskip("langchain_google_genai")
    from sentinel.agents.providers import build_model

    monkeypatch.setenv("SENTINEL_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "unit-test-placeholder-not-a-credential")
    monkeypatch.setenv("SENTINEL_MODEL", "gemini-3.8-flash")
    monkeypatch.setattr(google, "ChatGoogleGenerativeAI", lambda **kwargs: kwargs)
    settings = build_model()
    assert settings["model"] == "gemini-3.8-flash"
    assert settings["vertexai"] is False
    assert settings["max_retries"] == 0
    assert settings["thinking_level"] == "low"
