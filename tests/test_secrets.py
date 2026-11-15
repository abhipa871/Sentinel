from sentinel.secrets import redact_secrets


def test_provider_keys_are_redacted_from_errors():
    value = "provider rejected " + "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz012345"
    redacted = redact_secrets(value)
    assert "sk-proj" not in redacted
    assert "[REDACTED]" in redacted
