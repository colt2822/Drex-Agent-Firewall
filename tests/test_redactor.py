"""Tests for secret redaction engine."""

from drex_agent_firewall.security.redactor import SecretRedactor


def test_redact_api_keys():
    redactor = SecretRedactor()
    raw = "Here is my key: sk-proj-1234567890123456789012345678901234567890 and aws AKIA1234567890ABCDEF"
    sanitized = redactor.redact_text(raw)
    assert "sk-proj-" not in sanitized
    assert "AKIA1234567890ABCDEF" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized


def test_redact_private_key():
    redactor = SecretRedactor()
    raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    sanitized = redactor.redact_text(raw)
    assert "MIIEowIBAAKCAQEA" not in sanitized
    assert "[REDACTED_PRIVATE_KEY]" in sanitized


def test_redact_url_credentials():
    redactor = SecretRedactor()
    url = "https://admin:supersecret@api.example.com/data"
    sanitized = redactor.redact_text(url)
    assert "supersecret" not in sanitized
    assert "admin:[REDACTED]@api.example.com" in sanitized


def test_sanitize_nested_dict():
    redactor = SecretRedactor()
    data = {
        "user": "test",
        "api_key": "secret_value_12345",
        "nested": {
            "password": "my_password_xyz",
            "normal": "safe_value",
        },
        "tokens": ["ghp_123456789012345678901234567890123456"],
    }
    sanitized = redactor.sanitize(data)
    assert sanitized["api_key"] == "[REDACTED_SECRET_VALUE]"
    assert sanitized["nested"]["password"] == "[REDACTED_SECRET_VALUE]"
    assert sanitized["nested"]["normal"] == "safe_value"
    assert "ghp_" not in sanitized["tokens"][0]


def test_custom_secret_registration():
    redactor = SecretRedactor()
    redactor.register_secret("my_custom_production_token_999")
    text = "Authorization header with my_custom_production_token_999 attached"
    sanitized = redactor.redact_text(text)
    assert "my_custom_production_token_999" not in sanitized
    assert "[REDACTED_CUSTOM_SECRET]" in sanitized
