from __future__ import annotations

from ksef_client.cli.config.schema import CliConfig, ProfileConfig
from ksef_client.cli.diagnostics import checks


def test_run_preflight_warn_when_profile_and_tokens_missing(monkeypatch) -> None:
    monkeypatch.setattr(checks, "load_config", lambda: CliConfig())
    monkeypatch.setattr(checks, "get_tokens", lambda profile: None)

    result = checks.run_preflight()
    assert result["status"] == "WARN"
    assert result["profile"] is None
    assert result["checks"][0]["message"] == "No active profile is configured."


def test_run_preflight_warn_when_selected_profile_missing(monkeypatch) -> None:
    monkeypatch.setattr(checks, "load_config", lambda: CliConfig(active_profile="demo"))
    monkeypatch.setattr(checks, "get_tokens", lambda profile: None)

    result = checks.run_preflight()
    assert result["status"] == "WARN"
    assert result["profile"] == "demo"
    assert result["checks"][0]["message"] == "Profile 'demo' is not configured."


def test_run_preflight_pass_when_profile_and_tokens_available(monkeypatch) -> None:
    monkeypatch.setattr(
        checks,
        "load_config",
        lambda: CliConfig(
            active_profile="demo",
            profiles={
                "demo": ProfileConfig(
                    name="demo",
                    env="DEMO",
                    base_url="https://profile.example",
                    context_type="nip",
                    context_value="123",
                )
            },
        ),
    )
    monkeypatch.setattr(checks, "get_tokens", lambda profile: ("acc", "ref"))

    result = checks.run_preflight()
    assert result["status"] == "PASS"
    assert result["profile"] == "demo"
    assert all(item["status"] == "PASS" for item in result["checks"])


def test_run_preflight_uses_explicit_profile_override(monkeypatch) -> None:
    monkeypatch.setattr(
        checks,
        "load_config",
        lambda: CliConfig(
            active_profile="other",
            profiles={
                "demo": ProfileConfig(
                    name="demo",
                    env="DEMO",
                    base_url="https://profile.example",
                    context_type="nip",
                    context_value="123",
                )
            },
        ),
    )
    monkeypatch.setattr(checks, "get_tokens", lambda profile: ("acc", "ref"))

    result = checks.run_preflight("  demo  ")
    assert result["status"] == "PASS"
    assert result["profile"] == "demo"
