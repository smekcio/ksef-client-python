from ksef_client.cli.app import app
from ksef_client.cli.commands import invoice_cmd
from ksef_client.cli.config import paths


def test_root_help_and_version(runner) -> None:
    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0

    version_result = runner.invoke(app, ["--version"])
    assert version_result.exit_code == 0


def test_help_includes_option_descriptions(runner) -> None:
    auth_help = runner.invoke(app, ["auth", "login-token", "--help"])
    assert auth_help.exit_code == 0
    assert "Fallback" in auth_help.output
    assert "KSEF_TOKEN" in auth_help.output

    send_help = runner.invoke(app, ["send", "online", "--help"])
    assert send_help.exit_code == 0
    assert "Save UPO to this path" in send_help.output


def test_profile_global_option_is_propagated_to_commands(runner, monkeypatch) -> None:
    captured: dict[str, str] = {}

    def _fake_list_invoices(**kwargs):
        captured["profile"] = kwargs["profile"]
        return {"count": 0, "items": []}

    _write_config_for_profile("team-a")
    monkeypatch.setattr(invoice_cmd, "list_invoices", _fake_list_invoices)
    result = runner.invoke(
        app, ["--profile", "team-a", "invoice", "list", "--base-url", "https://demo.example"]
    )
    assert result.exit_code == 0
    assert captured["profile"] == "team-a"


def test_profile_global_option_rejects_unknown_profile(runner, monkeypatch) -> None:
    _write_config_for_profile("demo")
    result = runner.invoke(app, ["--profile", "missing", "invoice", "list"])
    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_profile_required_command_fails_without_active_profile(
    runner, monkeypatch, tmp_path
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        """
{
  "version": 1,
  "active_profile": null,
  "profiles": {}
}
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    result = runner.invoke(app, ["invoice", "list"])
    assert result.exit_code == 6
    assert "No active profile is configured." in result.output
    assert "ksef init --set-active" in result.output


def test_base_url_prefers_cli_option_over_environment(runner, monkeypatch) -> None:
    captured: dict[str, str] = {}

    def _fake_list_invoices(**kwargs):
        captured["base_url"] = kwargs["base_url"]
        return {"count": 0, "items": []}

    _write_config_for_profile("demo")
    monkeypatch.setattr(invoice_cmd, "list_invoices", _fake_list_invoices)
    monkeypatch.setenv("KSEF_BASE_URL", "https://env.example")
    result = runner.invoke(
        app,
        ["invoice", "list", "--base-url", "https://cli.example"],
    )
    assert result.exit_code == 0
    assert captured["base_url"] == "https://cli.example"


def test_base_url_uses_environment_when_option_missing(runner, monkeypatch) -> None:
    captured: dict[str, str] = {}

    def _fake_list_invoices(**kwargs):
        captured["base_url"] = kwargs["base_url"]
        return {"count": 0, "items": []}

    _write_config_for_profile("demo")
    monkeypatch.setattr(invoice_cmd, "list_invoices", _fake_list_invoices)
    monkeypatch.setenv("KSEF_BASE_URL", "https://env.example")
    result = runner.invoke(app, ["invoice", "list"])
    assert result.exit_code == 0
    assert captured["base_url"] == "https://env.example"


def test_base_url_uses_profile_when_option_and_env_missing(runner, monkeypatch, tmp_path) -> None:
    captured: dict[str, str] = {}

    def _fake_list_invoices(**kwargs):
        captured["base_url"] = kwargs["base_url"]
        return {"count": 0, "items": []}

    monkeypatch.setattr(invoice_cmd, "list_invoices", _fake_list_invoices)
    monkeypatch.delenv("KSEF_BASE_URL", raising=False)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        """
{
  "version": 1,
  "active_profile": "demo",
  "profiles": {
    "demo": {
      "env": "DEMO",
      "base_url": "https://profile.example",
      "context_type": "nip",
      "context_value": "123"
    }
  }
}
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    result = runner.invoke(app, ["invoice", "list"])
    assert result.exit_code == 0
    assert captured["base_url"] == "https://profile.example"


def _write_config_for_profile(profile_name: str):
    config_path = paths.config_file()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        f"""
{{
  "version": 1,
  "active_profile": "{profile_name}",
  "profiles": {{
    "{profile_name}": {{
      "env": "DEMO",
      "base_url": "https://profile.example",
      "context_type": "nip",
      "context_value": "123"
    }}
  }}
}}
""".strip(),
        encoding="utf-8",
    )
    return config_path
