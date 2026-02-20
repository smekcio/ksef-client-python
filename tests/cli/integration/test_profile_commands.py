from __future__ import annotations

import json

from ksef_client.cli.app import app
from ksef_client.cli.commands import profile_cmd
from ksef_client.cli.config import paths


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_profile_help(runner) -> None:
    result = runner.invoke(app, ["profile", "--help"])
    assert result.exit_code == 0


def test_profile_full_lifecycle(runner, monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    create = runner.invoke(
        app,
        [
            "--json",
            "profile",
            "create",
            "--name",
            "demo",
            "--env",
            "DEMO",
            "--context-type",
            "nip",
            "--context-value",
            "5265877635",
            "--set-active",
        ],
    )
    assert create.exit_code == 0
    create_payload = _json_output(create.stdout)
    assert create_payload["command"] == "profile.create"
    assert create_payload["data"]["active_profile"] == "demo"

    list_result = runner.invoke(app, ["--json", "profile", "list"])
    assert list_result.exit_code == 0
    list_payload = _json_output(list_result.stdout)
    assert list_payload["data"]["count"] == 1

    show = runner.invoke(app, ["--json", "profile", "show", "--name", "demo"])
    assert show.exit_code == 0
    show_payload = _json_output(show.stdout)
    assert show_payload["data"]["name"] == "demo"

    set_base = runner.invoke(
        app,
        [
            "--json",
            "profile",
            "set",
            "--name",
            "demo",
            "--key",
            "base_url",
            "--value",
            "https://demo.example",
        ],
    )
    assert set_base.exit_code == 0
    set_payload = _json_output(set_base.stdout)
    assert set_payload["data"]["base_url"] == "https://demo.example"

    create_second = runner.invoke(
        app,
        [
            "--json",
            "profile",
            "create",
            "--name",
            "test",
            "--env",
            "TEST",
            "--context-type",
            "nip",
            "--context-value",
            "123",
        ],
    )
    assert create_second.exit_code == 0

    use_second = runner.invoke(app, ["--json", "profile", "use", "--name", "test"])
    assert use_second.exit_code == 0
    use_payload = _json_output(use_second.stdout)
    assert use_payload["data"]["active_profile"] == "test"

    delete_second = runner.invoke(app, ["--json", "profile", "delete", "--name", "test"])
    assert delete_second.exit_code == 0
    delete_payload = _json_output(delete_second.stdout)
    assert delete_payload["data"]["deleted_profile"] == "test"


def test_profile_validation_errors(runner, monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    create = runner.invoke(
        app,
        [
            "profile",
            "create",
            "--name",
            "demo",
            "--env",
            "DEMO",
            "--context-type",
            "nip",
            "--context-value",
            "5265877635",
        ],
    )
    assert create.exit_code == 0

    duplicate = runner.invoke(
        app,
        [
            "profile",
            "create",
            "--name",
            "demo",
            "--env",
            "DEMO",
            "--context-type",
            "nip",
            "--context-value",
            "x",
        ],
    )
    assert duplicate.exit_code == 2

    invalid_key = runner.invoke(
        app,
        ["profile", "set", "--name", "demo", "--key", "unsupported", "--value", "x"],
    )
    assert invalid_key.exit_code == 2

    missing = runner.invoke(app, ["profile", "show", "--name", "missing"])
    assert missing.exit_code == 6


def test_profile_show_requires_name_or_active_profile(runner, monkeypatch, tmp_path) -> None:
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

    result = runner.invoke(app, ["profile", "show"])
    assert result.exit_code == 6
    assert "No active profile is configured." in result.output
    assert "Use --name" in result.output


def test_profile_command_error_paths(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        profile_cmd, "load_config", lambda: (_ for _ in ()).throw(RuntimeError("x"))
    )
    assert runner.invoke(app, ["profile", "list"]).exit_code == 6
    assert runner.invoke(app, ["profile", "use", "--name", "demo"]).exit_code == 6
    assert (
        runner.invoke(
            app, ["profile", "set", "--name", "demo", "--key", "env", "--value", "DEMO"]
        ).exit_code
        == 6
    )
    assert runner.invoke(app, ["profile", "delete", "--name", "demo"]).exit_code == 6
