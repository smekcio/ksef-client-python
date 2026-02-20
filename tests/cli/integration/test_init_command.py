from __future__ import annotations

import json

from ksef_client.cli.app import app
from ksef_client.cli.config import paths


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_init_help(runner) -> None:
    result = runner.invoke(app, ["init", "--help"])
    assert result.exit_code == 0


def test_init_non_interactive_creates_and_sets_profile(runner, monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    result = runner.invoke(
        app,
        [
            "--json",
            "init",
            "--name",
            "team-a",
            "--env",
            "DEMO",
            "--context-type",
            "nip",
            "--context-value",
            "123",
            "--non-interactive",
            "--set-active",
        ],
    )
    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "init"
    assert payload["profile"] == "team-a"
    assert payload["data"]["active_profile"] == "team-a"
    assert config_path.exists()


def test_init_interactive_prompts_for_missing_values(runner, monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    result = runner.invoke(
        app,
        ["--json", "init"],
        input="demo\nDEMO\nhttps://api-demo.ksef.mf.gov.pl\nnip\n5265877635\n",
    )
    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["profile"] == "demo"


def test_init_non_interactive_requires_context_fields(runner, monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(paths, "config_file", lambda: config_path)

    result = runner.invoke(
        app,
        [
            "init",
            "--name",
            "demo",
            "--env",
            "DEMO",
            "--non-interactive",
        ],
    )
    assert result.exit_code == 2
