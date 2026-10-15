"""`profile delete` musi posprzątać poświadczenia i checkpointy.

Wcześniej usuwał wyłącznie wpis w `config.json`: tokeny zostawały w keyringu
albo w `tokens.json`, a checkpointy w `sessions/<profil>/` — więc nowy profil o
tej samej nazwie dziedziczył ważny refresh token i sesje poprzednika.
"""

from __future__ import annotations

import json

from ksef_client.cli import app, session_store
from ksef_client.cli.auth import manager


def _payload(stdout: str) -> dict:
    return json.loads(stdout.strip())


def test_profile_delete_cleans_credentials_and_checkpoints(runner, monkeypatch) -> None:
    calls: list[str] = []

    def _logout(profile: str) -> dict[str, object]:
        calls.append(f"logout:{profile}")
        return {"profile": profile, "logged_out": True}

    def _delete_all(profile: str) -> int:
        calls.append(f"checkpoints:{profile}")
        return 2

    monkeypatch.setattr(manager, "logout", _logout)
    monkeypatch.setattr(session_store, "delete_all_checkpoints", _delete_all)

    result = runner.invoke(app, ["--json", "profile", "delete", "--name", "demo"])

    assert result.exit_code == 0
    assert "logout:demo" in calls
    assert "checkpoints:demo" in calls
    data = _payload(result.stdout)["data"]
    assert data["tokens_removed"] is True
    assert data["checkpoints_removed"] == 2


def test_profile_delete_keeps_credentials_with_the_flag(runner, monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(manager, "logout", lambda profile: calls.append(f"logout:{profile}"))

    result = runner.invoke(
        app, ["--json", "profile", "delete", "--name", "demo", "--keep-credentials"]
    )

    assert result.exit_code == 0
    assert calls == []
    data = _payload(result.stdout)["data"]
    assert data["tokens_removed"] is False
    assert data["checkpoints_removed"] == 0


def test_profile_delete_rejects_a_path_like_name(runner) -> None:
    result = runner.invoke(app, ["--json", "profile", "delete", "--name", "../evil"])

    assert result.exit_code != 0
    payload = _payload(result.stdout)
    assert payload["errors"][0]["code"] == "VALIDATION_ERROR"
