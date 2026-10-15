from __future__ import annotations

import json

from ksef_client import models as m
from ksef_client.cli import app
from ksef_client.cli import session_store as store
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.services.sessions import OnlineSessionState


def _online_checkpoint(session_id: str) -> store.OnlineSessionCheckpoint:
    return store.OnlineSessionCheckpoint(
        id=session_id,
        profile="demo",
        base_url="https://api-demo.ksef.mf.gov.pl",
        stage="opened",
        session_state=OnlineSessionState(
            reference_number="SES-OK",
            form_code=m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA"),
            valid_until="2026-04-01T12:30:00Z",
            symmetric_key_base64="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            iv_base64="AgICAgICAgICAgICAgICAg==",
        ),
    )


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def _prepare_broken_directory() -> None:
    """Zapisuje jeden poprawny checkpoint i jeden z `"form_code": {}`."""
    store.save_checkpoint(_online_checkpoint("online-demo"))
    payload = _online_checkpoint("broken").to_dict()
    # Pusty `form_code` dawał `TypeError` z `FormCode.__init__` i wywracał całą listę.
    payload["session_state"]["form_code"] = {}
    directory = store._profile_dir("demo")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "broken.json").write_text(json.dumps(payload), encoding="utf-8")


def test_session_list_reports_a_broken_checkpoint_instead_of_failing(runner) -> None:
    """Uszkodzony checkpoint trafia do `unreadable`, a lista kończy się sukcesem."""
    _prepare_broken_directory()

    result = runner.invoke(app, ["--json", "session", "list"])

    assert result.exit_code == 0
    data = _json_output(result.stdout)["data"]
    assert data["count"] == 1
    assert [item["id"] for item in data["items"]] == ["online-demo"]
    assert data["unreadable"] == ["broken.json"]
    assert "broken.json" in data["warning"]


def test_session_show_reports_a_broken_checkpoint_as_config_error(runner) -> None:
    """`session show` na uszkodzonym pliku daje czytelny `CONFIG_ERROR`, nie `UNEXPECTED`."""
    _prepare_broken_directory()

    result = runner.invoke(app, ["--json", "session", "show", "--id", "broken"])

    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    payload = _json_output(result.stdout)
    assert payload["ok"] is False
    assert payload["errors"][0]["code"] == "CONFIG_ERROR"
    assert "broken.json" in payload["errors"][0]["message"]
    assert "FormCode" in payload["errors"][0]["hint"]
