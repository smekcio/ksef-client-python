from __future__ import annotations

import json

from ksef_client.cli.output.json import JsonRenderer


def _lines(capsys) -> list[dict]:
    captured = capsys.readouterr().out.strip().splitlines()
    return [json.loads(line) for line in captured if line.strip()]


def test_json_renderer_info_success_error(capsys) -> None:
    renderer = JsonRenderer()
    renderer.info("ok", command="test")
    renderer.success(command="cmd", profile="demo", data={"x": 1}, message="done")
    renderer.error(command="cmd", profile="demo", code="E", message="boom", hint="fix")

    payloads = _lines(capsys)
    assert payloads[0]["ok"] is True
    assert payloads[0]["command"] == "test"
    assert payloads[0]["profile"] is None
    assert isinstance(payloads[0]["meta"]["duration_ms"], int)
    assert payloads[1]["profile"] == "demo"
    assert payloads[1]["data"]["message"] == "done"
    assert isinstance(payloads[1]["meta"]["duration_ms"], int)
    assert payloads[2]["ok"] is False
    assert payloads[2]["profile"] == "demo"
    assert payloads[2]["errors"][0]["hint"] == "fix"
    assert isinstance(payloads[2]["meta"]["duration_ms"], int)


def test_json_renderer_error_without_hint(capsys) -> None:
    renderer = JsonRenderer()
    renderer.error(command="cmd", profile="demo", code="E", message="boom")
    payload = _lines(capsys)[0]
    assert payload["ok"] is False
    assert payload["profile"] == "demo"
    assert "hint" not in payload["errors"][0]
    assert "timestamp" not in payload["meta"]
