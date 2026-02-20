from __future__ import annotations

import json

from ksef_client.cli.app import app
from ksef_client.cli.commands import invoice_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_invoice_download_help(runner) -> None:
    result = runner.invoke(app, ["invoice", "download", "--help"])
    assert result.exit_code == 0


def test_invoice_download_success(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_download(**kwargs):
        seen.update(kwargs)
        return {
            "ksef_number": kwargs["ksef_number"],
            "path": "out.xml",
            "bytes": 10,
            "sha256_base64": "h",
        }

    monkeypatch.setattr(invoice_cmd, "download_invoice", _fake_download)

    result = runner.invoke(
        app,
        [
            "invoice",
            "download",
            "--ksef-number",
            "ABC123",
            "--out",
            "tmp/out.xml",
            "--as",
            "xml",
            "--overwrite",
        ],
    )

    assert result.exit_code == 0
    assert seen["ksef_number"] == "ABC123"
    assert seen["as_format"] == "xml"
    assert seen["overwrite"] is True


def test_invoice_download_json_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        invoice_cmd,
        "download_invoice",
        lambda **kwargs: {"ksef_number": "X", "path": "x.xml", "bytes": 1, "sha256_base64": ""},
    )

    result = runner.invoke(
        app,
        ["--json", "invoice", "download", "--ksef-number", "X", "--out", "x.xml"],
    )

    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "invoice.download"
    assert payload["data"]["ksef_number"] == "X"


def test_invoice_download_io_error_exit_code(runner, monkeypatch) -> None:
    def _raise_error(**kwargs):
        _ = kwargs
        raise CliError("exists", ExitCode.IO_ERROR, "use --overwrite")

    monkeypatch.setattr(invoice_cmd, "download_invoice", _raise_error)

    result = runner.invoke(app, ["invoice", "download", "--ksef-number", "X", "--out", "x.xml"])

    assert result.exit_code == int(ExitCode.IO_ERROR)
