from __future__ import annotations

import json

from ksef_client.cli.app import app
from ksef_client.cli.commands import invoice_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_invoice_list_help(runner) -> None:
    result = runner.invoke(app, ["invoice", "list", "--help"])
    assert result.exit_code == 0


def test_invoice_list_success(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_list(**kwargs):
        seen.update(kwargs)
        return {
            "count": 1,
            "items": [{"ksefReferenceNumber": "KSEF/2026/01/0001"}],
            "continuation_token": "",
            "from": "2026-01-01T00:00:00Z",
            "to": "2026-01-31T23:59:59Z",
        }

    monkeypatch.setattr(invoice_cmd, "list_invoices", _fake_list)

    result = runner.invoke(
        app,
        [
            "invoice",
            "list",
            "--from",
            "2026-01-01",
            "--to",
            "2026-01-31",
            "--subject-type",
            "Subject2",
            "--date-type",
            "Issue",
            "--page-size",
            "5",
            "--page-offset",
            "10",
            "--sort-order",
            "Asc",
        ],
    )

    assert result.exit_code == 0
    assert seen["profile"] == "demo"
    assert seen["subject_type"] == "Subject2"
    assert seen["page_size"] == 5
    assert seen["page_offset"] == 10
    assert seen["sort_order"] == "Asc"
    assert "invoice.list" in result.stdout


def test_invoice_list_json_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        invoice_cmd,
        "list_invoices",
        lambda **kwargs: {"count": 0, "items": [], "continuation_token": "", "from": "", "to": ""},
    )

    result = runner.invoke(app, ["--json", "invoice", "list"])

    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "invoice.list"
    assert payload["profile"] == "demo"
    assert payload["data"]["count"] == 0


def test_invoice_list_validation_error_exit_code(runner, monkeypatch) -> None:
    def _raise_error(**kwargs):
        _ = kwargs
        raise CliError("bad input", ExitCode.VALIDATION_ERROR, "fix args")

    monkeypatch.setattr(invoice_cmd, "list_invoices", _raise_error)

    result = runner.invoke(app, ["invoice", "list"])

    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)


def test_invoice_list_json_validation_error_envelope(runner, monkeypatch) -> None:
    def _raise_error(**kwargs):
        _ = kwargs
        raise CliError("bad input", ExitCode.VALIDATION_ERROR, "fix args")

    monkeypatch.setattr(invoice_cmd, "list_invoices", _raise_error)

    result = runner.invoke(app, ["--json", "invoice", "list"])

    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
    payload = _json_output(result.stdout)
    assert payload["ok"] is False
    assert payload["command"] == "invoice.list"
    assert payload["profile"] == "demo"
    assert payload["data"] is None
    assert payload["errors"][0]["code"] == "VALIDATION_ERROR"
    assert payload["errors"][0]["message"] == "bad input"
    assert payload["errors"][0]["hint"] == "fix args"


def test_invoice_list_invalid_sort_order_is_rejected(runner) -> None:
    result = runner.invoke(app, ["invoice", "list", "--sort-order", "WRONG"])
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
