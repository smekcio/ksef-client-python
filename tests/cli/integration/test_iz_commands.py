from __future__ import annotations

import json
from pathlib import Path

from ksef_client.cli import app
from ksef_client.cli.commands import iz_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode

_KSEF = "5265877635-20250826-0100001AF629-AF"
_IZ = "1111111111-IZ202607-65ED02180000-E7"


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_iz_generate_help(runner) -> None:
    result = runner.invoke(app, ["iz", "generate", "--help"])
    assert result.exit_code == 0


def test_iz_query_help(runner) -> None:
    result = runner.invoke(app, ["iz", "query", "--help"])
    assert result.exit_code == 0


def test_iz_generate_two_numbers(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_generate(**kwargs):
        seen.update(kwargs)
        return {"collectiveIdentifierNumber": _IZ}

    monkeypatch.setattr(iz_cmd, "generate_collective_identifier", _fake_generate)

    result = runner.invoke(
        app,
        [
            "--json",
            "iz",
            "generate",
            "--ksef-number",
            _KSEF,
            "--ksef-number",
            _KSEF,
            "--max-invoices",
            "2",
        ],
    )
    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["data"]["collectiveIdentifierNumber"] == _IZ
    assert seen["ksef_numbers"] == [_KSEF, _KSEF]
    assert seen["max_invoices"] == 2


def test_iz_generate_from_file(runner, monkeypatch, tmp_path: Path) -> None:
    numbers_file = tmp_path / "ksef.txt"
    numbers_file.write_text(f"{_KSEF}\n# comment\n\n", encoding="utf-8")
    seen: dict[str, object] = {}

    def _fake_generate(**kwargs):
        seen.update(kwargs)
        return {"collectiveIdentifierNumber": _IZ}

    monkeypatch.setattr(iz_cmd, "generate_collective_identifier", _fake_generate)

    result = runner.invoke(
        app,
        ["--json", "iz", "generate", "--from-file", str(numbers_file)],
    )
    assert result.exit_code == 0
    assert seen["from_file"] == str(numbers_file)


def test_iz_query_all(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_query(**kwargs):
        seen.update(kwargs)
        return {"count": 1, "items": [{"collectiveIdentifierNumber": _IZ}]}

    monkeypatch.setattr(iz_cmd, "query_collective_identifiers", _fake_query)

    result = runner.invoke(
        app,
        [
            "--json",
            "iz",
            "query",
            "--from",
            "2026-01-01",
            "--to",
            "2026-01-31",
            "--all",
            "--continuation-token",
            "resume-query",
        ],
    )
    assert result.exit_code == 0
    assert seen["fetch_all"] is True
    assert seen["date_from"] == "2026-01-01"
    assert seen["continuation_token"] == "resume-query"
    payload = _json_output(result.stdout)
    assert payload["data"]["count"] == 1


def test_iz_invoices_two_identifiers(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_list(**kwargs):
        seen.update(kwargs)
        return {"count": 2, "items": []}

    monkeypatch.setattr(iz_cmd, "list_collective_identifier_invoices", _fake_list)

    result = runner.invoke(
        app,
        [
            "--json",
            "iz",
            "invoices",
            "--iz",
            _IZ,
            "--iz",
            _IZ,
            "--continuation-token",
            "resume-invoices",
        ],
    )
    assert result.exit_code == 0
    assert seen["iz_numbers"] == [_IZ, _IZ]
    assert seen["continuation_token"] == "resume-invoices"


def test_iz_by_ksef(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_list(**kwargs):
        seen.update(kwargs)
        return {"count": 0, "items": []}

    monkeypatch.setattr(iz_cmd, "list_collective_identifiers_by_ksef_number", _fake_list)

    result = runner.invoke(
        app,
        [
            "--json",
            "iz",
            "by-ksef",
            "--ksef-number",
            _KSEF,
            "--continuation-token",
            "resume-by-ksef",
        ],
    )
    assert result.exit_code == 0
    assert seen["ksef_number"] == _KSEF
    assert seen["continuation_token"] == "resume-by-ksef"


def test_iz_generate_maps_validation_error(runner, monkeypatch) -> None:
    def _raise(**kwargs):
        raise CliError(
            "No KSeF numbers provided.",
            ExitCode.VALIDATION_ERROR,
            "Pass --ksef-number and/or --from-file.",
        )

    monkeypatch.setattr(iz_cmd, "generate_collective_identifier", _raise)
    result = runner.invoke(app, ["--json", "iz", "generate"])
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)


def test_iz_query_maps_validation_error(runner, monkeypatch) -> None:
    def _raise(**kwargs):
        raise CliError("bad range", ExitCode.VALIDATION_ERROR, "fix dates")

    monkeypatch.setattr(iz_cmd, "query_collective_identifiers", _raise)
    result = runner.invoke(
        app,
        ["--json", "iz", "query", "--from", "2026-01-01", "--to", "2026-01-31"],
    )
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)


def test_iz_invoices_maps_validation_error(runner, monkeypatch) -> None:
    def _raise(**kwargs):
        raise CliError("bad iz", ExitCode.VALIDATION_ERROR, "fix iz")

    monkeypatch.setattr(iz_cmd, "list_collective_identifier_invoices", _raise)
    result = runner.invoke(app, ["--json", "iz", "invoices", "--iz", _IZ])
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)


def test_iz_by_ksef_maps_validation_error(runner, monkeypatch) -> None:
    def _raise(**kwargs):
        raise CliError("bad ksef", ExitCode.VALIDATION_ERROR, "fix number")

    monkeypatch.setattr(iz_cmd, "list_collective_identifiers_by_ksef_number", _raise)
    result = runner.invoke(app, ["--json", "iz", "by-ksef", "--ksef-number", _KSEF])
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)


def test_iz_invoices_help(runner) -> None:
    result = runner.invoke(app, ["iz", "invoices", "--help"])
    assert result.exit_code == 0


def test_iz_by_ksef_help(runner) -> None:
    result = runner.invoke(app, ["iz", "by-ksef", "--help"])
    assert result.exit_code == 0
