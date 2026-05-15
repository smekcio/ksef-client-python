from __future__ import annotations

import json
from datetime import date

import pytest

from ksef_client.cli import app
from ksef_client.cli.commands import fa3_cmd
from ksef_client.documents.fa3 import FA3BatchDraft, FA3InvoiceBuilder, FA3Party


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_fa3_template_command(runner, tmp_path) -> None:
    path = tmp_path / "fa3.xlsx"

    result = runner.invoke(app, ["--json", "fa3", "template", "--out", str(path), "--no-sample"])

    assert result.exit_code == 0
    assert path.exists()
    payload = _json_output(result.stdout)
    assert payload["command"] == "fa3.template"


def test_fa3_build_validate_and_inspect_json_draft(runner, tmp_path) -> None:
    builder = FA3InvoiceBuilder(
        invoice_number="FV/CLI/1",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("Usługa", quantity="1", unit_net_price="100")
    json_path = tmp_path / "draft.json"
    FA3BatchDraft((builder.build(),)).to_json(json_path)
    out_dir = tmp_path / "out"

    build = runner.invoke(
        app,
        ["--json", "fa3", "build", "--source", str(json_path), "--out", str(out_dir), "--xsd"],
    )
    inspect = runner.invoke(app, ["--json", "fa3", "inspect", "--source", str(json_path)])
    validate = runner.invoke(
        app,
        ["--json", "fa3", "validate", "--invoice", str(out_dir / "FV_CLI_1.xml")],
    )

    assert build.exit_code == 0
    assert inspect.exit_code == 0
    assert validate.exit_code == 0
    assert _json_output(inspect.stdout)["data"]["coverage_entries"] >= 5

    zip_path = tmp_path / "out.zip"
    build_zip = runner.invoke(
        app,
        [
            "--json",
            "fa3",
            "build",
            "--source",
            str(json_path),
            "--out",
            str(zip_path),
            "--zip",
        ],
    )
    import_report = tmp_path / "report.xlsx"
    import_result = runner.invoke(
        app,
        [
            "--json",
            "fa3",
            "import",
            "--source",
            str(json_path),
            "--report",
            str(import_report),
        ],
    )

    assert build_zip.exit_code == 0
    assert zip_path.exists()
    assert import_result.exit_code == 0
    assert _json_output(import_result.stdout)["command"] == "fa3.import"


def test_fa3_import_source_dispatches_by_suffix(monkeypatch, tmp_path) -> None:
    xlsx_path = tmp_path / "draft.xlsx"
    json_path = tmp_path / "draft.json"

    monkeypatch.setattr(
        fa3_cmd.FA3Importer,
        "from_xlsx",
        staticmethod(lambda path, *, mode: ("xlsx", path, mode)),
    )
    monkeypatch.setattr(
        fa3_cmd.FA3Importer,
        "from_json",
        staticmethod(lambda path, *, mode: ("json", path, mode)),
    )

    xlsx_result = fa3_cmd._import_source(str(xlsx_path), mode=fa3_cmd.ImportMode.VALIDATE_ONLY)
    json_result = fa3_cmd._import_source(str(json_path), mode=fa3_cmd.ImportMode.VALIDATE_ONLY)

    assert xlsx_result[0] == "xlsx"
    assert json_result[0] == "json"
    with pytest.raises(ValueError, match="Unsupported"):
        fa3_cmd._import_source(str(tmp_path / "draft.txt"), mode=fa3_cmd.ImportMode.VALIDATE_ONLY)


def test_fa3_commands_render_validation_errors(runner, monkeypatch, tmp_path) -> None:
    def fail(*_args, **_kwargs) -> None:
        raise ValueError("boom")

    monkeypatch.setattr(fa3_cmd.FA3Template, "create_xlsx", fail)
    template_result = runner.invoke(
        app,
        ["--json", "fa3", "template", "--out", str(tmp_path / "x.xlsx")],
    )
    assert template_result.exit_code == 2
    assert "VALIDATION_ERROR" in template_result.stdout

    build_result = runner.invoke(
        app,
        ["--json", "fa3", "build", "--source", str(tmp_path / "draft.txt"), "--out", str(tmp_path)],
    )
    validate_result = runner.invoke(
        app,
        ["--json", "fa3", "validate", "--invoice", str(tmp_path / "missing.xml")],
    )
    inspect_result = runner.invoke(
        app,
        ["--json", "fa3", "inspect", "--source", str(tmp_path / "draft.txt")],
    )

    assert build_result.exit_code == 2
    assert validate_result.exit_code == 2
    assert inspect_result.exit_code == 2


def test_fa3_import_and_build_validation_error_branches(runner, monkeypatch, tmp_path) -> None:
    def fail_import(*_args, **_kwargs) -> None:
        raise ValueError("bad import")

    monkeypatch.setattr(fa3_cmd, "_import_source", fail_import)
    import_result = runner.invoke(
        app,
        ["--json", "fa3", "import", "--source", str(tmp_path / "draft.json")],
    )
    assert import_result.exit_code == 2

    class InvalidResult:
        errors = ["bad row"]
        valid_drafts = ()

    monkeypatch.setattr(fa3_cmd, "_import_source", lambda *_args, **_kwargs: InvalidResult())
    build_result = runner.invoke(
        app,
        [
            "--json",
            "fa3",
            "build",
            "--source",
            str(tmp_path / "draft.json"),
            "--out",
            str(tmp_path / "out"),
        ],
    )
    assert build_result.exit_code == 2
