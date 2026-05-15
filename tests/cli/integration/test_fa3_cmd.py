from __future__ import annotations

import json
from datetime import date

from ksef_client.cli import app
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
