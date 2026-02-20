from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner


def _write_default_config(appdata_root: Path) -> None:
    config_path = appdata_root / "ksef-cli" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps(
            {
                "version": 1,
                "active_profile": "demo",
                "profiles": {
                    "demo": {
                        "env": "DEMO",
                        "base_url": "https://api-demo.ksef.mf.gov.pl",
                        "context_type": "nip",
                        "context_value": "123",
                    }
                },
            },
            ensure_ascii=True,
            indent=2,
        ),
        encoding="utf-8",
    )


@pytest.fixture
def runner(tmp_path, monkeypatch) -> CliRunner:
    appdata = tmp_path / "appdata"
    local_appdata = tmp_path / "localappdata"
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setenv("LOCALAPPDATA", str(local_appdata))
    _write_default_config(appdata)
    return CliRunner()
