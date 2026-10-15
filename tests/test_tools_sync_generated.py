from __future__ import annotations

from pathlib import Path

import pytest
from tools import sync_generated as sync_tool


def _fake_generate_openapi(
    input_path,
    output_path: Path,
    *,
    allow_fallback: bool = True,
    **kwargs,
) -> None:
    _ = (input_path, allow_fallback, kwargs)
    output_path.write_text("OPENAPI\n", encoding="utf-8")


def _fake_generate_models_stub(
    output_path: Path,
    *,
    models_path: Path,
    openapi_models_path: Path,
) -> None:
    openapi_content = openapi_models_path.read_text(encoding="utf-8")
    output_path.write_text(
        f"STUB from {models_path.name}\n{openapi_content}",
        encoding="utf-8",
    )


def test_sync_generated_writes_both_outputs(monkeypatch, tmp_path: Path) -> None:
    openapi_output = tmp_path / "openapi_models.py"
    models_stub_output = tmp_path / "models.pyi"
    models_path = tmp_path / "models.py"
    models_path.write_text("class Dummy: ...\n", encoding="utf-8")

    monkeypatch.setattr(
        sync_tool.generate_openapi_models,
        "generate_models",
        _fake_generate_openapi,
    )
    monkeypatch.setattr(
        sync_tool.generate_models_stub,
        "generate_models_stub",
        _fake_generate_models_stub,
    )

    sync_tool.sync_generated(
        check=False,
        openapi_output_path=openapi_output,
        models_stub_output_path=models_stub_output,
        models_path=models_path,
    )

    assert openapi_output.read_text(encoding="utf-8") == "OPENAPI\n"
    assert models_stub_output.read_text(encoding="utf-8") == "STUB from models.py\nOPENAPI\n"


def test_sync_generated_check_does_not_write_the_snapshot(monkeypatch, tmp_path: Path) -> None:
    """`--check` nie może nadpisywać śledzonego snapshotu OpenAPI.

    Wcześniej pobranie żywej specyfikacji aktualizowało
    `specs/ksef-openapi.snapshot.json` (2.8.1 → 2.9.0) i samo tworzyło rozjazd,
    który potem raportowało — oraz brudziło drzewo robocze.
    """
    openapi_output = tmp_path / "openapi_models.py"
    models_stub_output = tmp_path / "models.pyi"
    models_path = tmp_path / "models.py"
    models_path.write_text("class Dummy: ...\n", encoding="utf-8")
    captured: list[bool] = []

    def _capture(input_path, output_path, *, allow_fallback=True, write_snapshot=True):
        _ = (input_path, allow_fallback)
        captured.append(write_snapshot)
        output_path.write_text("OPENAPI\n", encoding="utf-8")

    monkeypatch.setattr(sync_tool.generate_openapi_models, "generate_models", _capture)
    monkeypatch.setattr(
        sync_tool.generate_models_stub, "generate_models_stub", _fake_generate_models_stub
    )

    sync_tool.sync_generated(
        check=False,
        openapi_output_path=openapi_output,
        models_stub_output_path=models_stub_output,
        models_path=models_path,
    )
    assert captured == [True]

    captured.clear()
    sync_tool.sync_generated(
        check=True,
        openapi_output_path=openapi_output,
        models_stub_output_path=models_stub_output,
        models_path=models_path,
    )
    assert captured == [False], "tryb --check nie może zapisywać snapshotu"


def test_generate_models_skips_snapshot_write_when_asked(monkeypatch, tmp_path: Path) -> None:
    """Sam generator też musi mieć wyłącznik zapisu snapshotu."""
    from tools import generate_openapi_models as models

    class _Document:
        text = "{}"
        used_fallback = False

    written: list[object] = []
    monkeypatch.setattr(models, "load_openapi_document", lambda **kwargs: _Document())
    monkeypatch.setattr(models, "parse_openapi_json", lambda document: {})
    monkeypatch.setattr(models, "render_models", lambda data: "# modele\n")
    monkeypatch.setattr(
        models,
        "write_openapi_snapshot",
        lambda text, snapshot_path=None: written.append(snapshot_path),
    )
    output = tmp_path / "openapi_models.py"

    models.generate_models(None, output, write_snapshot=False)
    assert output.exists()
    assert written == []

    models.generate_models(None, output, write_snapshot=True)
    assert len(written) == 1


def test_sync_generated_check_detects_stale_outputs(monkeypatch, tmp_path: Path) -> None:
    openapi_output = tmp_path / "openapi_models.py"
    models_stub_output = tmp_path / "models.pyi"
    models_path = tmp_path / "models.py"
    models_path.write_text("class Dummy: ...\n", encoding="utf-8")
    openapi_output.write_text("stale\n", encoding="utf-8")
    models_stub_output.write_text("stale\n", encoding="utf-8")

    monkeypatch.setattr(
        sync_tool.generate_openapi_models,
        "generate_models",
        _fake_generate_openapi,
    )
    monkeypatch.setattr(
        sync_tool.generate_models_stub,
        "generate_models_stub",
        _fake_generate_models_stub,
    )

    with pytest.raises(SystemExit) as exc:
        sync_tool.sync_generated(
            check=True,
            openapi_output_path=openapi_output,
            models_stub_output_path=models_stub_output,
            models_path=models_path,
        )

    assert exc.value.code == sync_tool.EXIT_DRIFT


def test_main_supports_check_mode(monkeypatch, tmp_path: Path) -> None:
    openapi_output = tmp_path / "openapi_models.py"
    models_stub_output = tmp_path / "models.pyi"
    models_path = tmp_path / "models.py"
    models_path.write_text("class Dummy: ...\n", encoding="utf-8")

    monkeypatch.setattr(
        sync_tool.generate_openapi_models,
        "generate_models",
        _fake_generate_openapi,
    )
    monkeypatch.setattr(
        sync_tool.generate_models_stub,
        "generate_models_stub",
        _fake_generate_models_stub,
    )

    sync_tool.sync_generated(
        check=False,
        openapi_output_path=openapi_output,
        models_stub_output_path=models_stub_output,
        models_path=models_path,
    )

    monkeypatch.setattr(
        sync_tool.sys,
        "argv",
        [
            "sync_generated.py",
            "--check",
            "--openapi-output",
            str(openapi_output),
            "--models-stub-output",
            str(models_stub_output),
            "--models",
            str(models_path),
        ],
    )
    sync_tool.main()
