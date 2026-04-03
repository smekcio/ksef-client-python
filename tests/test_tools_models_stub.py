from __future__ import annotations

from pathlib import Path

import pytest
from tools import generate_models_stub as stub_generator

ROOT = Path(__file__).resolve().parents[1]
MODELS_PATH = ROOT / "src/ksef_client/models.py"
OPENAPI_MODELS_PATH = ROOT / "src/ksef_client/openapi_models.py"
MODELS_STUB_PATH = ROOT / "src/ksef_client/models.pyi"


def test_render_models_stub_contains_expected_sections() -> None:
    rendered = stub_generator.render_models_stub(
        MODELS_PATH,
        openapi_models_path=OPENAPI_MODELS_PATH,
    )

    assert "from .openapi_models import (" in rendered
    assert "@_dataclass(frozen=True)\nclass StatusInfo:" in rendered
    assert "class LighthouseKsefStatus(str, _Enum):" in rendered
    assert '"UnknownApiProblem",' in rendered


def test_generate_models_stub_reproduces_repo_stub(tmp_path: Path) -> None:
    output_path = tmp_path / "models.pyi"

    stub_generator.generate_models_stub(
        output_path,
        models_path=MODELS_PATH,
        openapi_models_path=OPENAPI_MODELS_PATH,
    )

    assert output_path.read_text(encoding="utf-8") == MODELS_STUB_PATH.read_text(encoding="utf-8")


def test_check_generated_models_stub_detects_diff(tmp_path: Path) -> None:
    output_path = tmp_path / "models.pyi"
    output_path.write_text(MODELS_STUB_PATH.read_text(encoding="utf-8"), encoding="utf-8")

    assert (
        stub_generator.check_generated_models_stub(
            output_path,
            models_path=MODELS_PATH,
            openapi_models_path=OPENAPI_MODELS_PATH,
        )
        is None
    )

    output_path.write_text("stale\n", encoding="utf-8")
    diff = stub_generator.check_generated_models_stub(
        output_path,
        models_path=MODELS_PATH,
        openapi_models_path=OPENAPI_MODELS_PATH,
    )

    assert diff is not None
    assert "generated-models-stub" in diff


def test_main_supports_check_mode(monkeypatch, tmp_path: Path) -> None:
    output_path = tmp_path / "models.pyi"
    stub_generator.generate_models_stub(
        output_path,
        models_path=MODELS_PATH,
        openapi_models_path=OPENAPI_MODELS_PATH,
    )

    monkeypatch.setattr(
        stub_generator.sys,
        "argv",
        [
            "generate_models_stub.py",
            "--models",
            str(MODELS_PATH),
            "--openapi-models",
            str(OPENAPI_MODELS_PATH),
            "--output",
            str(output_path),
            "--check",
        ],
    )
    stub_generator.main()

    output_path.write_text("stale\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        stub_generator.main()

    assert "Generated models stub is out of date" in str(exc.value)
