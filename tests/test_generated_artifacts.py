from __future__ import annotations

from pathlib import Path

from tools import generate_models_stub, generate_openapi_models, openapi_spec

ROOT = Path(__file__).resolve().parents[1]
REPO_OPENAPI_MODELS_PATH = ROOT / "src/ksef_client/openapi_models.py"
REPO_MODELS_STUB_PATH = ROOT / "src/ksef_client/models.pyi"
REPO_MODELS_PATH = ROOT / "src/ksef_client/models.py"
SNAPSHOT_PATH = openapi_spec.DEFAULT_KSEF_OPENAPI_FALLBACK_PATH


def test_generated_artifacts_match_repository_versions(tmp_path: Path) -> None:
    generated_openapi_path = tmp_path / "openapi_models.py"
    generated_models_stub_path = tmp_path / "models.pyi"

    generate_openapi_models.generate_models(SNAPSHOT_PATH, generated_openapi_path)
    generate_models_stub.generate_models_stub(
        generated_models_stub_path,
        models_path=REPO_MODELS_PATH,
        openapi_models_path=generated_openapi_path,
    )

    assert generated_openapi_path.read_text(encoding="utf-8") == REPO_OPENAPI_MODELS_PATH.read_text(
        encoding="utf-8"
    )
    assert (
        generated_models_stub_path.read_text(encoding="utf-8")
        == REPO_MODELS_STUB_PATH.read_text(encoding="utf-8")
    )
