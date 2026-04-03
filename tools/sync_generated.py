from __future__ import annotations

import argparse
import difflib
import sys
import tempfile
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import generate_models_stub, generate_openapi_models

DEFAULT_OPENAPI_OUTPUT_PATH = Path("src/ksef_client/openapi_models.py")
DEFAULT_MODELS_STUB_OUTPUT_PATH = Path("src/ksef_client/models.pyi")
DEFAULT_MODELS_PATH = Path("src/ksef_client/models.py")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Failed to read generated artifact from {path}: {exc}") from exc


def _diff_output(*, actual_path: Path, expected_text: str, generated_name: str) -> str | None:
    actual_text = _read_text(actual_path)
    if actual_text == expected_text:
        return None
    diff = difflib.unified_diff(
        actual_text.splitlines(),
        expected_text.splitlines(),
        fromfile=str(actual_path),
        tofile=generated_name,
        lineterm="",
    )
    return "\n".join(diff) + "\n"


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def sync_generated(
    *,
    check: bool,
    input_path: Path | None = None,
    allow_fallback: bool = True,
    openapi_output_path: Path = DEFAULT_OPENAPI_OUTPUT_PATH,
    models_stub_output_path: Path = DEFAULT_MODELS_STUB_OUTPUT_PATH,
    models_path: Path = DEFAULT_MODELS_PATH,
) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir_name:
        tmp_dir = Path(tmp_dir_name)
        generated_openapi_path = tmp_dir / "openapi_models.py"
        generated_models_stub_path = tmp_dir / "models.pyi"

        generate_openapi_models.generate_models(
            input_path,
            generated_openapi_path,
            allow_fallback=allow_fallback,
        )
        generate_models_stub.generate_models_stub(
            generated_models_stub_path,
            models_path=models_path,
            openapi_models_path=generated_openapi_path,
        )

        generated_openapi_text = _read_text(generated_openapi_path)
        generated_models_stub_text = _read_text(generated_models_stub_path)

        if check:
            diffs = [
                diff
                for diff in (
                    _diff_output(
                        actual_path=openapi_output_path,
                        expected_text=generated_openapi_text,
                        generated_name="generated-openapi-models",
                    ),
                    _diff_output(
                        actual_path=models_stub_output_path,
                        expected_text=generated_models_stub_text,
                        generated_name="generated-models-stub",
                    ),
                )
                if diff is not None
            ]
            if diffs:
                for diff in diffs:
                    print(diff, end="")
                raise SystemExit(
                    "Generated artifacts are out of date. "
                    "Run tools/sync_generated.py and commit the result."
                )
            return

        _write_text(openapi_output_path, generated_openapi_text)
        _write_text(models_stub_output_path, generated_models_stub_text)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        type=Path,
        help="Optional path to a local OpenAPI JSON file. Defaults to the official KSeF endpoint.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if generated artifacts differ from the outputs instead of writing files.",
    )
    parser.add_argument(
        "--no-fallback",
        action="store_true",
        help="Require the live OpenAPI spec when --input is not provided.",
    )
    parser.add_argument(
        "--openapi-output",
        default=DEFAULT_OPENAPI_OUTPUT_PATH,
        type=Path,
        help="Path to output openapi_models.py file.",
    )
    parser.add_argument(
        "--models-stub-output",
        default=DEFAULT_MODELS_STUB_OUTPUT_PATH,
        type=Path,
        help="Path to output models.pyi file.",
    )
    parser.add_argument(
        "--models",
        default=DEFAULT_MODELS_PATH,
        type=Path,
        help="Path to models.py source file used to render wrapper stubs.",
    )
    args = parser.parse_args()

    sync_generated(
        check=args.check,
        input_path=args.input,
        allow_fallback=not args.no_fallback,
        openapi_output_path=args.openapi_output,
        models_stub_output_path=args.models_stub_output,
        models_path=args.models,
    )


if __name__ == "__main__":
    main()
