from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = REPO_ROOT / ".tmp" / "cli-packaging"
INSTALL_HINT = 'pip install "ksef-client[cli]"'


def _run(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd or REPO_ROOT,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Command failed with exit code {result.returncode}: {' '.join(command)}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result


def _venv_executable(venv_dir: Path, name: str) -> Path:
    scripts_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")
    suffix = ".exe" if os.name == "nt" else ""
    return scripts_dir / f"{name}{suffix}"


def _pip_command(python: Path, *args: str) -> list[str]:
    return [str(python), "-m", "pip", *args]


def _assert_contains(text: str, expected: str) -> None:
    if expected not in text:
        raise AssertionError(f"Expected to find {expected!r} in:\n{text}")


def _build_wheel() -> Path:
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    builder_python, _, _ = _create_venv(BUILD_DIR / "venv-build")
    _run(
        _pip_command(
            builder_python,
            "install",
            "--upgrade",
            "pip",
            "build",
            "setuptools>=77",
            "wheel",
        )
    )
    _run([str(builder_python), "-m", "build", "--wheel", "--outdir", str(BUILD_DIR)])
    wheels = sorted(BUILD_DIR.glob("*.whl"))
    if len(wheels) != 1:
        raise AssertionError(f"Expected exactly one wheel in {BUILD_DIR}, got {wheels}")
    return wheels[0]


def _create_venv(path: Path) -> tuple[Path, Path, Path]:
    _run([sys.executable, "-m", "venv", str(path)])
    python = _venv_executable(path, "python")
    ksef = _venv_executable(path, "ksef")
    _run(_pip_command(python, "install", "--upgrade", "pip"))
    return python, _venv_executable(path, "pip"), ksef


def _check_base_install(wheel: Path) -> None:
    python, _, ksef = _create_venv(BUILD_DIR / "venv-base")
    _run(_pip_command(python, "install", str(wheel)))
    _run([str(python), "-c", "import ksef_client.cli"])
    _run(
        [
            str(python),
            "-c",
            (
                "from importlib.util import find_spec; "
                "from pathlib import Path; "
                "spec = find_spec('ksef_client'); "
                "package_dir = Path(spec.origin).parent; "
                "assert (package_dir / 'py.typed').is_file(); "
                "assert (package_dir / 'models.pyi').is_file()"
            ),
        ]
    )

    result = subprocess.run([str(ksef), "--version"], text=True, capture_output=True, check=False)
    output = f"{result.stdout}{result.stderr}"
    if result.returncode != 6:
        raise AssertionError(
            f"Expected exit code 6 for base install, got {result.returncode}\n{output}"
        )
    _assert_contains(output, INSTALL_HINT)
    if "ModuleNotFoundError" in output:
        raise AssertionError(f"Unexpected traceback in base install output:\n{output}")


def _check_cli_extra_install(wheel: Path) -> None:
    python, _, ksef = _create_venv(BUILD_DIR / "venv-cli")
    requirement = f"ksef-client[cli] @ {wheel.resolve().as_uri()}"
    _run(_pip_command(python, "install", requirement))
    _run([str(python), "-c", "from ksef_client.cli import app; assert app is not None"])

    result = subprocess.run([str(ksef), "--version"], text=True, capture_output=True, check=False)
    output = f"{result.stdout}{result.stderr}"
    if result.returncode != 0:
        raise AssertionError(
            f"Expected exit code 0 for CLI extra install, got {result.returncode}\n{output}"
        )
    _assert_contains(output, "ksef-cli")


def main() -> None:
    wheel = _build_wheel()
    _check_base_install(wheel)
    _check_cli_extra_install(wheel)


if __name__ == "__main__":
    main()
