from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tarfile
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = REPO_ROOT / ".tmp" / "cli-packaging"
INSTALL_HINT = 'pip install "ksef-client[cli]"'

#: Pliki XSD FA(3) deklarowane w `[tool.setuptools.package-data]`. Bez nich
#: `to_xml(xsd_validate=True)` z zainstalowanego pakietu nie ma czego skompilować,
#: a wheel pozostaje instalowalny — dlatego obecność tych plików jest sprawdzana
#: na zawartości zbudowanego wheela, a nie w drzewie źródeł.
SCHEMA_FILES = (
    "schemat_FA(3)_v1-0E.xsd",
    "ElementarneTypyDanych_v10-0E.xsd",
    "KodyKrajow_v10-0E.xsd",
    "StrukturyDanych_v10-0E.xsd",
)

#: Smoke test walidacji XSD z zainstalowanego wheela (wymaga dodatku `fa3`).
FA3_SMOKE_TEST = textwrap.dedent(
    """
    from datetime import date

    from ksef_client.documents.fa3 import FA3InvoiceBuilder, FA3Party, validate_invoice_xml

    draft = (
        FA3InvoiceBuilder(
            invoice_number="FV/PKG/001/2026",
            issue_date=date(2026, 5, 16),
            seller=FA3Party(
                name="Sprzedawca Sp. z o.o.", tax_id="1234567890", address="ul. Prosta 1"
            ),
            buyer=FA3Party(name="Nabywca S.A.", tax_id="1111111111", address="ul. Jasna 2"),
            currency="PLN",
            issue_place="Warszawa",
        )
        .add_line("Usluga konsultingowa", quantity="2", unit_net_price="500", vat_rate="23")
        .build()
    )

    xml = draft.to_xml(xsd_validate=True)
    if b"<Faktura" not in xml or b"<P_15>1230.00</P_15>" not in xml:
        raise AssertionError(f"nieoczekiwany XML z walidacją XSD: {xml[:400]!r}")
    assert validate_invoice_xml(xml).valid
    bad = validate_invoice_xml(xml.replace(b"<NIP>", b"<NIP>private-"))
    assert bad.issues and all(issue.field == "NIP" for issue in bad.issues)
    assert "private-" not in repr(bad)
    print(f"fa3 xsd smoke OK: {len(xml)} B")
    """
).strip()


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


def _build_distributions() -> tuple[Path, Path]:
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
    _run(
        [
            str(builder_python),
            "-m",
            "build",
            "--sdist",
            "--wheel",
            "--outdir",
            str(BUILD_DIR),
        ]
    )
    wheels = sorted(BUILD_DIR.glob("*.whl"))
    sdists = sorted(BUILD_DIR.glob("*.tar.gz"))
    if len(wheels) != 1:
        raise AssertionError(f"Expected exactly one wheel in {BUILD_DIR}, got {wheels}")
    if len(sdists) != 1:
        raise AssertionError(f"Expected exactly one sdist in {BUILD_DIR}, got {sdists}")
    return wheels[0], sdists[0]


def _create_venv(path: Path) -> tuple[Path, Path, Path]:
    _run([sys.executable, "-m", "venv", str(path)])
    python = _venv_executable(path, "python")
    ksef = _venv_executable(path, "ksef")
    _run(_pip_command(python, "install", "--upgrade", "pip"))
    return python, _venv_executable(path, "pip"), ksef


def _check_sdist_contents(sdist: Path) -> None:
    """sdist musi nieść źródła z XSD i nie może nieść testów, których nie da się uruchomić.

    `setuptools` domyślnie dołącza do sdist pliki `tests/test*.py`, ale bez
    `conftest.py`, `helpers.py` i katalogu `tools/` takich testów nie da się
    uruchomić po rozpakowaniu archiwum (kolekcja kończy się błędami importu).
    """
    with tarfile.open(sdist) as archive:
        names = archive.getnames()

    packaged_tests = [name for name in names if name.endswith("/tests") or "/tests/" in name]
    if packaged_tests:
        raise AssertionError(
            "sdist zawiera testy, których nie da się uruchomić (MANIFEST.in -> prune tests):\n"
            + "\n".join(packaged_tests[:10])
        )

    missing_schemas = [
        schema for schema in SCHEMA_FILES if not any(name.endswith(f"/{schema}") for name in names)
    ]
    if missing_schemas:
        raise AssertionError(f"sdist bez plików XSD: {missing_schemas}")

    # Samo `src/ksef_client/...` nie wystarcza: archiwum z XSD i katalogiem pakietu,
    # ale bez modułów, przechodziło tę kontrolę (dowód z weryfikacji obalającej).
    required_modules = ("/src/ksef_client/__init__.py", "/src/ksef_client/models.py")
    missing_modules = [
        module for module in required_modules if not any(name.endswith(module) for name in names)
    ]
    if missing_modules:
        raise AssertionError(f"sdist bez modułów pakietu: {missing_modules}")


def _check_base_install(wheel: Path) -> None:
    python, _, ksef = _create_venv(BUILD_DIR / "venv-base")
    _run(_pip_command(python, "install", str(wheel)))
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    quickstart = re.search(r"^```python\n(.+?)\n```.*?^```text\n(.+?)\n```", readme, re.M | re.S)
    if quickstart is None:
        raise AssertionError("Brak przykładu startowego w Pythonie lub jego wyniku w README.")
    result = _run([str(python), "-c", quickstart[1]], cwd=REPO_ROOT / "docs" / "examples")
    if result.stdout.strip() != quickstart[2]:
        raise AssertionError(
            f"Wynik przykładu z README: {result.stdout!r}, oczekiwano {quickstart[2]!r}"
        )
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
                "assert (package_dir / 'models.pyi').is_file(); "
                f"schemas = package_dir / 'documents' / 'fa3' / 'schemas'; "
                f"missing = [name for name in {SCHEMA_FILES!r} if not (schemas / name).is_file()]; "
                "assert not missing, f'brak plikow XSD w wheelu: {missing}'"
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


def _check_fa3_validation_from_wheel(wheel: Path) -> None:
    """`to_xml(xsd_validate=True)` musi działać z wheela, bez drzewa źródeł."""
    python, _, _ = _create_venv(BUILD_DIR / "venv-fa3")
    requirement = f"ksef-client[fa3] @ {wheel.resolve().as_uri()}"
    _run(_pip_command(python, "install", requirement))
    result = _run([str(python), "-c", FA3_SMOKE_TEST])
    _assert_contains(f"{result.stdout}{result.stderr}", "fa3 xsd smoke OK")
    # Exercising the wheel as an importable archive also checks package-resource discovery.
    prefix = "import sys; sys.path.insert(0, sys.argv[1])\n"
    _run([str(python), "-c", prefix + FA3_SMOKE_TEST, str(wheel.resolve())])


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
    wheel, sdist = _build_distributions()
    _check_sdist_contents(sdist)
    _check_base_install(wheel)
    _check_fa3_validation_from_wheel(wheel)
    _check_cli_extra_install(wheel)


if __name__ == "__main__":
    main()
