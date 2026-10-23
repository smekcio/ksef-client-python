"""Fail closed unless every required live TEST scenario really passed."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MANIFEST = Path(__file__).resolve().parents[1] / "tests/required_test_e2e.json"


def required_tests(path: Path = MANIFEST) -> list[str]:
    names = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(names, list)
        or not names
        or any(
            not isinstance(n, str) or not re.fullmatch(r"tests/test_\w+\.py::test_\w+", n)
            for n in names
        )
    ):
        raise ValueError("Invalid required E2E manifest")
    if len(set(names)) != len(names):
        raise ValueError("Duplicate required E2E tests")
    return names


def verify(report: Path, required: list[str]) -> None:
    root = ET.parse(report).getroot()
    outcomes: dict[str, list[bool]] = {}
    for case in root.iter("testcase"):
        node = case.get("classname", "").replace(".", "/") + ".py::" + case.get("name", "")
        passed = not any(case.find(tag) is not None for tag in ("skipped", "failure", "error"))
        outcomes.setdefault(node, []).append(passed)
    if list(root.iter("error")) or list(root.iter("failure")):
        raise ValueError("E2E report contains errors or failures")
    failed = [name for name in required if outcomes.get(name) != [True]]
    if failed:
        raise ValueError("Required E2E tests missing, repeated or not passed: " + ", ".join(failed))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument(
        "--run", action="store_true", help="Run required tests once before verification"
    )
    args = parser.parse_args(argv)
    try:
        required = required_tests(args.manifest)
        if args.run:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.unlink(missing_ok=True)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "--tb=short",
                    "--show-capture=no",
                    "-o",
                    "xfail_strict=true",
                    f"--junitxml={args.report}",
                    *required,
                ],
                check=False,
            )
            if result.returncode:
                return result.returncode
        verify(args.report, required)
    except (OSError, ValueError, TypeError, ET.ParseError):
        print(
            "Required TEST E2E gate failed: invalid manifest/report or non-passing tests",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
