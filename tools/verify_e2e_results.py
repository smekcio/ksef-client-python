"""Fail closed unless every required live TEST scenario really passed."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MANIFEST = Path(__file__).resolve().parents[1] / "tests/required_test_e2e.json"
REQUIRED = [
    "tests/test_e2e_token_flows.py::test_e2e_test_environment_full_flow_token",
    "tests/test_e2e_token_flows.py::test_e2e_test_environment_full_flow_xades",
    "tests/test_e2e_resume_flows.py::test_e2e_test_environment_online_resume_token",
    "tests/test_e2e_resume_flows.py::test_e2e_test_environment_batch_resume_token",
    "tests/test_e2e_pagination.py::test_e2e_test_environment_cursor_restart",
    "tests/test_e2e_facade.py::test_e2e_test_environment_facade_streaming_export",
    "tests/test_e2e_invoice_sync.py::test_e2e_test_environment_invoice_sync_restart",
    "tests/test_e2e_invoice_xml_sync.py::test_e2e_test_environment_invoice_xml_restart",
]
TOKEN_REV2 = ["tests/test_e2e_rev2_tokens.py::test_e2e_test_environment_rev2_token_lifecycle"]
OPERATIONS = [
    "tests/test_e2e_certificate_rotation.py::"
    "test_e2e_test_environment_certificate_rotation_between_cycles",
    "tests/test_e2e_offline_queue.py::test_e2e_test_environment_offline_queue_restart_and_upo",
    "tests/test_e2e_export_archive.py::test_e2e_test_environment_export_archive_restart",
]
LIVE_SUITES = {
    "required": REQUIRED,
    "token-rev2": TOKEN_REV2,
    "operations": OPERATIONS,
    "extended": [*TOKEN_REV2, *OPERATIONS],
}


def validate_live_install(required: list[str], *, suite: str = "required") -> None:
    from tools.release_artifacts import verify_installed_wheel

    if (
        required != LIVE_SUITES[suite]
        or os.environ.get("KSEF_TEST_INSTALLED") != "1"
        or os.environ.get("KSEF_E2E") != "1"
    ):
        raise ValueError("Live gate requires the approved TEST manifest and installed wheel mode")
    wheel = os.environ.get("KSEF_TEST_WHEEL")
    if not wheel:
        raise ValueError("Missing exact wheel")
    verify_installed_wheel(Path(wheel))


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
    if root.tag not in {"testsuites", "testsuite"}:
        raise ValueError("Invalid JUnit root")
    for suite in root.iter():
        if suite.tag in {"testsuite", "testsuites"}:
            for counter in ("errors", "failures"):
                value = suite.get(counter)
                if value is not None and int(value) != 0:
                    raise ValueError("JUnit suite reports errors or failures")
    outcomes: dict[str, list[bool]] = {}
    for case in root.iter("testcase"):
        node = case.get("classname", "").replace(".", "/") + ".py::" + case.get("name", "")
        passed = not any(case.find(tag) is not None for tag in ("skipped", "failure", "error"))
        outcomes.setdefault(node, []).append(passed)
    if list(root.iter("error")) or list(root.iter("failure")):
        raise ValueError("E2E report contains errors or failures")
    if any(
        node.tag in {"rerunFailure", "rerunError", "flakyFailure", "flakyError"}
        for node in root.iter()
    ):
        raise ValueError("E2E scenarios must pass without scenario reruns")
    if outcomes != {name: [True] for name in required}:
        raise ValueError("JUnit must contain exactly one success for each approved E2E test")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--suite", choices=LIVE_SUITES, default="required")
    parser.add_argument(
        "--run", action="store_true", help="Run required tests once before verification"
    )
    args = parser.parse_args(argv)
    try:
        if args.manifest is not None or args.suite == "required":
            required = required_tests(args.manifest or MANIFEST)
        else:
            required = LIVE_SUITES[args.suite]
        if args.run:
            validate_live_install(required, suite=args.suite)
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.unlink(missing_ok=True)
            result = subprocess.run(
                [
                    sys.executable,
                    "-u",
                    "-m",
                    "pytest",
                    "-v",
                    "--tb=short",
                    "--show-capture=no",
                    "--durations=0",
                    "--maxfail=1",
                    "-o",
                    "xfail_strict=true",
                    f"--junitxml={args.report}",
                    # Exercise durable XML before the other metadata-heavy flows.
                    # Verification still requires every approved scenario exactly once.
                    *(required[-1:] + required[:-1] if args.suite == "required" else required),
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
