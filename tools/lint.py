from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path


def _run(cmd: list[str]) -> int:
    proc = subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1])
    return int(proc.returncode)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail when optional lint tools (ruff/mypy) are missing.",
    )
    args = parser.parse_args()

    rc = 0

    rc |= _run([sys.executable, "-m", "compileall", "src", "tests"])
    rc |= _run([sys.executable, "-m", "pip", "check"])

    missing: list[str] = []

    if importlib.util.find_spec("ruff") is not None:
        rc |= _run([sys.executable, "-m", "ruff", "check", "."])
    else:
        missing.append("ruff")

    if importlib.util.find_spec("mypy") is not None:
        rc |= _run([sys.executable, "-m", "mypy", "src", "tests"])
    else:
        missing.append("mypy")

    if args.strict and missing:
        print(f"Missing tools: {', '.join(missing)}", file=sys.stderr)
        return 2

    if missing:
        print(f"Skipped (not installed): {', '.join(missing)}", file=sys.stderr)

    return 0 if rc == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
