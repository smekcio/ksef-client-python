"""Run one scheduled loop per KSeF profile and log its CLI results as JSON."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any


def cycle(profile: str, options: list[str]) -> tuple[dict[str, Any], bool, float | None]:
    try:
        result = subprocess.run(
            ["ksef", "--profile", profile, "--json", *options],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=180,
            check=False,
        )
        report = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        report = {
            "ok": False,
            "profile": profile,
            "command": ".".join(options[:2]),
            "errors": [{"code": "CLI_UNAVAILABLE"}],
        }
    print(json.dumps(report), flush=True)
    errors = report.get("errors") or []
    first = errors[0] if errors else {}
    return report, first.get("code") == "RETRY_EXHAUSTED", first.get("retry_after_seconds")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--since", required=True)
    parser.add_argument("--role", default="Subject2")
    parser.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()
    if args.interval < 1:
        parser.error("--interval must be positive")

    common = ["--state-dir", str(args.state_dir)]
    archive = [
        "archive",
        "sync",
        *common,
        "--since",
        args.since,
        "--role",
        args.role,
        "--timeout",
        "30",
    ]
    offline = ["offline", "run", *common, "--limit", "5", "--timeout", "15"]
    next_archive = next_offline = time.monotonic()
    cursor: dict[str, str] | None = None
    while True:
        if time.monotonic() >= next_offline:
            page = (
                ["--after-due-at", cursor["due_at"], "--after-hash", cursor["invoice_hash"]]
                if cursor
                else []
            )
            report, limited, retry_after = cycle(args.profile, offline + page)
            if report.get("ok"):
                cursor = report["data"]["next_cursor"]
            next_offline = time.monotonic() + max(args.interval, retry_after or 0)
            if limited:
                next_archive = max(next_archive, next_offline)
        if time.monotonic() >= next_archive:
            _, limited, retry_after = cycle(args.profile, archive)
            next_archive = time.monotonic() + max(args.interval, retry_after or 0)
            if limited:
                next_offline = max(next_offline, next_archive)
        time.sleep(max(0, min(next_archive, next_offline) - time.monotonic()))


if __name__ == "__main__":
    main()
