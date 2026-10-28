"""Bounded process supervisor for the single installed-wheel TEST scenario."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, cast


def _stop(process: subprocess.Popen, grace: float) -> None:
    if os.name != "posix":
        # A manual Windows runner must provide equivalent process-tree cleanup.
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        process.wait(timeout=grace)
        return
    with contextlib.suppress(ProcessLookupError):
        cast(Any, os).killpg(process.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=grace)
    # The leader may have exited while a descendant ignored SIGTERM.
    with contextlib.suppress(ProcessLookupError):
        cast(Any, os).killpg(process.pid, 9)
    process.wait(timeout=grace)


def run_phases(
    commands: list[list[str]],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float = 1800,
    grace: float = 10,
) -> None:
    deadline = time.monotonic() + timeout
    for command in commands:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Invoice sync process watchdog expired")
        options = {"start_new_session": True} if os.name == "posix" else {"creationflags": 0x200}
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **options,
        )
        try:
            process.wait(timeout=remaining)
        except BaseException:
            _stop(process, grace)
            raise TimeoutError("Invoice sync process watchdog interrupted a phase") from None
        if process.returncode:
            _stop(process, grace)
            raise RuntimeError("Invoice sync phase failed (private output withheld)")
