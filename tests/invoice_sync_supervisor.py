"""Bounded process supervisor for the single installed-wheel TEST scenario."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, cast

# A TEST endpoint may require waiting for its hourly quota window. Each live
# restart scenario has a hard watchdog and a soft deadline leaving cleanup time.
LIVE_SCENARIO_TIMEOUT = 4500
LIVE_SCENARIO_SOFT_TIMEOUT = LIVE_SCENARIO_TIMEOUT - 60


def linux_process_running(pid: int) -> bool:
    try:
        state = Path("/proc", str(pid), "stat").read_text().rsplit(") ", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state not in {"Z", "X"}


def _stop(process: subprocess.Popen, grace: float) -> None:
    if os.name != "posix":
        # A manual Windows runner must provide equivalent process-tree cleanup.
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=grace,
            )
        if process.poll() is None:
            process.kill()
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
    for phase, command in enumerate(commands, 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"Invoice sync process watchdog expired before phase {phase}")
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
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException as error:
            _stop(process, grace)
            if isinstance(error, subprocess.TimeoutExpired):
                raise TimeoutError(
                    f"Invoice sync process watchdog interrupted phase {phase}"
                ) from None
            raise
        # Reap descendants also when their leader exited successfully.
        _stop(process, grace)
        if process.returncode:
            raise RuntimeError(
                f"Invoice sync phase {phase} failed "
                f"(exit {process.returncode}; private output withheld)"
            )
