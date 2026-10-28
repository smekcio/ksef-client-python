"""One synthetic metadata page per fresh interpreter; SQLite is the only resume state."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if os.environ.get("KSEF_TEST_INSTALLED") != "1":
    sys.path.insert(0, str(ROOT / "src"))

from tools.release_artifacts import verify_installed_wheel  # noqa: E402

from tests.invoice_sync_store_harness import SQLiteHarness  # noqa: E402
from tests.test_invoice_sync import H1, Server, make_sync, row  # noqa: E402


def verify() -> None:
    if os.environ.get("KSEF_TEST_INSTALLED") == "1":
        import ksef_client

        assert ROOT / "src" not in Path(ksef_client.__file__).resolve().parents
        verify_installed_wheel(Path(os.environ["KSEF_TEST_WHEEL"]))


async def run(directory: Path, asynchronous: bool, autocommit: bool) -> None:
    verify()
    # A boundary shared by 30 rows forces page offsets as well as 100-day windows.
    rows = [row(str(i), "2024-01-02T00:00:00Z") for i in range(30)] + [
        row(
            str(i + 30),
            (datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(days=35 * i)).isoformat(),
        )
        for i in range(20)
    ]
    server = Server(rows)
    sync, http = make_sync(server, asynchronous=asynchronous)
    try:
        async with SQLiteHarness(
            directory,
            asynchronous=asynchronous,
            autocommit=autocommit,
        ) as store:
            report = await store.run_once(sync, max_pages_per_stream=1)
            checkpoint = await store.load(sync.streams[0].scope)
        assert checkpoint is not None
        assert report.streams[0].pages_committed == 1
        assert len(server.calls) == 1
        assert checkpoint.committed_hwm == (H1 if report.complete else None)
        assert report.complete or report.streams[0].stop_reason == "work_limit"
        if not report.complete:
            assert report.common_coverage is None
        evidence = {
            "pid": os.getpid(),
            "complete": report.complete,
            "checkpoint": checkpoint.to_json(),
            "wire": server.calls[0],
            "sdk_path": __import__("ksef_client").__file__,
        }
        (directory / "page.json").write_text(json.dumps(evidence), encoding="utf-8")
    finally:
        if asynchronous:
            await http.aclose()
        else:
            http.close()
    verify()


if __name__ == "__main__":
    asyncio.run(run(Path(sys.argv[1]), sys.argv[2] == "async", sys.argv[3] == "autocommit"))
