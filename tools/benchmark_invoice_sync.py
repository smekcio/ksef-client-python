"""Isolated Linux/Python 3.12 RSS comparison for bounded metadata synchronization."""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))


def worker(total: int, *, boundary: int = 100, dense_page: bool = False) -> dict:
    import resource

    import httpx
    from docs.examples.invoice_sync_sqlite import SQLiteInvoiceSyncStore

    from ksef_client import KsefClientOptions
    from ksef_client import models as m
    from ksef_client.clients.invoices import InvoicesClient
    from ksef_client.http import BaseHttpClient
    from ksef_client.invoice_search import _date
    from ksef_client.invoice_sync_state import MAX_CHECKPOINT_BYTES, canonical_json

    epoch = datetime(2025, 1, 1, tzinfo=timezone.utc)

    def stamp(index):
        return (epoch + timedelta(seconds=index // boundary)).isoformat()

    last = stamp(total + boundary)
    digest = base64.b64encode(b"a" * 32).decode()
    thirds = (
        [
            m.InvoiceMetadataThirdSubject.from_dict(
                {
                    "identifier": {"type": "Nip", "value": "1234567890"},
                    "role": 2,
                    "name": "x" * 512,
                }
            )
            for _ in range(100)
        ]
        if dense_page
        else None
    )

    def handle(request):
        query = json.loads(request.content)
        lower = _date(query["dateRange"]["from"])[0]
        first = max(0, int((lower - epoch).total_seconds()) * boundary)
        offset = int(request.url.params["pageOffset"]) * 250
        low, high = first + offset, min(first + offset + 250, total)
        rows = [
            m.InvoiceMetadata(
                ksef_number=f"invoice-{index:09}",
                invoice_hash=digest,
                permanent_storage_date=stamp(index),
                invoice_number="benchmark",
                third_subjects=thirds,
            )
            for index in range(low, high)
        ]
        more = high < total
        body = json.dumps(
            {
                "invoices": [r.to_dict() for r in rows],
                "hasMore": more,
                "isTruncated": more and offset + 250 == 10000,
                "permanentStorageHwmDate": last,
            }
        ).encode()
        return httpx.Response(
            200, headers={"Content-Type": "application/json"}, stream=httpx.ByteStream(body)
        )

    http = BaseHttpClient(KsefClientOptions(base_url="https://benchmark.invalid/v2"))
    http.close()
    http._client = httpx.Client(transport=httpx.MockTransport(handle))
    sync = InvoicesClient(http).sync(
        namespace="benchmark",
        sync_key="metadata",
        context_key="test",
        since=epoch.isoformat(),
        subject_types=("Subject1",),
        page_size=250,
    )
    steps, commits, sizes, serialization = [], [], [], []
    snapshot_sizes = []
    with tempfile.TemporaryDirectory(prefix="invoice-sync-") as folder:
        connection = sqlite3.connect(Path(folder) / "sync.db", timeout=5)
        connection.execute("PRAGMA cache_size=-2048")
        store = SQLiteInvoiceSyncStore(connection)
        original = store.commit

        def commit(batch):
            started = time.perf_counter()
            encoded = canonical_json(batch.next_checkpoint.to_dict(), MAX_CHECKPOINT_BYTES)
            serialization.append(time.perf_counter() - started)
            sizes.append(len(encoded))
            snapshot_sizes.append(len(batch._observations))
            start = time.perf_counter()
            result = original(batch)
            commits.append(time.perf_counter() - start)
            return result

        store.commit = commit
        stream = sync.streams[0]
        batch = stream.begin_cycle(None, until=last)
        cp = batch.confirm(store.commit(batch))
        while cp.phase == "active":
            start = time.perf_counter()
            batch = stream.next_batch(cp)
            cp = batch.confirm(store.commit(batch))
            steps.append(time.perf_counter() - start)
        count = connection.execute("SELECT count(*) FROM invoices").fetchone()[0]
        assert count == total
        connection.close()
    http.close()
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    ordered = sorted(steps)
    return {
        "records": total,
        "peak_rss_bytes": peak,
        "steps": len(steps),
        "checkpoint_max_bytes": max(sizes),
        "page_snapshot_max_bytes": max(snapshot_sizes),
        "checkpoint_serialize_p50_seconds": statistics.median(serialization),
        "commit_p50_seconds": statistics.median(commits),
        "commit_p95_seconds": sorted(commits)[min(len(commits) - 1, int(0.95 * len(commits)))],
        "step_p50_seconds": statistics.median(steps),
        "step_p95_seconds": ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))],
        "boundary_size": boundary,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=int)
    parser.add_argument("--boundary", type=int, default=100)
    parser.add_argument("--dense-page", action="store_true")
    parser.add_argument("--pairs", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.pairs <= 0 or args.boundary <= 0 or (args.worker is not None and args.worker <= 0):
        parser.error("pairs, boundary and worker must be positive")
    if sys.platform != "linux" or sys.version_info[:2] != (3, 12):
        raise SystemExit("Reference measurements require Linux/Python 3.12")
    if args.worker:
        result = worker(args.worker, boundary=args.boundary, dense_page=args.dense_page)
        result["environment"] = {
            "platform": platform.platform(),
            "python": platform.python_version(),
        }
        _output(result, args.output)
        return
    pairs = []
    for _ in range(args.pairs):
        pair = []
        for count in (50_000, 500_000):
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--worker",
                    str(count),
                    "--boundary",
                    str(args.boundary),
                    *(["--dense-page"] if args.dense_page else []),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=1800,
            )
            pair.append(json.loads(result.stdout))
        pairs.append(
            {
                "small": pair[0],
                "large": pair[1],
                "rss_delta_bytes": max(0, pair[1]["peak_rss_bytes"] - pair[0]["peak_rss_bytes"]),
            }
        )
    result = {
        "schema_version": 1,
        "parameters": {
            "pairs": args.pairs,
            "boundary": args.boundary,
            "dense_page": args.dense_page,
        },
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "pid": os.getpid(),
        },
        "pairs": pairs,
        "passed": max(p["rss_delta_bytes"] for p in pairs) <= 32 * 1024 * 1024,
    }
    _output(result, args.output)
    if not result["passed"]:
        raise SystemExit(1)


def _output(result: dict, path: Path | None) -> None:
    value = json.dumps(result, indent=2)
    if path:
        path.write_text(value + "\n", encoding="utf-8")
    print(value)


if __name__ == "__main__":
    main()
