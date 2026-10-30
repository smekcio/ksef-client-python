"""Measure queue-length RSS in fresh processes; no network or invoice submission."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if os.environ.get("KSEF_TEST_INSTALLED") != "1":
    sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from ksef_client import (  # noqa: E402
    FileInvoiceXmlStore,
    InvoiceSyncScope,
    InvoiceXmlKey,
    SQLiteInvoiceSyncStore,
)
from tools.benchmark_streaming_export import peak_rss  # noqa: E402


def measure(records: int) -> dict[str, int]:
    content = b"<invoice>benchmark</invoice>"
    expected = base64.b64encode(hashlib.sha256(content).digest()).decode()
    scope = InvoiceSyncScope("benchmark", "0" * 64, "ctx", "job", "1" * 64)
    number = "5555555555-20250828-010080615740-E4"
    with tempfile.TemporaryDirectory(prefix="ksef-xml-rss-") as directory:
        root = Path(directory)
        with (
            FileInvoiceXmlStore(root / "xml") as storage,
            SQLiteInvoiceSyncStore.open(
                root / "db",
                enqueue_xml=True,
                xml_storage_id=storage.storage_id,
            ) as store,
        ):
            # Generate rows inside SQLite, keeping Python allocations constant. The
            # synthetic tail labels are never interpreted as actual KSeF numbers.
            store.connection.execute(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?) "
                "INSERT INTO invoices SELECT ?,?,?,CASE WHEN x=1 THEN ? "
                "ELSE printf('z%09d',x) END,? FROM n",
                (records, scope.namespace, scope.environment, scope.context_key, number, expected),
            )
            store.connection.execute(
                "INSERT INTO invoice_observations SELECT namespace,environment,context_key,"
                "?,?,ksef_number,'{}' FROM invoices",
                (scope.sync_key, scope.stream_id),
            )
            store.connection.execute(
                "INSERT INTO invoice_xml_documents(namespace,environment,context_key,"
                "ksef_number,expected_hash,created_at) "
                "SELECT namespace,environment,context_key,ksef_number,invoice_hash,0 FROM invoices"
            )
            store.connection.commit()
            assert store.describe_xml([scope]).observed == records
            assert len(store.list_xml([scope], limit=100)) == min(100, records)
            assert store.backfill_xml([scope], batch_size=100, time_budget=0.05).processed >= 0
            claim = store.claim_xml([scope], lease_seconds=120)
            assert claim is not None and claim.key.ksef_number == number
            key = InvoiceXmlKey(scope.namespace, scope.environment, scope.context_key, number)
            receipt = storage.put_verified(key, content, expected)
            store.finish_xml(claim, receipt)
            assert store.describe_xml([scope]).ready == 1
            return {"records": records, "peak_rss_bytes": peak_rss()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", type=int)
    args = parser.parse_args()
    if args.child is not None:
        print(json.dumps(measure(args.child)))
        return
    results = []
    for count in (50_000, 500_000):
        completed = subprocess.run(
            [sys.executable, __file__, "--child", str(count)],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        results.append(json.loads(completed.stdout))
    growth = results[1]["peak_rss_bytes"] - results[0]["peak_rss_bytes"]
    print(
        json.dumps(
            {"results": results, "growth_bytes": growth, "limit_bytes": 32 * 1024 * 1024}, indent=2
        )
    )
    if growth > 32 * 1024 * 1024:
        raise SystemExit("Queue length increased peak RSS beyond the acceptance threshold")


if __name__ == "__main__":
    main()
