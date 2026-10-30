"""Compare historical SELECT cost with indexed claims on a real local SQLite queue."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ksef_client import InvoiceSyncScope, SQLiteInvoiceSyncStore  # noqa: E402
from ksef_client.utils.ksef_number import _crc8  # noqa: E402


def measure(records: int, claims: int) -> dict:
    scope = InvoiceSyncScope("benchmark", "0" * 64, "ctx", "job", "1" * 64)
    prefix = (scope.namespace, scope.environment, scope.context_key)
    expected = base64.b64encode(hashlib.sha256(b"<invoice/>").digest()).decode()

    def rows():
        for index in range(records):
            stem = f"5555555555-20250828-{index:012X}"
            yield (*prefix, f"{stem}-{_crc8(stem.encode()):02X}", expected)

    with (
        tempfile.TemporaryDirectory(prefix="ksef-xml-claims-") as directory,
        SQLiteInvoiceSyncStore.open(
            Path(directory) / "queue.db", enqueue_xml=True, xml_storage_id="benchmark"
        ) as store,
    ):
        store.connection.executemany("INSERT INTO invoices VALUES (?,?,?,?,?)", rows())
        store.connection.execute(
            "INSERT INTO invoice_observations SELECT namespace,environment,context_key,"
            "?,?,ksef_number,'{}' FROM invoices",
            (scope.sync_key, scope.stream_id),
        )
        store.connection.execute(
            "INSERT INTO invoice_xml_documents(namespace,environment,context_key,"
            "ksef_number,expected_hash,created_at) SELECT namespace,environment,"
            "context_key,ksef_number,invoice_hash,0 FROM invoices"
        )
        store.connection.commit()
        cte, values = store._selected([scope])
        baseline = cte + (
            "SELECT d.namespace,d.environment,d.context_key,d.ksef_number,"
            "d.variant,d.expected_hash,d.fencing,d.failures,d.attempts "
            "FROM invoice_xml_documents d JOIN selected s "
            "USING(namespace,environment,context_key,ksef_number) "
            "WHERE (d.status IN ('pending','retry_wait') AND d.next_attempt_at<=?) "
            "OR (d.status='leased' AND d.lease_until<=?) "
            "ORDER BY d.next_attempt_at,d.created_at,d.ksef_number LIMIT 1"
        )
        indexed, indexed_parameters = store._claim_query([scope], time.time())
        old_times, indexed_times, new_times = [], [], []
        for _ in range(min(10, claims)):
            store.connection.execute("BEGIN IMMEDIATE")
            started = time.perf_counter()
            store.connection.execute(baseline, (*values, time.time(), time.time())).fetchone()
            old_times.append(time.perf_counter() - started)
            store.connection.rollback()
        for _ in range(min(10, claims)):
            store.connection.execute("BEGIN IMMEDIATE")
            started = time.perf_counter()
            store.connection.execute(indexed, indexed_parameters).fetchone()
            indexed_times.append(time.perf_counter() - started)
            store.connection.rollback()

        def instructions(sql, parameters):
            steps = 0

            def progress():
                nonlocal steps
                steps += 100
                return 0

            store.connection.set_progress_handler(progress, 100)
            try:
                store.connection.execute(sql, parameters).fetchone()
            finally:
                store.connection.set_progress_handler(None, 0)
            return steps

        baseline_steps = instructions(baseline, (*values, time.time(), time.time()))
        indexed_steps = instructions(indexed, indexed_parameters)
        for _ in range(claims):
            started = time.perf_counter()
            assert store.claim_xml([scope]) is not None
            new_times.append(time.perf_counter() - started)
        query, parameters = store._claim_query([scope], time.time())
        return {
            "records": records,
            "claims": claims,
            "baseline_select_median_ms": statistics.median(old_times) * 1000,
            "indexed_select_median_ms": statistics.median(indexed_times) * 1000,
            "baseline_select_vm_steps_approx": baseline_steps,
            "indexed_select_vm_steps_approx": indexed_steps,
            "indexed_full_claim_median_ms": statistics.median(new_times) * 1000,
            "indexed_full_claim_max_ms": max(new_times) * 1000,
            "indexed_full_claim_total_ms": sum(new_times) * 1000,
            "plan": [
                row[-1]
                for row in store.connection.execute("EXPLAIN QUERY PLAN " + query, parameters)
            ],
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=50_000)
    parser.add_argument("--claims", type=int, default=100)
    args = parser.parse_args()
    if not 1 <= args.claims <= args.records:
        parser.error("Require 1 <= claims <= records")
    print(json.dumps(measure(args.records, args.claims), indent=2))


if __name__ == "__main__":
    main()
