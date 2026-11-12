"""Fresh-interpreter XML queue recovery/contender used by process and wheel tests."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

if os.environ.get("KSEF_TEST_INSTALLED") != "1":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ksef_client import FileInvoiceXmlStore, InvoiceSyncCheckpoint, SQLiteInvoiceSyncStore


def main() -> None:
    database, directory, mode = sys.argv[1:]
    with (
        FileInvoiceXmlStore(directory) as storage,
        SQLiteInvoiceSyncStore.open(
            database, enqueue_xml=True, xml_storage_id=storage.storage_id
        ) as store,
    ):
        rows = store.connection.execute("SELECT checkpoint_json FROM sync_checkpoints").fetchall()
        scopes = [InvoiceSyncCheckpoint.from_json(row[0]).scope for row in rows]
        claim = store.claim_xml(scopes, lease_seconds=120)
        if claim is None:
            print(json.dumps({"claimed": False}))
            return
        if mode == "crash":
            os._exit(71)
        receipt = storage.inspect(claim.key, claim.expected_hash)
        if receipt is None:
            raise RuntimeError("Expected prepublished XML")
        store.finish_xml(claim, receipt)
        print(json.dumps({"claimed": True, "fencing": claim.fencing}))


if __name__ == "__main__":
    main()
