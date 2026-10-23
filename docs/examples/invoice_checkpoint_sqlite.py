"""Transactional metadata checkpoints. See docs/reliable-pagination.md.

Example:
  Set KSEF_ACCESS_TOKEN in the environment, then run:
  python docs/examples/invoice_checkpoint_sqlite.py --database invoices.sqlite \
    --context-key Nip:5265877635 --from 2026-10-01 --to 2026-10-02

Use a TokenManager/AuthenticatedClient for long-running applications.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from typing import Protocol

from ksef_client import InvoiceMetadataPage, KsefClient, KsefClientOptions, models as m


class MetadataSearch(Protocol):
    def page(self, cursor: str | None = None) -> InvoiceMetadataPage: ...


def sync_pages(connection: sqlite3.Connection, search: MetadataSearch, *, sync_key: str) -> int:
    """Persist items and next cursor atomically; returns newly processed item count.

    Use one worker per sync_key. Do not log cursors or the database contents.
    A committed completed=1 row distinguishes completion from an unstarted scan.
    """
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS invoices (
            sync_key TEXT NOT NULL, ksef_number TEXT NOT NULL, metadata TEXT NOT NULL,
            PRIMARY KEY (sync_key, ksef_number)
        );
        CREATE TABLE IF NOT EXISTS checkpoints (
            sync_key TEXT PRIMARY KEY, cursor TEXT, completed INTEGER NOT NULL
        );
    """)
    row = connection.execute(
        "SELECT cursor, completed FROM checkpoints WHERE sync_key=?",
        (sync_key,),
    ).fetchone()
    if row is not None and row[1]:
        return 0
    cursor = row[0] if row else None
    processed = 0
    while True:
        page = search.page(cursor)
        with connection:
            for invoice in page.items:
                if not invoice.ksef_number:
                    raise ValueError("Missing KSeF number; checkpoint was not advanced")
                connection.execute(
                    "INSERT INTO invoices VALUES (?, ?, ?) "
                    "ON CONFLICT(sync_key, ksef_number) DO UPDATE SET metadata=excluded.metadata",
                    (sync_key, invoice.ksef_number, json.dumps(invoice.to_dict())),
                )
            connection.execute(
                "INSERT INTO checkpoints VALUES (?, ?, ?) ON CONFLICT(sync_key) "
                "DO UPDATE SET cursor=excluded.cursor, completed=excluded.completed",
                (sync_key, page.next_cursor, int(page.next_cursor is None)),
            )
        processed += len(page.items)
        cursor = page.next_cursor
        if cursor is None:
            return processed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--context-key", required=True, help="Same context as KSEF_ACCESS_TOKEN")
    parser.add_argument("--base-url", default="https://api-test.ksef.mf.gov.pl")
    parser.add_argument("--from", dest="date_from", required=True)
    parser.add_argument("--to", dest="date_to", required=True)
    args = parser.parse_args()
    request = m.InvoiceQueryFilters(
        subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
        date_range=m.InvoiceQueryDateRange(
            date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
            from_=args.date_from,
            to=args.date_to,
            restrict_to_permanent_storage_hwm_date=True,
        ),
    )
    identity = json.dumps([args.base_url, args.context_key, request.to_dict()], sort_keys=True)
    sync_key = hashlib.sha256(identity.encode()).hexdigest()
    with KsefClient(
        KsefClientOptions(base_url=args.base_url), access_token=os.environ["KSEF_ACCESS_TOKEN"]
    ) as client:
        search = client.invoices.search_invoice_metadata(request, context_key=args.context_key)
        with sqlite3.connect(args.database) as connection:
            print(f"Processed {sync_pages(connection, search, sync_key=sync_key)} metadata records")


if __name__ == "__main__":
    main()
