from __future__ import annotations

import runpy
import sqlite3
from pathlib import Path

import pytest

from ksef_client import InvoiceMetadataPage
from ksef_client import models as m

sync_pages = runpy.run_path(
    str(Path(__file__).parents[1] / "docs/examples/invoice_checkpoint_sqlite.py")
)["sync_pages"]


class Search:
    def __init__(self):
        self.calls = []

    def page(self, cursor=None):
        self.calls.append(cursor)
        return InvoiceMetadataPage(
            [m.InvoiceMetadata(ksef_number="one")], "next" if cursor is None else None
        )


def test_checkpoint_and_items_rollback_together(tmp_path):
    db = tmp_path / "checkpoint.sqlite"
    search = Search()
    with sqlite3.connect(db) as con:
        con.executescript("""
            CREATE TABLE checkpoints(sync_key TEXT PRIMARY KEY, cursor TEXT, completed INTEGER);
            CREATE TRIGGER crash BEFORE INSERT ON checkpoints
            BEGIN SELECT RAISE(ABORT, 'crash'); END;
        """)
        with pytest.raises(sqlite3.IntegrityError, match="crash"):
            sync_pages(con, search, sync_key="test")
        assert con.execute("SELECT count(*) FROM invoices").fetchone()[0] == 0
        assert con.execute("SELECT count(*) FROM checkpoints").fetchone()[0] == 0
        con.execute("DROP TRIGGER crash")
    with sqlite3.connect(db) as con:
        assert sync_pages(con, search, sync_key="test") == 2
        assert con.execute("SELECT count(*) FROM invoices").fetchone()[0] == 1
        assert con.execute("SELECT cursor,completed FROM checkpoints").fetchone() == (None, 1)
    with sqlite3.connect(db) as con:
        assert sync_pages(con, search, sync_key="test") == 0
    assert search.calls == [None, None, "next"]


def test_restart_after_successful_commit(tmp_path):
    class CrashingSearch(Search):
        def page(self, cursor=None):
            if cursor == "next":
                raise RuntimeError("process stopped")
            return super().page(cursor)

    db = tmp_path / "restart.sqlite"
    with sqlite3.connect(db) as con, pytest.raises(RuntimeError):
        sync_pages(con, CrashingSearch(), sync_key="test")
    search = Search()
    with sqlite3.connect(db) as con:
        assert sync_pages(con, search, sync_key="test") == 1
        assert search.calls == ["next"]
        assert con.execute("SELECT count(*) FROM invoices").fetchone()[0] == 1


def test_distinct_scans_upsert_the_same_invoice(tmp_path):
    with sqlite3.connect(tmp_path / "scans.sqlite") as con:
        sync_pages(con, Search(), sync_key="first")
        sync_pages(con, Search(), sync_key="second")
        assert con.execute("SELECT count(*) FROM invoices").fetchone()[0] == 1
        assert con.execute("SELECT count(*) FROM checkpoints").fetchone()[0] == 2


def test_missing_number_never_advances_checkpoint(tmp_path):
    class InvalidSearch:
        def page(self, cursor=None):
            return InvoiceMetadataPage([m.InvoiceMetadata()], None)

    with sqlite3.connect(tmp_path / "invalid.sqlite") as con:
        with pytest.raises(ValueError, match="Missing KSeF number"):
            sync_pages(con, InvalidSearch(), sync_key="first")
        assert con.execute("SELECT count(*) FROM checkpoints").fetchone()[0] == 0
