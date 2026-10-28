"""Run the same real SQLite contract directly or through an application async adapter."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from docs.examples.invoice_sync_sqlite import SQLiteInvoiceSyncStore


class SQLiteHarness:
    def __init__(
        self, directory, *, asynchronous, autocommit=False, store_type=SQLiteInvoiceSyncStore
    ):
        self.directory, self.asynchronous, self.autocommit = directory, asynchronous, autocommit
        self.store_type = store_type
        self.executor = ThreadPoolExecutor(max_workers=1) if asynchronous else None
        self.threads: set[int] = set()
        self.store: Any = None

    async def call(self, operation):
        def invoke():
            self.threads.add(threading.get_ident())
            return operation()

        if self.executor is None:
            return invoke()
        return await asyncio.get_running_loop().run_in_executor(self.executor, invoke)

    async def __aenter__(self):
        def create():
            connection = sqlite3.connect(self.directory / "sync.db", timeout=2)
            if self.autocommit:
                if hasattr(connection, "autocommit"):
                    connection.autocommit = True
                else:
                    connection.isolation_level = None
            return self.store_type(connection, enqueue_xml=True)

        try:
            self.store = await self.call(create)
        except BaseException:
            if self.executor is not None:
                self.executor.shutdown(wait=True)
            raise
        return self

    async def __aexit__(self, *exc):
        try:
            await self.call(self.store.connection.close)
        finally:
            if self.executor is not None:
                self.executor.shutdown(wait=True)
            assert len(self.threads) == 1
            assert (threading.get_ident() not in self.threads) == self.asynchronous

    async def load(self, scope):
        return await self.call(lambda: self.store.load(scope))

    async def commit(self, batch):
        return await self.call(lambda: self.store.commit(batch))

    async def run_once(self, sync, **kwargs):
        if self.asynchronous:
            return await sync.run_once(self, **kwargs)
        return sync.run_once(self.store, **kwargs)

    async def next_batch(self, stream, checkpoint):
        if self.asynchronous:
            return await stream.next_batch(checkpoint)
        return stream.next_batch(checkpoint)

    async def sql(self, statement):
        return await self.call(lambda: self.store.connection.execute(statement).fetchall())
