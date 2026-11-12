"""One supervised phase. This helper comes from the trusted workflow checkout."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

# Only trusted tests/helpers are added. Never add the source SDK or an editable install.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from docs.examples.invoice_sync_sqlite import SQLiteInvoiceSyncStore  # noqa: E402
from tools.release_artifacts import verify_installed_wheel  # noqa: E402

from ksef_client import (  # noqa: E402
    Ksef,
    KsefIncompletePaginationError,  # noqa: E402
    TokenCredentials,
)
from ksef_client import models as m  # noqa: E402
from ksef_client.invoice_search import _date  # noqa: E402
from ksef_client.request_control import request_control, wait_seconds  # noqa: E402
from ksef_client.utils.ksef_number import canonical_ksef_number  # noqa: E402
from tests.invoice_live_diagnostics import diagnostic  # noqa: E402
from tests.invoice_live_options import live_options  # noqa: E402
from tests.test_e2e_token_flows import (  # noqa: E402
    _build_invoice_xml,
    _load_test_token_config,
)


def verify() -> None:
    import ksef_client

    assert os.environ.get("KSEF_TEST_INSTALLED") == "1"
    assert ROOT / "src" not in Path(ksef_client.__file__).resolve().parents
    verify_installed_wheel(Path(os.environ["KSEF_TEST_WHEEL"]))


def document_number(number):
    try:
        return canonical_ksef_number(number)
    except ValueError:
        return number


def find_at_hwm(scan, number):
    cursor, found = None, None
    try:
        while True:
            page = scan.observation_page(cursor)
            found = next(
                (
                    r
                    for r in page.observations
                    if document_number(r.ksef_number or "") == document_number(number)
                ),
                found,
            )
            cursor = page.next_cursor
            if cursor is None:
                return found, page.permanent_storage_hwm_date
    except KsefIncompletePaginationError as error:
        if error.reason_code != "hwm_before_start":
            raise
        return None, None


def check_wire_bounds(scan, query, response) -> None:
    wire = query.date_range
    assert _date(scan.from_) <= _date(wire.from_) <= _date(wire.to) <= _date(scan.to)
    assert (_date(wire.to)[0].date() - _date(wire.from_)[0].date()).days <= 100
    assert wire.restrict_to_permanent_storage_hwm_date is True
    assert response.permanent_storage_hwm_date is not None
    upper = min((wire.to, response.permanent_storage_hwm_date), key=_date)
    assert all(
        _date(wire.from_) <= _date(row.permanent_storage_date) <= _date(upper)
        for row in response.invoices
    )


def run(phase: str) -> None:
    diagnostic(stage="connect", phase=phase, path=Path("metadata-live-diagnostic.json"))
    verify()
    path = Path("state.json")
    state = json.loads(path.read_text(encoding="utf-8"))
    config = _load_test_token_config()
    assert config.token
    options = live_options(config.base_url, config.context_type, config.context_value)
    with (
        request_control(deadline=state["soft_deadline"]),
        Ksef.connect(
            options=options,
            credentials=TokenCredentials(config.token),
            context_type=config.context_type,
            context_value=config.context_value,
            timeout=120,
        ) as client,
    ):
        original_transport = client.api.invoices._query_invoice_metadata_observation_page

        def observed_transport(*args, **kwargs):
            try:
                return original_transport(*args, **kwargs)
            except BaseException as error:
                diagnostic(transport_error=error, path=Path("metadata-live-diagnostic.json"))
                raise

        cast(Any, client.api.invoices)._query_invoice_metadata_observation_page = observed_transport
        sync = client.invoices.sync(
            namespace="installed-wheel-test",
            sync_key="metadata",
            since=state["since"],
            subject_types=(m.InvoiceQuerySubjectType.SUBJECT1,),
        )
        connection = sqlite3.connect("sync.db", timeout=5)
        store = SQLiteInvoiceSyncStore(connection)
        try:
            old = store.load(sync.streams[0].scope)
            assert (old is None) == (phase == "bootstrap")
            if old is not None:
                assert old.committed_hwm == state["h1"] and old.phase == "idle"
            diagnostic(stage="submit", path=Path("metadata-live-diagnostic.json"))
            with client.online_session() as session:
                submitted = session.send_invoice(
                    _build_invoice_xml(
                        seller_nip=config.context_value,
                        environment_name="invoice-sync-" + phase,
                    )
                ).wait(timeout=120)
            # Closing only starts finalization. Match the facade live flow before
            # observing metadata, so acceptance is not mistaken for publication.
            session.wait(timeout=360)
            assert session.upo().wait(timeout=360).pages
            assert submitted.ksef_number
            submitted_number = canonical_ksef_number(submitted.ksef_number)
            poll_end = state["soft_deadline"]
            query = m.InvoiceQueryFilters(
                subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
                date_range=m.InvoiceQueryDateRange(
                    date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
                    from_=state["since"],
                    restrict_to_permanent_storage_hwm_date=True,
                ),
            )
            diagnostic(stage="observe", path=Path("metadata-live-diagnostic.json"))
            with request_control(deadline=poll_end):
                while True:
                    scan = client.api.invoices.search_invoice_metadata_range(
                        replace(
                            query,
                            date_range=replace(
                                query.date_range, to=datetime.now(timezone.utc).isoformat()
                            ),
                        ),
                        context_key=client.context_key,
                    )
                    found, observed_hwm = find_at_hwm(scan, submitted.ksef_number)
                    if found is not None:
                        assert observed_hwm
                        if old is not None:
                            assert _date(cast(str, found.permanent_storage_date)) > _date(
                                cast(str, old.committed_hwm)
                            )
                        break
                    wait_seconds(60)
            original_factory = sync.streams[0]._search_factory
            original_wire = client.api.invoices._query_invoice_metadata_observation_page
            bounds: list[m.InvoiceQueryDateRange] = []

            def checked_wire(filters, **kwargs):
                response = original_wire(filters, **kwargs)
                check_wire_bounds(bounds[-1], filters, response)
                return response

            cast(Any, client.api.invoices)._query_invoice_metadata_observation_page = checked_wire

            def checked_factory(filters, **kwargs):
                bounds.append(filters.date_range)
                if old is not None:
                    assert _date(filters.date_range.from_) == _date(cast(str, old.committed_hwm))
                assert filters.date_range.to is not None
                return original_factory(filters, **kwargs)

            sync.streams[0]._search_factory = checked_factory
            diagnostic(stage="metadata", path=Path("metadata-live-diagnostic.json"))
            while True:
                report = sync.run_once(store, time_budget=120)
                diagnostic(metadata_report=report, path=Path("metadata-live-diagnostic.json"))
                checkpoint = store.load(sync.streams[0].scope)
                assert checkpoint is not None
                if report.complete:
                    break
                assert report.streams[0].status == "partial" and checkpoint.phase == "active"
            assert bounds and checkpoint.phase == "idle" and checkpoint.committed_hwm
            assert (
                connection.execute(
                    "SELECT count(*) FROM invoices WHERE ksef_number=?", (submitted_number,)
                ).fetchone()[0]
                == 1
            )
            if old is None:
                state.update(a=submitted_number, h1=checkpoint.committed_hwm)
                path.write_text(json.dumps(state), encoding="utf-8")
            else:
                assert (
                    connection.execute(
                        "SELECT count(*) FROM invoices WHERE ksef_number=?", (state["a"],)
                    ).fetchone()[0]
                    == 1
                )
                assert _date(checkpoint.committed_hwm) > _date(state["h1"])
            diagnostic(stage="ready", path=Path("metadata-live-diagnostic.json"))
            Path(phase + "-evidence.json").write_text(
                json.dumps(
                    {
                        "phase": phase,
                        "complete": True,
                        "hwm": checkpoint.committed_hwm,
                        "generation": checkpoint.generation_id,
                        "revision": checkpoint.revision,
                    }
                ),
                encoding="utf-8",
            )
        finally:
            connection.close()
    verify()


if __name__ == "__main__":
    try:
        run(sys.argv[1])
    except BaseException as error:
        diagnostic(error=error, path=Path("metadata-live-diagnostic.json"))
        raise
