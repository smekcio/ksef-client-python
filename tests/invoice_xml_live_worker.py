"""Installed-wheel TEST XML synchronization, split across fresh interpreters."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ksef_client import (  # noqa: E402
    FileInvoiceXmlStore,
    Ksef,
    KsefClientOptions,
    KsefIncompletePaginationError,
    RetryConfig,
    SQLiteInvoiceSyncStore,
    TokenCredentials,
)
from ksef_client import (  # noqa: E402
    models as m,
)
from ksef_client.request_control import request_control, wait_seconds  # noqa: E402
from tests.invoice_sync_live_worker import verify  # noqa: E402
from tests.test_e2e_token_flows import (  # noqa: E402
    _build_invoice_xml,
    _load_test_token_config,
)


def run(phase: str) -> None:
    verify()
    state_path = Path("state.json")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    config = _load_test_token_config()
    assert config.token
    options = KsefClientOptions(
        base_url=config.base_url,
        retry=RetryConfig(
            max_retries=5,
            retryable_post_paths=frozenset({"/invoices/query/metadata"}),
        ),
    )
    with (
        request_control(deadline=state["soft_deadline"]),
        Ksef.connect(
            options=options,
            credentials=TokenCredentials(config.token),
            context_type=config.context_type,
            context_value=config.context_value,
        ) as client,
    ):
        if phase == "metadata":
            with client.online_session() as session:
                result = session.send_invoice(
                    _build_invoice_xml(
                        seller_nip=config.context_value,
                        environment_name="xml-durable",
                    )
                ).wait(timeout=120)
            state["number"] = result.ksef_number
            state_path.write_text(json.dumps(state), encoding="utf-8")
        query = m.InvoiceQueryFilters(
            subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
            date_range=m.InvoiceQueryDateRange(
                date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
                from_=state["since"],
                restrict_to_permanent_storage_hwm_date=True,
            ),
            ksef_number=state["number"],
        )
        sync = client.invoices.sync_documents(
            namespace="wheel-xml-test", sync_key="xml", queries=[query]
        )
        with (
            FileInvoiceXmlStore("documents") as storage,
            SQLiteInvoiceSyncStore.open(
                "sync.db",
                enqueue_xml=True,
                xml_storage_id=storage.storage_id,
            ) as store,
        ):
            if phase == "metadata":
                # Wait for the new invoice to enter the metadata repository, then commit
                # its real page/checkpoint/job without making any XML request.
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
                    try:
                        found = any(item.ksef_number == state["number"] for item in scan)
                    except KsefIncompletePaginationError as error:
                        if error.reason_code != "hwm_before_start":
                            raise
                        found = False
                    if found:
                        sync.metadata.run_once(store, time_budget=120)
                        report = sync.describe(store)
                        if report.xml.pending == 1 and report.metadata_complete:
                            break
                    wait_seconds(30)
                assert report.xml.ready == 0 and not report.complete
            else:
                assert sync.describe(store).xml.pending == 1
                while True:
                    report_xml = sync.xml.run_once(store, storage, time_budget=120)
                    if report_xml.ready == 1:
                        break
                    wait_seconds(30)
                again = sync.xml.run_once(store, storage)
                assert again.ready == 1 and again.downloaded == 0 and again.claims == 0
                report = sync.describe(store)
                assert report.complete
                state["complete"] = True
                state_path.write_text(json.dumps(state), encoding="utf-8")
    verify()


if __name__ == "__main__":
    run(sys.argv[1])
