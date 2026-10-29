"""One restartable TEST synchronization. Set KSEF_NIP and KSEF_TOKEN first."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ksef_client import (
    FileInvoiceXmlStore,
    InvoiceDocumentReport,
    Ksef,
    KsefClientOptions,
    KsefEnvironment,
    RetryConfig,
    SQLiteInvoiceSyncStore,
    TokenCredentials,
)


def synchronize_once(
    directory: Path, *, since: str = "2024-01-01T00:00:00Z"
) -> InvoiceDocumentReport:
    options = KsefClientOptions(
        base_url=KsefEnvironment.TEST.value,
        retry=RetryConfig(retryable_post_paths=frozenset({"/invoices/query/metadata"})),
    )
    with (
        Ksef.connect(
            options=options,
            context_type="Nip",
            context_value=os.environ["KSEF_NIP"],
            credentials=TokenCredentials(os.environ["KSEF_TOKEN"]),
        ) as client,
        FileInvoiceXmlStore(directory / "xml") as storage,
        SQLiteInvoiceSyncStore.open(
            directory / "invoices.db",
            enqueue_xml=True,
            xml_storage_id=storage.storage_id,
        ) as store,
    ):
        sync = client.invoices.sync_documents(namespace="firma", sync_key="erp", since=since)
        return sync.run_once(store, storage, time_budget=600, raise_on_error=False)


def main() -> None:
    report = synchronize_once(Path("private"))
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    if (
        report.xml.blocked
        or report.xml.stop_reason == "authentication"
        or any(stream.status == "failed" for stream in report.metadata.streams)
    ):
        print("Sprawdź kody błędów w raporcie i usuń przyczynę przed ponowieniem.")
    elif report.complete:
        print("XML wszystkich odkrytych faktur jest gotowy. Zaplanuj następny cykl synchronizacji.")
    else:
        print("Postęp zapisany. Uruchom ponownie z tą samą bazą i katalogiem XML.")


if __name__ == "__main__":
    main()
