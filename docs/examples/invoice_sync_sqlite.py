"""Example adapter; production applications import the public SDK adapter directly."""

from ksef_client._sqlite_metadata import KEY, SCHEMA, _key  # noqa: F401
from ksef_client.sqlite_store import SQLiteInvoiceSyncStore as _Store


class SQLiteInvoiceSyncStore(_Store):
    def __init__(self, connection, *, enqueue_xml=False, xml_storage_id="legacy-example"):
        super().__init__(
            connection,
            enqueue_xml=enqueue_xml,
            xml_storage_id=xml_storage_id if enqueue_xml else None,
        )
