from __future__ import annotations

from dataclasses import replace
from typing import Any, cast
from uuid import uuid4

import pytest

from ksef_client import (
    InvoiceSyncCheckpoint,
    InvoiceSyncCommitReceipt,
    InvoiceSyncScope,
    KsefInvalidSyncCheckpointError,
    KsefSyncError,
    KsefSyncLimitError,
    KsefSyncStateError,
)
from ksef_client.invoice_sync_state import (
    MAX_CHECKPOINT_BYTES,
    MAX_QUERY_BYTES,
    MAX_REVISION,
    _walk,
    administrative_batch,
    canonical_json,
    canonical_spec,
    make_batch,
    utc_timestamp,
)
from tests.test_invoice_sync import H1, START, Server, make_sync, query, row


@pytest.fixture
def active():
    sync, http = make_sync(Server())
    try:
        yield sync.streams[0].begin_cycle(None, until=H1).next_checkpoint
    finally:
        http.close()


@pytest.mark.parametrize(
    "path,value",
    [
        (("kind",), "other"),
        (("version",), True),
        (("version",), 2),
        (("scope",), []),
        (("scope", "namespace"), ""),
        (("scope", "environment"), "a"),
        (("scope", "stream_id"), "0" * 64),
        (("scope", "extra"), "secret"),
        (("spec",), []),
        (("spec", "semantics_version"), True),
        (("spec", "query", "dateRange", "from"), "2024-01-01T01:00:00+01:00"),
        (("spec", "query", "unknown"), 1),
        (("spec", "query", "dateRange", "to"), H1),
        (("spec", "query", "dateRange", "dateType"), "Issue"),
        (("spec", "query", "dateRange", "restrictToPermanentStorageHwmDate"), 1),
        (("generation_id",), "not-uuid"),
        (("last_commit_id",), "bad"),
        (("revision",), True),
        (("revision",), 0),
        (("revision",), MAX_REVISION + 1),
        (("committed_hwm",), "2023-01-01T00:00:00Z"),
        (("phase",), "other"),
        (("phase",), "idle"),
        (("active",), None),
        (("active", "extra"), 1),
        (("active", "cycle_id"), "bad"),
        (("active", "from"), H1),
        (("active", "cycle_to"), "2023-01-01T00:00:00Z"),
        (("active", "page_size"), True),
        (("active", "window_days"), 0),
        (("active", "cursor"), 3),
        (("active", "cursor"), "\u0105"),
        pytest.param(("active", "cursor"), "x" * (2 * 1024 * 1024 + 1), id="oversized-cursor"),
        (("unexpected",), "payload"),
    ],
)
def test_untrusted_envelopes_rejected(active, path, value):
    data = active.to_dict()
    node = data
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    with pytest.raises(KsefInvalidSyncCheckpointError):
        InvoiceSyncCheckpoint.from_dict(data)


@pytest.mark.parametrize(
    "value",
    [
        "{}",
        "[]",
        "null",
        "{",
        b"\xff",
        '{"a":1,"a":2}',
        '{"a":NaN}',
        '{"a":Infinity}',
        pytest.param('"' + "x" * MAX_CHECKPOINT_BYTES, id="oversized-json"),
    ],
)
def test_checkpoint_json_is_bounded_and_strict(value):
    with pytest.raises(KsefInvalidSyncCheckpointError):
        InvoiceSyncCheckpoint.from_json(value)


def test_snapshots_are_deeply_immutable_and_private(active):
    invoice = replace(
        row(), third_subjects=[{"identifier": {"type": "Nip", "value": "private"}, "role": 1}]
    )
    batch = make_batch(active, active.to_dict(), observations=(invoice,), is_page=True)
    invoice.third_subjects[0]["identifier"]["value"] = "mutated"
    third = batch.observations[0].third_subjects
    assert third is not None
    third.clear()
    data = batch.next_checkpoint.to_dict()
    data["spec"]["query"]["dateRange"]["from"] = H1
    assert batch.observation_dicts[0]["thirdSubjects"][0]["identifier"]["value"] == "private"
    assert batch.next_checkpoint.spec["query"]["dateRange"]["from"] == START
    for text in (repr(active), repr(batch), repr(active.scope), repr(batch.receipt)):
        assert "private" not in text and "Nip:test" not in text and "tenant" not in text
    assert InvoiceSyncCheckpoint.from_json(active.to_json()) == active
    assert InvoiceSyncCheckpoint.from_dict(active.to_dict()) == active


@pytest.mark.parametrize("value", ["", "2024-01-01", "2024-01-01T00:00:00", True, "x" * 129])
def test_strict_timestamps(value):
    with pytest.raises(ValueError):
        utc_timestamp(value)


def test_fraction_offsets_and_legal_cursor_size(active):
    assert utc_timestamp("2024-01-01T01:00:00.1234567+01:00") == "2024-01-01T00:00:00.1234567Z"
    assert utc_timestamp("2024-01-01T00:00:00.1000000Z") == "2024-01-01T00:00:00.1Z"
    data = active.to_dict()
    data["active"]["cursor"] = "x" * (2 * 1024 * 1024)
    restored = InvoiceSyncCheckpoint.from_dict(data).active
    assert restored is not None and restored["cursor"] == data["active"]["cursor"]


def test_size_depth_nodes_and_unicode(active, monkeypatch):
    with pytest.raises(ValueError):
        _walk({1: "x"})
    with pytest.raises(ValueError):
        _walk({"a": object()})
    for value in ({"a": list(range(50000))}, list(range(50000))):
        with pytest.raises(ValueError):
            _walk(value)
    deep: Any = []
    for _ in range(17):
        deep = [deep]
    with pytest.raises(KsefInvalidSyncCheckpointError):
        InvoiceSyncCheckpoint.from_dict({"a": deep})
    with pytest.raises(ValueError):
        canonical_json({"a": "\u0105" * 10}, 30)
    assert len(canonical_json("a" * (MAX_QUERY_BYTES - 2), MAX_QUERY_BYTES)) == MAX_QUERY_BYTES
    with pytest.raises(ValueError):
        canonical_json("a" * (MAX_QUERY_BYTES - 1), MAX_QUERY_BYTES)
    monkeypatch.setattr("ksef_client.invoice_sync_state.MAX_CHECKPOINT_BYTES", 1)
    with pytest.raises(KsefSyncLimitError) as caught:
        make_batch(active, active.to_dict())
    assert caught.value.limit_stage == "checkpoint"


@pytest.mark.parametrize(
    "invoice",
    [row(hash_=None), row(hash_="invalid"), row(hash_="a" * 44), row(number=""), row(date=None)],
)
def test_required_metadata_integrity(active, invoice):
    with pytest.raises(KsefSyncError) as caught:
        make_batch(active, active.to_dict(), observations=(invoice,), is_page=True)
    assert caught.value.reason_code == "invalid_metadata"


def test_page_snapshot_limit_and_revision_overflow(active, monkeypatch):
    monkeypatch.setattr("ksef_client.invoice_sync_state.MAX_PAGE_BYTES", 5)
    with pytest.raises(KsefSyncLimitError) as caught:
        make_batch(active, active.to_dict(), observations=(row(),), is_page=True)
    assert caught.value.limit_stage == "page_snapshot"
    data = active.to_dict()
    data["revision"] = MAX_REVISION
    full = InvoiceSyncCheckpoint.from_dict(data)
    with pytest.raises(KsefSyncStateError):
        make_batch(full, full.to_dict())


def test_receipt_scope_and_recovery_validation(active):
    receipt = InvoiceSyncCommitReceipt(
        active.scope, active.generation_id, active.revision, str(uuid4())
    )
    assert receipt.scope == active.scope
    for changes in ({"scope": None}, {"revision": True}, {"revision": 0}, {"commit_id": "bad"}):
        with pytest.raises(ValueError):
            replace(receipt, **changes)
    with pytest.raises(ValueError):
        InvoiceSyncScope("n", "bad", "c", "s", "0" * 64)
    for operation, reason in (
        ("invalid", "operator_replay"),
        ("restart_active", "backup_restored"),
    ):
        with pytest.raises(ValueError):
            administrative_batch(active, operation, reason=reason)
    with pytest.raises(ValueError):
        administrative_batch(active, "restart_backfill", reason="operator_replay")
    idle = active.to_dict()
    idle.update(phase="idle", active=None, committed_hwm=H1)
    idle_cp = InvoiceSyncCheckpoint.from_dict(idle)
    with pytest.raises(KsefSyncStateError):
        administrative_batch(idle_cp, "restart_active", reason="operator_replay")


def test_spec_validation_and_oversized_query():
    with pytest.raises(TypeError):
        canonical_spec(cast(Any, {}))
    with pytest.raises(ValueError):
        canonical_spec(replace(query(), invoice_number="x" * MAX_QUERY_BYTES))
    data = query().to_dict()
    data["subjectType"] = "Unknown"
    with pytest.raises(ValueError):
        canonical_spec(type(query()).from_dict(data))
