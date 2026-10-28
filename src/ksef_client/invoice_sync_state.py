"""Immutable metadata synchronization state and pure, CAS-ready transitions.

Explicit JSON contains private filters and cursors. It is persistence data,
never a diagnostic representation or an authorization credential.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

from . import models as m
from ._json_bounds import check_json_structure
from .exceptions import (
    KsefInvalidSyncCheckpointError,
    KsefSyncDataConflictError,
    KsefSyncError,
    KsefSyncLimitError,
    KsefSyncStateError,
    KsefSyncStoreError,
)
from .invoice_search import (
    MAX_CURSOR_BYTES,
    _check_retained_filter_fields,
    _date,
    _json_object,
    _reject_constant,
    _same_json,
)
from .pagination import validate_page_size

MAX_CHECKPOINT_BYTES = 4 * 1024 * 1024
MAX_QUERY_BYTES = 128 * 1024
MAX_PAGE_BYTES = 16 * 1024 * 1024
MAX_REVISION = 2**63 - 1
_STAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.([0-9]+))?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_HEX = re.compile(r"[0-9a-f]{64}")


def utc_timestamp(value: str) -> str:
    """Canonical UTC, retaining every fractional digit (including API ticks)."""
    if type(value) is not str or len(value) > 128:
        raise ValueError("A timestamp with an explicit timezone is required")
    match = _STAMP.fullmatch(value)
    if match is None:
        raise ValueError("A timestamp with an explicit timezone is required")
    parsed, _ = _date(value)
    fraction = (match.group(1) or "").rstrip("0")
    prefix = f"{parsed.year:04d}-" + parsed.strftime("%m-%dT%H:%M:%S")
    return prefix + ("." + fraction if fraction else "") + "Z"


def _walk(
    value: Any,
    *,
    max_depth: int = 16,
    max_nodes: int = 50_000,
    max_chars: int | None = None,
) -> None:
    pending = [(value, 0)]
    nodes = characters = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > max_depth or nodes > max_nodes:
            raise ValueError("JSON structure exceeds bounds")
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError("JSON object keys must be strings")
            if len(item) + nodes > max_nodes:
                raise ValueError("JSON structure exceeds bounds")
            characters += sum(len(key) for key in item)
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) in (list, tuple):
            if len(item) + nodes > max_nodes:
                raise ValueError("JSON structure exceeds bounds")
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in (str, int, float, bool):
            raise ValueError("Unsupported JSON value")
        elif type(item) is str:
            characters += len(item)
        elif type(item) is float and not math.isfinite(item):
            raise ValueError("Non-finite JSON number")
        if max_chars is not None and characters > max_chars:
            raise _JsonSizeLimit("JSON size exceeds bounds")


class _JsonSizeLimit(ValueError):
    pass


def canonical_json(value: Any, limit: int, *, page: bool = False) -> bytes:
    _walk(value, max_nodes=1_000_000 if page else 50_000, max_chars=limit)
    encoder = json.JSONEncoder(
        sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    result = bytearray()
    for piece in encoder.iterencode(value):
        encoded = piece.encode("ascii")
        if len(result) + len(encoded) > limit:
            raise _JsonSizeLimit("JSON size exceeds bounds")
        result.extend(encoded)
    return bytes(result)


def _loads(raw: str | bytes) -> Any:
    return json.loads(raw, object_pairs_hook=_json_object, parse_constant=_reject_constant)


def _identifier(value: Any, limit: int) -> None:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
    ):
        raise ValueError("Invalid synchronization identifier")


def _uuid(value: Any) -> None:
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError("Invalid synchronization UUID")


def _execution_parameters(page_size: int, window_days: int) -> None:
    validate_page_size(page_size)
    if type(window_days) is not int or not 1 <= window_days <= 100:
        raise ValueError("window_days must be an integer from 1 to 100")


@dataclass(frozen=True)
class InvoiceSyncScope:
    namespace: str = field(repr=False)
    environment: str = field(repr=False)
    context_key: str = field(repr=False)
    sync_key: str = field(repr=False)
    stream_id: str

    def __post_init__(self) -> None:
        for value, limit in ((self.namespace, 256), (self.context_key, 4096), (self.sync_key, 256)):
            _identifier(value, limit)
        for value in (self.environment, self.stream_id):
            if type(value) is not str or _HEX.fullmatch(value) is None:
                raise ValueError("Invalid synchronization fingerprint")

    def to_dict(self) -> dict[str, str]:
        return {
            name: getattr(self, name)
            for name in ("namespace", "environment", "context_key", "sync_key", "stream_id")
        }


def canonical_spec(query: m.InvoiceQueryFilters) -> dict[str, Any]:
    if not isinstance(query, m.InvoiceQueryFilters):
        raise TypeError("Synchronization requires typed InvoiceQueryFilters")
    value = query.to_dict()
    canonical_json(value, MAX_QUERY_BYTES)
    dr = value["dateRange"]
    if (
        dr.get("dateType") != "PermanentStorage"
        or dr.get("to") is not None
        or dr.get("restrictToPermanentStorageHwmDate") is not True
        or value.get("subjectType") not in {role.value for role in m.InvoiceQuerySubjectType}
    ):
        raise ValueError("Sync requires an open, HWM-restricted PermanentStorage query")
    dr["from"] = utc_timestamp(dr["from"])
    restored = m.InvoiceQueryFilters.from_dict(value).to_dict()
    _check_retained_filter_fields(value, restored)
    canonical_json(restored, MAX_QUERY_BYTES)
    return {"semantics_version": 1, "query": restored}


def spec_fingerprint(spec: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(spec, MAX_QUERY_BYTES + 128)).hexdigest()


def _validate_checkpoint(data: Any) -> None:
    if type(data) is not dict or set(data) != {
        "kind",
        "version",
        "scope",
        "spec",
        "generation_id",
        "revision",
        "committed_hwm",
        "phase",
        "active",
        "last_commit_id",
    }:
        raise ValueError("Invalid checkpoint envelope")
    if (
        data["kind"] != "invoice-sync-stream"
        or type(data["version"]) is not int
        or data["version"] != 1
    ):
        raise ValueError("Unsupported checkpoint version")
    if type(data["scope"]) is not dict:
        raise ValueError("Invalid checkpoint scope")
    scope = InvoiceSyncScope(**data["scope"])
    spec = data["spec"]
    if (
        type(spec) is not dict
        or set(spec) != {"semantics_version", "query"}
        or type(spec["semantics_version"]) is not int
        or spec["semantics_version"] != 1
    ):
        raise ValueError("Invalid stream specification")
    canonical_json(spec["query"], MAX_QUERY_BYTES)
    normalized = canonical_spec(m.InvoiceQueryFilters.from_dict(spec["query"]))
    if not _same_json(normalized, spec) or spec_fingerprint(spec) != scope.stream_id:
        raise ValueError("Incompatible stream specification")
    _uuid(data["generation_id"])
    _uuid(data["last_commit_id"])
    if type(data["revision"]) is not int or not 1 <= data["revision"] <= MAX_REVISION:
        raise ValueError("Invalid checkpoint revision")
    initial = spec["query"]["dateRange"]["from"]
    hwm = data["committed_hwm"]
    if hwm is not None and _date(utc_timestamp(hwm)) < _date(initial):
        raise ValueError("Checkpoint HWM precedes history")
    active = data["active"]
    if data["phase"] == "idle":
        if active is not None or hwm is None:
            raise ValueError("Invalid idle checkpoint")
    elif data["phase"] == "active":
        if type(active) is not dict or set(active) != {
            "cycle_id",
            "from",
            "cycle_to",
            "page_size",
            "window_days",
            "cursor",
        }:
            raise ValueError("Invalid active checkpoint")
        _uuid(active["cycle_id"])
        _execution_parameters(active["page_size"], active["window_days"])
        low, high = utc_timestamp(active["from"]), utc_timestamp(active["cycle_to"])
        if _date(low) != _date(hwm or initial) or _date(high) < _date(low):
            raise ValueError("Invalid scan bounds")
        cursor = active["cursor"]
        if cursor is not None and (
            type(cursor) is not str or len(cursor) > MAX_CURSOR_BYTES or not cursor.isascii()
        ):
            raise ValueError("Invalid cursor envelope")
    else:
        raise ValueError("Invalid checkpoint phase")


@dataclass(frozen=True)
class _CheckpointSummary:
    scope: InvoiceSyncScope
    generation_id: str
    revision: int
    committed_hwm: str | None
    phase: str
    last_commit_id: str


@dataclass(frozen=True, repr=False)
class InvoiceSyncCheckpoint:
    _snapshot: bytes
    _summary: _CheckpointSummary = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            if type(self._snapshot) is not bytes:
                raise KsefInvalidSyncCheckpointError("invalid_checkpoint")
            if len(self._snapshot) > MAX_CHECKPOINT_BYTES:
                raise KsefInvalidSyncCheckpointError("checkpoint_size_limit")
            check_json_structure(self._snapshot, max_nodes=100_000, max_depth=18)
            data = _loads(self._snapshot)
            _walk(data, max_chars=MAX_CHECKPOINT_BYTES)
            _validate_checkpoint(data)
            raw = canonical_json(data, MAX_CHECKPOINT_BYTES)
            object.__setattr__(self, "_snapshot", raw)
            object.__setattr__(
                self,
                "_summary",
                _CheckpointSummary(
                    InvoiceSyncScope(**data["scope"]),
                    data["generation_id"],
                    data["revision"],
                    data["committed_hwm"],
                    data["phase"],
                    data["last_commit_id"],
                ),
            )
        except _JsonSizeLimit:
            raise KsefInvalidSyncCheckpointError("checkpoint_size_limit") from None
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
            raise KsefInvalidSyncCheckpointError("invalid_checkpoint") from None

    def __repr__(self) -> str:
        return f"InvoiceSyncCheckpoint(phase={self.phase!r}, revision={self.revision})"

    @classmethod
    def from_json(cls, value: str | bytes) -> InvoiceSyncCheckpoint:
        if type(value) not in (str, bytes):
            raise KsefInvalidSyncCheckpointError("invalid_checkpoint")
        if len(value) > MAX_CHECKPOINT_BYTES:
            raise KsefInvalidSyncCheckpointError("checkpoint_size_limit")
        try:
            return cls(value.encode("utf-8") if isinstance(value, str) else value)
        except UnicodeError:
            raise KsefInvalidSyncCheckpointError("invalid_checkpoint") from None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> InvoiceSyncCheckpoint:
        try:
            raw = canonical_json(value, MAX_CHECKPOINT_BYTES)
        except _JsonSizeLimit:
            raise KsefInvalidSyncCheckpointError("checkpoint_size_limit") from None
        except (ValueError, TypeError, RecursionError, OverflowError):
            raise KsefInvalidSyncCheckpointError("invalid_checkpoint") from None
        return cls(raw)

    def to_json(self) -> str:
        return self._snapshot.decode("ascii")

    def to_dict(self) -> dict[str, Any]:
        return _loads(self._snapshot)

    @property
    def scope(self) -> InvoiceSyncScope:
        return self._summary.scope

    @property
    def spec(self) -> dict[str, Any]:
        return self.to_dict()["spec"]

    @property
    def generation_id(self) -> str:
        return self._summary.generation_id

    @property
    def revision(self) -> int:
        return self._summary.revision

    @property
    def committed_hwm(self) -> str | None:
        return self._summary.committed_hwm

    @property
    def phase(self) -> str:
        return self._summary.phase

    @property
    def active(self) -> dict[str, Any] | None:
        return self.to_dict()["active"]

    @property
    def last_commit_id(self) -> str:
        return self._summary.last_commit_id


@dataclass(frozen=True)
class InvoiceSyncCommitReceipt:
    scope: InvoiceSyncScope
    generation_id: str = field(repr=False)
    revision: int
    commit_id: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.scope, InvoiceSyncScope):
            raise ValueError("Invalid receipt scope")
        _uuid(self.generation_id)
        _uuid(self.commit_id)
        if type(self.revision) is not int or not 1 <= self.revision <= MAX_REVISION:
            raise ValueError("Invalid receipt revision")


@dataclass(frozen=True, repr=False)
class InvoiceSyncBatch:
    _checkpoint: InvoiceSyncCheckpoint
    _observations: bytes
    expected_generation: str | None
    expected_revision: int | None
    is_page: bool
    _record_count: int | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return f"InvoiceSyncBatch(revision={self.next_checkpoint.revision}, is_page={self.is_page})"

    @property
    def scope(self) -> InvoiceSyncScope:
        return self._checkpoint.scope

    @property
    def next_checkpoint(self) -> InvoiceSyncCheckpoint:
        return self._checkpoint

    @property
    def observations(self) -> tuple[m.InvoiceMetadata, ...]:
        return tuple(m.InvoiceMetadata.from_dict(item) for item in self.observation_dicts)

    @property
    def observation_dicts(self) -> list[dict[str, Any]]:
        return _loads(self._observations)

    @property
    def observation_count(self) -> int:
        return self._record_count if self._record_count is not None else len(self.observation_dicts)

    @property
    def receipt(self) -> InvoiceSyncCommitReceipt:
        checkpoint = self._checkpoint
        return InvoiceSyncCommitReceipt(
            checkpoint.scope,
            checkpoint.generation_id,
            checkpoint.revision,
            checkpoint.last_commit_id,
        )

    def confirm(self, receipt: InvoiceSyncCommitReceipt) -> InvoiceSyncCheckpoint:
        if not isinstance(receipt, InvoiceSyncCommitReceipt) or receipt != self.receipt:
            raise KsefSyncStoreError(operation="commit", commit_outcome="unknown")
        return self._checkpoint


def make_batch(
    previous: InvoiceSyncCheckpoint | None,
    data: dict[str, Any],
    *,
    observations: tuple[m.InvoiceMetadata, ...] = (),
    is_page: bool = False,
    new_generation: bool = False,
) -> InvoiceSyncBatch:
    if previous is not None and (
        data.get("scope") != previous.scope.to_dict()
        or not _same_json(data.get("spec"), previous.spec)
    ):
        raise KsefSyncStateError("checkpoint_identity_mismatch")
    if previous is not None and previous.revision == MAX_REVISION:
        raise KsefSyncStateError("revision_exhausted")
    data["revision"] = previous.revision + 1 if previous else 1
    data["generation_id"] = (
        str(uuid4()) if new_generation or previous is None else previous.generation_id
    )
    data["last_commit_id"] = str(uuid4())
    try:
        raw = canonical_json(data, MAX_CHECKPOINT_BYTES)
    except ValueError:
        raise KsefSyncLimitError(
            limit_stage="checkpoint", limit_bytes=MAX_CHECKPOINT_BYTES
        ) from None
    checkpoint = InvoiceSyncCheckpoint(raw)
    values = []
    hashes: dict[str, str] = {}
    for invoice in observations:
        try:
            number = invoice.ksef_number
            _identifier(number, 256)
            assert isinstance(number, str)
            encoded = invoice.invoice_hash
            if type(encoded) is not str or len(encoded) != 44:
                raise ValueError("Invalid document hash")
            digest = base64.b64decode(encoded, validate=True)
            if len(digest) != 32:
                raise ValueError("Invalid document hash")
            canonical_hash = base64.b64encode(digest).decode("ascii")
            utc_timestamp(invoice.permanent_storage_date)  # type: ignore[arg-type]
            if number in hashes and hashes[number] != canonical_hash:
                raise KsefSyncDataConflictError("invoice_hash_conflict")
            hashes[number] = canonical_hash
            value = invoice.to_dict()
            value["invoiceHash"] = canonical_hash
            values.append(value)
        except (ValueError, TypeError, AttributeError, binascii.Error):
            raise KsefSyncError("invalid_metadata") from None
    try:
        snapshot = canonical_json(values, MAX_PAGE_BYTES, page=True)
    except _JsonSizeLimit:
        raise KsefSyncLimitError(limit_stage="page_snapshot", limit_bytes=MAX_PAGE_BYTES) from None
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise KsefSyncError("invalid_metadata") from None
    return InvoiceSyncBatch(
        checkpoint,
        snapshot,
        previous.generation_id if previous else None,
        previous.revision if previous else None,
        is_page,
        len(values),
    )


def active_state(from_: str, until: str, page_size: int, window_days: int) -> dict[str, Any]:
    _execution_parameters(page_size, window_days)
    until = utc_timestamp(until)
    if _date(until) < _date(from_):
        raise ValueError("Cycle end precedes its start")
    return {
        "cycle_id": str(uuid4()),
        "from": from_,
        "cycle_to": until,
        "page_size": page_size,
        "window_days": window_days,
        "cursor": None,
    }


def begin_cycle(
    scope: InvoiceSyncScope,
    spec: dict[str, Any],
    checkpoint: InvoiceSyncCheckpoint | None,
    *,
    until: str,
    page_size: int,
    window_days: int,
) -> InvoiceSyncBatch:
    if checkpoint is not None:
        if checkpoint.scope != scope or not _same_json(checkpoint.spec, spec):
            raise KsefSyncStateError("checkpoint_identity_mismatch")
        if checkpoint.phase != "idle":
            raise KsefSyncStateError("cycle_already_active")
        data = checkpoint.to_dict()
    else:
        data = {
            "kind": "invoice-sync-stream",
            "version": 1,
            "scope": scope.to_dict(),
            "spec": spec,
            "committed_hwm": None,
        }
    data["phase"] = "active"
    data["active"] = active_state(
        data["committed_hwm"] or spec["query"]["dateRange"]["from"], until, page_size, window_days
    )
    return make_batch(checkpoint, data)


def administrative_batch(
    checkpoint: InvoiceSyncCheckpoint,
    operation: str,
    *,
    reason: str,
    until: str | None = None,
    page_size: int | None = None,
    window_days: int | None = None,
) -> InvoiceSyncBatch:
    reasons = {
        "restart_active": {
            "cursor_invalid",
            "library_upgrade",
            "page_size_limit",
            "checkpoint_limit",
            "transient_pagination_retry",
            "operator_replay",
        },
        "restart_backfill": {"permissions_changed", "operator_replay"},
        "fence_after_restore": {"backup_restored"},
    }
    if operation not in reasons or reason not in reasons[operation]:
        raise ValueError("Invalid recovery reason for this operation")
    data = checkpoint.to_dict()
    if operation == "restart_active":
        active = data["active"]
        if active is None:
            raise KsefSyncStateError("cycle_not_active")
        data["active"] = active_state(
            active["from"],
            active["cycle_to"],
            active["page_size"] if page_size is None else page_size,
            active["window_days"] if window_days is None else window_days,
        )
    elif operation == "restart_backfill":
        if until is None or page_size is None or window_days is None:
            raise ValueError("Backfill requires bounds and execution parameters")
        data["committed_hwm"], data["phase"] = None, "active"
        data["active"] = active_state(
            data["spec"]["query"]["dateRange"]["from"], until, page_size, window_days
        )
    return make_batch(checkpoint, data, new_generation=operation != "restart_active")
