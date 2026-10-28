"""Cooperative, restartable synchronization of invoice metadata, per role."""

from __future__ import annotations

import asyncio
import math
import time
from collections import deque
from collections.abc import Callable, Generator, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from . import models as m
from .exceptions import (
    ErrorCode,
    KsefError,
    KsefHttpError,
    KsefInvalidSyncCheckpointError,
    KsefPaginationError,
    KsefResponseLimitError,
    KsefSyncConflictError,
    KsefSyncDataConflictError,
    KsefSyncError,
    KsefSyncLimitError,
    KsefSyncRunError,
    KsefSyncStoreError,
)
from .invoice_search import InvoiceMetadataObservationPage, _date, _same_json
from .invoice_sync_state import (
    InvoiceSyncBatch,
    InvoiceSyncCheckpoint,
    InvoiceSyncCommitReceipt,
    InvoiceSyncScope,
    _execution_parameters,
    administrative_batch,
    begin_cycle,
    canonical_spec,
    make_batch,
    spec_fingerprint,
)
from .rate_limiting import (
    CancellationSignal,
    KsefRateLimitWaitTimeout,
    KsefRequestCancelledError,
)
from .request_control import current_request_control, request_control


class InvoiceSyncStore(Protocol):
    def load(self, scope: InvoiceSyncScope) -> InvoiceSyncCheckpoint | None: ...
    def commit(self, batch: InvoiceSyncBatch) -> InvoiceSyncCommitReceipt: ...


class AsyncInvoiceSyncStore(Protocol):
    async def load(self, scope: InvoiceSyncScope) -> InvoiceSyncCheckpoint | None: ...
    async def commit(self, batch: InvoiceSyncBatch) -> InvoiceSyncCommitReceipt: ...


@dataclass(frozen=True)
class InvoiceSyncCoverage:
    from_: str
    to: str
    stream_ids: tuple[str, ...]


@dataclass(frozen=True)
class InvoiceSyncStreamResult:
    scope: InvoiceSyncScope
    status: str
    coverage: InvoiceSyncCoverage | None = None
    stop_reason: str | None = None
    pages_committed: int = 0
    records_delivered: int = 0
    error_code: ErrorCode | None = None
    observed_generation: str | None = field(default=None, repr=False)
    observed_revision: int | None = None
    observed_at: str | None = None
    new_stream: bool = False
    original_error: KsefError | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stream_id": self.scope.stream_id,
            "status": self.status,
            "stop_reason": self.stop_reason,
            "pages_committed": self.pages_committed,
            "records_delivered": self.records_delivered,
            "error_code": self.error_code.value if self.error_code else None,
            "observed_generation": self.observed_generation,
            "observed_revision": self.observed_revision,
            "observed_at": self.observed_at,
            "new_stream": self.new_stream,
        }


@dataclass(frozen=True)
class InvoiceSyncReport:
    streams: tuple[InvoiceSyncStreamResult, ...]
    common_coverage: InvoiceSyncCoverage | None

    @property
    def complete(self) -> bool:
        return bool(self.streams) and all(item.status == "completed" for item in self.streams)

    @property
    def new_streams(self) -> tuple[InvoiceSyncScope, ...]:
        return tuple(item.scope for item in self.streams if item.new_stream)

    def to_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "streams": [item.to_dict() for item in self.streams],
            "common_coverage": None
            if self.common_coverage is None
            else {
                "from": self.common_coverage.from_,
                "to": self.common_coverage.to,
                "stream_ids": list(self.common_coverage.stream_ids),
            },
        }


def _coverage(checkpoint: InvoiceSyncCheckpoint | None) -> InvoiceSyncCoverage | None:
    if checkpoint is None or checkpoint.committed_hwm is None:
        return None
    return InvoiceSyncCoverage(
        checkpoint.spec["query"]["dateRange"]["from"],
        checkpoint.committed_hwm,
        (checkpoint.scope.stream_id,),
    )


def _report(results: Sequence[InvoiceSyncStreamResult]) -> InvoiceSyncReport:
    common = None
    if results and all(item.coverage is not None for item in results):
        covers = [item.coverage for item in results if item.coverage is not None]
        low = max((cover.from_ for cover in covers), key=_date)
        high = min((cover.to for cover in covers), key=_date)
        if _date(low) <= _date(high):
            common = InvoiceSyncCoverage(low, high, tuple(item.scope.stream_id for item in results))
    return InvoiceSyncReport(tuple(results), common)


class InvoiceSyncStream:
    def __init__(
        self,
        scope: InvoiceSyncScope,
        query: m.InvoiceQueryFilters,
        search_factory: Callable[..., Any],
        *,
        page_size: int,
        window_days: int,
    ) -> None:
        _execution_parameters(page_size, window_days)
        self._scope, self._spec = scope, canonical_spec(query)
        if spec_fingerprint(self._spec) != scope.stream_id:
            raise ValueError("Stream specification does not match its scope")
        self._search_factory = search_factory
        self._page_size, self._window_days = page_size, window_days

    @property
    def scope(self) -> InvoiceSyncScope:
        return self._scope

    def _validate(self, checkpoint: InvoiceSyncCheckpoint, *, cursor: bool = True) -> None:
        if not isinstance(checkpoint, InvoiceSyncCheckpoint):
            raise KsefInvalidSyncCheckpointError("checkpoint_required")
        if checkpoint.scope != self.scope or not _same_json(checkpoint.spec, self._spec):
            raise KsefInvalidSyncCheckpointError("checkpoint_identity_mismatch")
        if cursor and checkpoint.active is not None:
            self._search(checkpoint).validate_cursor(checkpoint.active["cursor"])

    def _search(self, checkpoint: InvoiceSyncCheckpoint) -> Any:
        active = checkpoint.active
        assert active is not None
        query = checkpoint.spec["query"]
        query["dateRange"].update({"from": active["from"], "to": active["cycle_to"]})
        search = self._search_factory(
            m.InvoiceQueryFilters.from_dict(query),
            context_key=self.scope.context_key,
            page_size=active["page_size"],
            window_days=active["window_days"],
            sort_order="Asc",
            access_token=None,
        )
        identity = search.identity
        if (
            identity.environment != self.scope.environment
            or identity.context_key != self.scope.context_key
        ):
            raise KsefInvalidSyncCheckpointError("source_identity_mismatch")
        return search

    def begin_cycle(
        self, checkpoint: InvoiceSyncCheckpoint | None, *, until: str
    ) -> InvoiceSyncBatch:
        if checkpoint is not None:
            self._validate(checkpoint)
        return begin_cycle(
            self.scope,
            self._spec,
            checkpoint,
            until=until,
            page_size=self._page_size,
            window_days=self._window_days,
        )

    def _advance(
        self, checkpoint: InvoiceSyncCheckpoint, page: InvoiceMetadataObservationPage
    ) -> InvoiceSyncBatch:
        data = checkpoint.to_dict()
        active = data["active"]
        if page.next_cursor is None:
            hwm = page.permanent_storage_hwm_date
            try:
                if hwm is None or not _date(active["from"]) <= _date(hwm) <= _date(
                    active["cycle_to"]
                ):
                    raise ValueError("Invalid completed HWM")
            except (ValueError, TypeError):
                raise KsefSyncError("invalid_hwm") from None
            data.update(committed_hwm=hwm, phase="idle", active=None)
        else:
            active["cursor"] = page.next_cursor
        batch = make_batch(checkpoint, data, observations=page.observations, is_page=True)
        self._validate(batch.next_checkpoint)
        return batch

    def next_batch(self, checkpoint: InvoiceSyncCheckpoint) -> InvoiceSyncBatch | None:
        self._validate(checkpoint)
        if checkpoint.active is None:
            return None
        try:
            page = self._search(checkpoint).observation_page(checkpoint.active["cursor"])
        except KsefResponseLimitError as error:
            raise KsefSyncLimitError(
                limit_stage="response_body",
                limit_bytes=error.limit_bytes,
                observed_bytes=error.observed_bytes,
            ) from None
        return self._advance(checkpoint, page)

    def restart_active(
        self,
        checkpoint: InvoiceSyncCheckpoint,
        *,
        reason: str,
        page_size: int | None = None,
        window_days: int | None = None,
    ) -> InvoiceSyncBatch:
        self._validate(checkpoint, cursor=False)
        return administrative_batch(
            checkpoint,
            "restart_active",
            reason=reason,
            page_size=page_size,
            window_days=window_days,
        )

    def restart_backfill(
        self, checkpoint: InvoiceSyncCheckpoint, *, until: str, reason: str
    ) -> InvoiceSyncBatch:
        self._validate(checkpoint, cursor=False)
        return administrative_batch(
            checkpoint,
            "restart_backfill",
            reason=reason,
            until=until,
            page_size=self._page_size,
            window_days=self._window_days,
        )

    def fence_after_restore(
        self, checkpoint: InvoiceSyncCheckpoint, *, reason: str
    ) -> InvoiceSyncBatch:
        self._validate(checkpoint)
        return administrative_batch(checkpoint, "fence_after_restore", reason=reason)


class AsyncInvoiceSyncStream(InvoiceSyncStream):
    async def next_batch(self, checkpoint: InvoiceSyncCheckpoint) -> InvoiceSyncBatch | None:  # type: ignore[override]
        self._validate(checkpoint)
        if checkpoint.active is None:
            return None
        try:
            page = await self._search(checkpoint).observation_page(checkpoint.active["cursor"])
        except KsefResponseLimitError as error:
            raise KsefSyncLimitError(
                limit_stage="response_body",
                limit_bytes=error.limit_bytes,
                observed_bytes=error.observed_bytes,
            ) from None
        return self._advance(checkpoint, page)


def _positive(value: Any, name: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be a positive finite number")
    try:
        result = float(value)
    except OverflowError:
        raise ValueError(f"{name} must be a positive finite number") from None
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"{name} must be a positive finite number")
    return result


@dataclass
class _Progress:
    stream: InvoiceSyncStream
    checkpoint: InvoiceSyncCheckpoint | None = None
    pages: int = 0
    records: int = 0
    new: bool = False
    observed_at: str | None = None
    status: str = "partial"
    reason: str | None = None
    error: KsefError | None = None
    trustworthy: bool = True

    def result(self) -> InvoiceSyncStreamResult:
        cp = self.checkpoint
        return InvoiceSyncStreamResult(
            scope=self.stream.scope,
            status=self.status,
            coverage=_coverage(cp) if self.trustworthy else None,
            stop_reason=self.reason,
            pages_committed=self.pages,
            records_delivered=self.records,
            error_code=self.error.code if self.error else None,
            observed_generation=cp.generation_id if cp else None,
            observed_revision=cp.revision if cp else None,
            observed_at=self.observed_at,
            new_stream=self.new,
            original_error=self.error,
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_EXPECTED = (KsefSyncError, KsefHttpError, KsefPaginationError)
_STORE_ERRORS = (
    KsefSyncStoreError,
    KsefSyncConflictError,
    KsefSyncDataConflictError,
    KsefInvalidSyncCheckpointError,
    KsefRateLimitWaitTimeout,
    KsefRequestCancelledError,
)


class _InvoiceSyncBase:
    def __init__(self, streams: Sequence[InvoiceSyncStream]) -> None:
        if not 1 <= len(streams) <= 4 or any(not isinstance(s, InvoiceSyncStream) for s in streams):
            raise ValueError("Sync requires one to four streams")
        roles = [stream._spec["query"]["subjectType"] for stream in streams]
        if len(set(roles)) != len(roles):
            raise ValueError("Sync requires unique roles")
        self._streams = tuple(streams)

    @property
    def streams(self) -> tuple[InvoiceSyncStream, ...]:
        return self._streams

    def describe(
        self,
        checkpoints: Sequence[InvoiceSyncCheckpoint | None]
        | Mapping[InvoiceSyncScope, InvoiceSyncCheckpoint | None],
    ) -> InvoiceSyncReport:
        values = (
            [checkpoints.get(stream.scope) for stream in self.streams]
            if isinstance(checkpoints, Mapping)
            else list(checkpoints)
        )
        if len(values) != len(self.streams):
            raise ValueError("One checkpoint per selected stream is required")
        results = []
        for stream, checkpoint in zip(self.streams, values, strict=True):
            if checkpoint is not None:
                stream._validate(checkpoint)
            progress = _Progress(
                stream,
                checkpoint,
                observed_at=_now(),
                status="completed" if checkpoint and checkpoint.phase == "idle" else "partial",
            )
            results.append(progress.result())
        return _report(results)

    def _run(
        self,
        *,
        time_budget: float,
        max_pages_per_stream: int | None,
        step_time_budget: float | None,
        cancellation: CancellationSignal | None,
        raise_on_error: bool,
    ) -> Generator[tuple[str, Any], Any, InvoiceSyncReport]:
        budget = _positive(time_budget, "time_budget")
        step = (
            _positive(step_time_budget, "step_time_budget")
            if step_time_budget is not None
            else (budget / len(self.streams))
        )
        if max_pages_per_stream is not None and (
            type(max_pages_per_stream) is not int or max_pages_per_stream <= 0
        ):
            raise ValueError("max_pages_per_stream must be a positive integer")
        if type(raise_on_error) is not bool:
            raise TypeError("raise_on_error must be bool")
        parent = current_request_control()
        global_end, cycle_to = time.monotonic() + budget, _now()
        progresses = [_Progress(stream) for stream in self.streams]

        def classify(error: KsefRateLimitWaitTimeout, step_end: float) -> str:
            if (
                parent is not None
                and parent.deadline is not None
                and (parent.deadline <= min(global_end, step_end))
            ):
                raise error
            # Only an expired SDK deadline is a normal partial result.
            now = time.monotonic()
            if global_end <= step_end and now >= global_end:
                return "time_budget"
            if now >= step_end:
                return "step_time_budget"
            raise error

        def failed(progress: _Progress, error: KsefError) -> None:
            if isinstance(error, KsefSyncStoreError) and error.failure_scope == "store":
                raise error from None
            progress.status, progress.error = "failed", error
            progress.reason = getattr(error, "reason_code", None) or error.code.value
            if isinstance(error, (KsefSyncConflictError, KsefSyncStoreError)):
                progress.trustworthy = False

        # All loaded envelopes/cursors are checked before the first network read.
        for progress in progresses:
            end = time.monotonic() + step
            try:
                with request_control(
                    deadline=min(global_end, end), cancellation=cancellation
                ) as control:
                    cp = yield ("load", progress.stream.scope)
                    control.check()
                    if cp is not None:
                        if not isinstance(cp, InvoiceSyncCheckpoint):
                            raise KsefInvalidSyncCheckpointError("invalid_store_checkpoint")
                        if cp.scope != progress.stream.scope:
                            raise KsefSyncStoreError(operation="load", failure_scope="store")
                        progress.checkpoint = cp
                        progress.stream._validate(cp)
                    progress.new = cp is None
                    progress.observed_at = _now()
            except KsefRateLimitWaitTimeout as error:
                progress.reason = classify(error, end)
            except _EXPECTED as error:
                failed(progress, error)
        queue = deque(p for p in progresses if p.error is None and p.reason is None)
        while queue:
            progress = queue.popleft()
            end = time.monotonic() + step
            try:
                with request_control(
                    deadline=min(global_end, end), cancellation=cancellation
                ) as control:
                    cp = progress.checkpoint
                    if cp is None or cp.phase == "idle":
                        batch = progress.stream.begin_cycle(cp, until=cycle_to)
                    else:
                        batch = yield ("next", (progress.stream, cp))
                        assert isinstance(batch, InvoiceSyncBatch)
                    control.check()
                    receipt = yield ("commit", batch)
                    progress.checkpoint = batch.confirm(receipt)
                    progress.observed_at = _now()
                    if batch.is_page:
                        progress.pages += 1
                        progress.records += len(batch.observation_dicts)
                    if progress.checkpoint.phase == "idle":
                        progress.status = "completed"
                    elif (
                        max_pages_per_stream is not None and progress.pages >= max_pages_per_stream
                    ):
                        progress.reason = "work_limit"
                    else:
                        queue.append(progress)
                    # A begun commit is collected before propagating cancellation/deadlines.
                    control.check()
            except KsefRateLimitWaitTimeout as error:
                reason = classify(error, end)
                if progress.status != "completed":
                    progress.reason = reason
                queue = deque(p for p in queue if p is not progress)
            except _EXPECTED as error:
                failed(progress, error)
                queue = deque(p for p in queue if p is not progress)
        report = _report([progress.result() for progress in progresses])
        if raise_on_error and any(item.status == "failed" for item in report.streams):
            raise KsefSyncRunError(report) from None
        return report


class InvoiceSync(_InvoiceSyncBase):
    def run_once(
        self,
        store: InvoiceSyncStore,
        *,
        time_budget: float = 600,
        max_pages_per_stream: int | None = None,
        step_time_budget: float | None = None,
        cancellation: CancellationSignal | None = None,
        raise_on_error: bool = True,
    ) -> InvoiceSyncReport:
        runner = self._run(
            time_budget=time_budget,
            max_pages_per_stream=max_pages_per_stream,
            step_time_budget=step_time_budget,
            cancellation=cancellation,
            raise_on_error=raise_on_error,
        )
        return _drive(runner, store)


def _store_failure(error: Exception, operation: str) -> KsefSyncStoreError:
    return KsefSyncStoreError(
        operation=operation,
        commit_outcome="unknown" if operation == "commit" else "not_started",
        failure_scope="store",
        original_error=error,
    )


def _drive(
    runner: Generator[tuple[str, Any], Any, InvoiceSyncReport], store: InvoiceSyncStore
) -> InvoiceSyncReport:
    value, error = None, None
    try:
        while True:
            try:
                operation, argument = runner.throw(error) if error else runner.send(value)
            except StopIteration as done:
                return done.value
            error = None
            try:
                if operation == "next":
                    stream, checkpoint = argument
                    value = stream.next_batch(checkpoint)
                else:
                    try:
                        value = getattr(store, operation)(argument)
                    except _STORE_ERRORS as known:
                        raise known from None
                    except asyncio.CancelledError:
                        raise
                    except Exception as original:
                        raise _store_failure(original, operation) from None
            except BaseException as caught:
                error = caught
    finally:
        runner.close()


async def _commit_and_drain(
    store: AsyncInvoiceSyncStore, batch: InvoiceSyncBatch
) -> InvoiceSyncCommitReceipt:
    task = asyncio.ensure_future(store.commit(batch))
    cancelled = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            cancelled = error
        except Exception:
            break
    if cancelled is not None:
        # Retrieve the result/exception even after repeated outer cancellation.
        with suppress(BaseException):
            task.result()
        raise cancelled
    return task.result()


class AsyncInvoiceSync(_InvoiceSyncBase):
    async def run_once(
        self,
        store: AsyncInvoiceSyncStore,
        *,
        time_budget: float = 600,
        max_pages_per_stream: int | None = None,
        step_time_budget: float | None = None,
        cancellation: CancellationSignal | None = None,
        raise_on_error: bool = True,
    ) -> InvoiceSyncReport:
        runner = self._run(
            time_budget=time_budget,
            max_pages_per_stream=max_pages_per_stream,
            step_time_budget=step_time_budget,
            cancellation=cancellation,
            raise_on_error=raise_on_error,
        )
        value, error = None, None
        try:
            while True:
                try:
                    operation, argument = runner.throw(error) if error else runner.send(value)
                except StopIteration as done:
                    return done.value
                error = None
                try:
                    if operation == "next":
                        stream, checkpoint = argument
                        value = await stream.next_batch(checkpoint)
                    else:
                        try:
                            value = (
                                await _commit_and_drain(store, argument)
                                if operation == "commit"
                                else await store.load(argument)
                            )
                        except _STORE_ERRORS as known:
                            raise known from None
                        except asyncio.CancelledError:
                            raise
                        except Exception as original:
                            raise _store_failure(original, operation) from None
                except BaseException as caught:
                    error = caught
        finally:
            runner.close()
