"""One state machine drives sync/async XML downloads and durable fenced commits."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import random
import time
from collections.abc import Generator
from dataclasses import replace
from typing import Any

from ._async_cleanup import shield_and_drain
from ._bounded_http import check_control
from .exceptions import KsefHttpError, KsefResponseLimitError, KsefTransportError
from .invoice_sync import AsyncInvoiceSync, InvoiceSync
from .invoice_xml_types import (
    InvoiceDocumentReport,
    InvoiceXmlClaim,
    InvoiceXmlReport,
    KsefXmlIntegrityError,
    KsefXmlLeaseLostError,
    KsefXmlRunError,
    KsefXmlStorageError,
    positive,
    positive_int,
    verify_hash,
)
from .operations import environment_key
from .rate_limiting import CancellationSignal, KsefRateLimitWaitTimeout, KsefRequestCancelledError
from .request_control import current_request_control, request_control

Event = tuple[str, str, tuple[Any, ...], dict[str, Any]]


def _failure(error: Exception, claim: InvoiceXmlClaim, max_failures: int) -> dict[str, Any]:
    reason, blocked, failure, minimum = "api_error", True, False, 0.0
    if isinstance(error, (KsefXmlIntegrityError, KsefResponseLimitError)):
        reason = error.reason_code
    elif isinstance(error, KsefTransportError):
        reason, blocked, failure = "network_error", False, True
    elif isinstance(error, KsefHttpError):
        codes = set(getattr(error, "exception_codes", ()))
        if 21165 in codes:
            reason, blocked = "not_available", False
        elif error.status_code == 429:
            reason, blocked = "rate_limited", False
        elif error.status_code in {500, 502, 503, 504}:
            reason, blocked, failure = "transient_http", False, True
        elif error.status_code == 401:
            reason, blocked = "authentication", False
        elif 21164 in codes:
            reason = "not_found"
        elif error.status_code == 403:
            reason = "forbidden"
        if error.status_code == 429:
            # Unlike in-request retry, durable scheduling must not clip long cooldowns.
            from .http import _budget_retry_after

            minimum = _budget_retry_after(getattr(error, "retry_after_raw", None))
    if failure and claim.failures + 1 >= max_failures:
        reason, blocked = "retry_exhausted", True
    exponent = min(max(0, claim.attempts - 1), 10)
    delay = max(minimum, min(3600.0, 5.0 * 2**exponent * random.uniform(0.8, 1.2)))
    return {"reason": reason, "blocked": blocked, "failure": failure, "delay": delay}


class _InvoiceXmlBase:
    def __init__(
        self,
        metadata: InvoiceSync,
        client: Any,
        *,
        max_xml_bytes: int = 16 * 1024 * 1024,
        lease_seconds: float = 120,
        document_time_budget: float = 60,
        max_failures: int = 12,
    ) -> None:
        if not isinstance(metadata, InvoiceSync):
            raise TypeError("InvoiceXmlSync requires synchronous metadata")
        self._initialize(
            metadata, client, max_xml_bytes, lease_seconds, document_time_budget, max_failures
        )

    def _initialize(
        self,
        metadata: Any,
        client: Any,
        max_xml_bytes: int,
        lease_seconds: float,
        document_time_budget: float,
        max_failures: int,
    ) -> None:
        self.metadata, self.client = metadata, client
        self.scopes = tuple(s.scope for s in metadata.streams)
        self.max_xml_bytes = positive_int(max_xml_bytes, "max_xml_bytes")
        self.lease_seconds = positive(lease_seconds, "lease_seconds")
        self.document_time_budget = positive(document_time_budget, "document_time_budget")
        self.max_failures = positive_int(max_failures, "max_failures")
        if self.lease_seconds < self.document_time_budget + 30:
            raise ValueError("Lease must exceed document budget by at least 30 seconds")
        self._validate_source()

    def _validate_source(self) -> None:
        target = environment_key(self.client._http.api_base_url)
        if any(s.environment != target for s in self.scopes):
            raise ValueError("XML source differs from metadata environment")

    def _machine(
        self,
        storage_id: str,
        *,
        time_budget: float,
        max_documents: int,
        cancellation: CancellationSignal | None,
        raise_on_error: bool,
    ) -> Generator[Event, Any, InvoiceXmlReport]:
        budget = positive(time_budget, "time_budget")
        positive_int(max_documents, "max_documents")
        if type(raise_on_error) is not bool:
            raise TypeError("raise_on_error must be bool")
        self._validate_source()
        parent = current_request_control()
        end = time.monotonic() + budget
        counts = {"claims": 0, "downloaded": 0, "recovered": 0, "downloaded_bytes": 0, "errors": 0}
        stop_reason = None
        yield ("store", "validate_xml", (self.scopes, storage_id), {})
        for _ in range(max_documents):
            claim = None
            try:
                with request_control(deadline=end, cancellation=cancellation):
                    check_control()
                    claim = yield (
                        "store",
                        "claim_xml",
                        (self.scopes,),
                        {"lease_seconds": self.lease_seconds},
                    )
                    if claim is None:
                        break
                    if not isinstance(claim, InvoiceXmlClaim) or claim.storage_id != storage_id:
                        raise KsefXmlStorageError("invalid_claim")
                    if (claim.key.namespace, claim.key.environment, claim.key.context_key) != (
                        self.scopes[0].namespace,
                        self.scopes[0].environment,
                        self.scopes[0].context_key,
                    ):
                        raise KsefXmlStorageError("claim_scope_mismatch")
                    counts["claims"] += 1
                    with request_control(timeout_seconds=self.document_time_budget):
                        receipt = yield ("storage", "inspect", (claim.key, claim.expected_hash), {})
                        recovered = receipt is not None
                        if receipt is not None and receipt.size > self.max_xml_bytes:
                            raise KsefResponseLimitError(limit_bytes=self.max_xml_bytes)
                        if receipt is None:
                            self._validate_source()
                            result = yield (
                                "client",
                                "get_invoice_bytes_limited",
                                (claim.key.ksef_number,),
                                {"max_bytes": self.max_xml_bytes},
                            )
                            verify_hash(result.content, claim.expected_hash)
                            if result.sha256_base64 is not None:
                                verify_hash(result.content, result.sha256_base64)
                            check_control()
                            receipt = yield (
                                "storage",
                                "put_verified",
                                (claim.key, result.content, claim.expected_hash),
                                {},
                            )
                            counts["downloaded_bytes"] += len(result.content)
                            # Do not retain an XML buffer across iterations or database I/O.
                            del result
                        receipt.validate(claim.key, claim.expected_hash, storage_id)
                        check_control()
                        yield ("store", "finish_xml", (claim, receipt), {})
                        counts["recovered" if recovered else "downloaded"] += 1
            except KsefXmlLeaseLostError:
                stop_reason = "lease_lost"
            except (
                KsefHttpError,
                KsefTransportError,
                KsefResponseLimitError,
                KsefXmlIntegrityError,
            ) as error:
                if claim is None:
                    raise
                counts["errors"] += 1
                attributes = _failure(error, claim, self.max_failures)
                with contextlib.suppress(KsefXmlLeaseLostError):
                    yield ("store", "defer_xml", (claim,), attributes)
                if attributes["reason"] == "authentication":
                    stop_reason = "authentication"
                    break
            except (
                KsefRateLimitWaitTimeout,
                KsefRequestCancelledError,
                asyncio.CancelledError,
            ) as error:
                if claim is not None:
                    with contextlib.suppress(KsefXmlLeaseLostError):
                        # HTTP retry waits execute inside the handler for the last
                        # response. Cancellation/deadline must not discard its full
                        # server cooldown when handing control back to the queue.
                        previous = error.__context__
                        if isinstance(previous, KsefHttpError) and previous.status_code == 429:
                            retry = _failure(previous, claim, self.max_failures)
                            counts["errors"] += 1
                        else:
                            retry = {
                                "reason": "cancelled"
                                if not isinstance(error, KsefRateLimitWaitTimeout)
                                else "document_time_budget",
                                "delay": 5,
                            }
                        yield (
                            "store",
                            "defer_xml",
                            (claim,),
                            retry,
                        )
                if not isinstance(error, KsefRateLimitWaitTimeout):
                    raise
                if parent is not None:
                    parent.check()
                if time.monotonic() >= end:
                    stop_reason = "time_budget"
                    break
            # Disk/DB failures deliberately escape: lease expiry retains the obligation.
        else:
            stop_reason = "work_limit"
        report = yield ("store", "describe_xml", (self.scopes,), {})
        report = replace(report, **counts, stop_reason=stop_reason)
        if raise_on_error and (report.blocked or report.stop_reason == "authentication"):
            raise KsefXmlRunError(report)
        return report


class InvoiceXmlSync(_InvoiceXmlBase):
    def run_once(
        self,
        store: Any,
        storage: Any,
        *,
        time_budget: float = 600,
        max_documents: int = 100,
        cancellation: CancellationSignal | None = None,
        raise_on_error: bool = True,
    ) -> InvoiceXmlReport:
        runner = self._machine(
            storage.storage_id,
            time_budget=time_budget,
            max_documents=max_documents,
            cancellation=cancellation,
            raise_on_error=raise_on_error,
        )
        return _drive(runner, {"store": store, "storage": storage, "client": self.client})


def _drive(
    runner: Generator[Event, Any, InvoiceXmlReport], actors: dict[str, Any]
) -> InvoiceXmlReport:
    value, error = None, None
    try:
        while True:
            try:
                target, name, args, kwargs = runner.throw(error) if error else runner.send(value)
            except StopIteration as done:
                return done.value
            error = None
            value = None
            try:
                value = getattr(actors[target], name)(*args, **kwargs)
                if inspect.isawaitable(value):
                    if inspect.iscoroutine(value):
                        value.close()
                    raise TypeError("Synchronous XML worker requires synchronous adapters")
            except BaseException as caught:
                error = caught
    finally:
        runner.close()


class AsyncInvoiceXmlSync(_InvoiceXmlBase):
    def __init__(
        self,
        metadata: AsyncInvoiceSync,
        client: Any,
        *,
        max_xml_bytes: int = 16 * 1024 * 1024,
        lease_seconds: float = 120,
        document_time_budget: float = 60,
        max_failures: int = 12,
    ) -> None:
        if not isinstance(metadata, AsyncInvoiceSync):
            raise TypeError("AsyncInvoiceXmlSync requires asynchronous metadata")
        self._initialize(
            metadata, client, max_xml_bytes, lease_seconds, document_time_budget, max_failures
        )

    async def run_once(
        self,
        store: Any,
        storage: Any,
        *,
        time_budget: float = 600,
        max_documents: int = 100,
        cancellation: CancellationSignal | None = None,
        raise_on_error: bool = True,
    ) -> InvoiceXmlReport:
        runner = self._machine(
            storage.storage_id,
            time_budget=time_budget,
            max_documents=max_documents,
            cancellation=cancellation,
            raise_on_error=raise_on_error,
        )
        actors = {"store": store, "storage": storage, "client": self.client}
        value, error = None, None
        try:
            while True:
                try:
                    target, name, args, kwargs = (
                        runner.throw(error) if error else runner.send(value)
                    )
                except StopIteration as done:
                    return done.value
                value, error = None, None
                try:
                    if target == "store" and name in {"claim_xml", "finish_xml"}:
                        # Deliver native cancellation before crossing the mutation boundary.
                        await asyncio.sleep(0)
                        check_control()
                    result = getattr(actors[target], name)(*args, **kwargs)
                    if not inspect.isawaitable(result):
                        raise TypeError("Async XML worker requires awaitable adapters")
                    value = await shield_and_drain(result) if target == "store" else await result
                except BaseException as caught:
                    error = caught
        finally:
            runner.close()


def _changed(metadata: Any, report: Any, xml: InvoiceXmlReport) -> bool:
    return any(
        (result.observed_generation, result.observed_revision)
        != ((cp.generation_id, cp.revision) if cp is not None else (None, None))
        for result, cp in zip(report.streams, xml.checkpoints, strict=True)
    )


class InvoiceDocumentSync:
    def __init__(self, metadata: InvoiceSync, client: Any, **xml_options: Any) -> None:
        self.metadata = metadata
        self.xml = InvoiceXmlSync(metadata, client, **xml_options)

    def describe(self, store: Any) -> InvoiceDocumentReport:
        xml = store.describe_xml(self.xml.scopes)
        return InvoiceDocumentReport(self.metadata.describe(xml.checkpoints), xml)

    def run_once(
        self,
        store: Any,
        storage: Any,
        *,
        time_budget: float = 600,
        metadata_time_budget: float = 300,
        max_documents: int = 100,
        cancellation: CancellationSignal | None = None,
        raise_on_error: bool = True,
    ) -> InvoiceDocumentReport:
        budget = positive(time_budget, "time_budget")
        metadata_budget = min(positive(metadata_time_budget, "metadata_time_budget"), budget)
        positive_int(max_documents, "max_documents")
        if type(raise_on_error) is not bool:
            raise TypeError("raise_on_error must be bool")
        store.validate_xml(self.xml.scopes, storage.storage_id)
        end = time.monotonic() + budget
        with request_control(cancellation=cancellation):
            report = self.metadata.run_once(
                store, time_budget=metadata_budget, cancellation=cancellation, raise_on_error=False
            )
            remaining = end - time.monotonic()
            if remaining > 0:
                xml = self.xml.run_once(
                    store,
                    storage,
                    time_budget=remaining,
                    max_documents=max_documents,
                    cancellation=cancellation,
                    raise_on_error=False,
                )
            else:
                xml = replace(store.describe_xml(self.xml.scopes), stop_reason="time_budget")
        result = InvoiceDocumentReport(report, xml, _changed(self.metadata, report, xml))
        if raise_on_error and (
            any(s.status == "failed" for s in report.streams)
            or xml.blocked
            or xml.stop_reason == "authentication"
        ):
            raise KsefXmlRunError(result)
        return result


class AsyncInvoiceDocumentSync:
    def __init__(self, metadata: AsyncInvoiceSync, client: Any, **xml_options: Any) -> None:
        self.metadata = metadata
        self.xml = AsyncInvoiceXmlSync(metadata, client, **xml_options)

    async def describe(self, store: Any) -> InvoiceDocumentReport:
        xml = await store.describe_xml(self.xml.scopes)
        return InvoiceDocumentReport(self.metadata.describe(xml.checkpoints), xml)

    async def run_once(
        self,
        store: Any,
        storage: Any,
        *,
        time_budget: float = 600,
        metadata_time_budget: float = 300,
        max_documents: int = 100,
        cancellation: CancellationSignal | None = None,
        raise_on_error: bool = True,
    ) -> InvoiceDocumentReport:
        budget = positive(time_budget, "time_budget")
        metadata_budget = min(positive(metadata_time_budget, "metadata_time_budget"), budget)
        positive_int(max_documents, "max_documents")
        if type(raise_on_error) is not bool:
            raise TypeError("raise_on_error must be bool")
        await store.validate_xml(self.xml.scopes, storage.storage_id)
        end = time.monotonic() + budget
        with request_control(cancellation=cancellation):
            report = await self.metadata.run_once(
                store, time_budget=metadata_budget, cancellation=cancellation, raise_on_error=False
            )
            remaining = end - time.monotonic()
            if remaining > 0:
                xml = await self.xml.run_once(
                    store,
                    storage,
                    time_budget=remaining,
                    max_documents=max_documents,
                    cancellation=cancellation,
                    raise_on_error=False,
                )
            else:
                xml = replace(await store.describe_xml(self.xml.scopes), stop_reason="time_budget")
        result = InvoiceDocumentReport(report, xml, _changed(self.metadata, report, xml))
        if raise_on_error and (
            any(s.status == "failed" for s in report.streams)
            or xml.blocked
            or xml.stop_reason == "authentication"
        ):
            raise KsefXmlRunError(result)
        return result
