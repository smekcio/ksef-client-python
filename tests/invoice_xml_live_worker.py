"""Installed-wheel TEST XML synchronization, split across fresh interpreters."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
from ksef_client.exceptions import KsefHttpError, KsefSyncRunError  # noqa: E402
from ksef_client.invoice_search import _date  # noqa: E402
from ksef_client.invoice_xml_types import KsefXmlRunError  # noqa: E402
from ksef_client.rate_limiting import KsefRateLimitWaitTimeout  # noqa: E402
from ksef_client.request_control import request_control, wait_seconds  # noqa: E402
from ksef_client.sqlite_store import SAFE_REASONS  # noqa: E402
from ksef_client.utils.ksef_number import canonical_ksef_number  # noqa: E402
from tests.invoice_sync_live_worker import verify  # noqa: E402
from tests.test_e2e_token_flows import (  # noqa: E402
    _load_test_token_config,
)


def document_number(number: str) -> str:
    try:
        return canonical_ksef_number(number)
    except ValueError:
        # Let the real queue quarantine malformed server metadata and report its code.
        return number


def target_job(store: Any, scopes: Any, number: str) -> dict[str, Any] | None:
    number = document_number(number)
    after = ""
    while rows := store.list_xml(scopes, after=after, limit=100):
        for row in rows:
            if row["ksef_number"] == number:
                return row
        after = rows[-1]["ksef_number"]
    return None


def diagnostic(
    *,
    stage: str | None = None,
    observation: str | None = None,
    report: Any = None,
    error: BaseException | None = None,
    visibility: tuple[int, bool] | None = None,
    path: Path = Path("xml-live-diagnostic.json"),
) -> dict[str, Any]:
    """Persist only fixed stages, counts and SDK codes; never child output or queries."""
    stages = {"connect", "submit", "observe", "metadata", "queued", "xml", "ready"}
    try:
        previous = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, ValueError):
        previous = {}
    value: dict[str, Any] = {
        "stage": stage if stage in stages else previous.get("stage", "unknown")
    }
    if value["stage"] not in stages:
        value["stage"] = "unknown"
    if visibility is not None:
        value["visible_count"], value["target_visible"] = visibility
    else:
        if type(previous.get("visible_count")) is int:
            value["visible_count"] = previous["visible_count"]
        if type(previous.get("target_visible")) is bool:
            value["target_visible"] = previous["target_visible"]
    if value["stage"] == "observe":
        observed = observation if observation is not None else previous.get("observation")
        if isinstance(observed, str) and observed in {"hwm_before_start", "not_visible", "visible"}:
            value["observation"] = observed
    if report is not None:
        xml = report.xml
        for name in (
            "observed",
            "not_enqueued",
            "pending",
            "leased",
            "retry_wait",
            "blocked",
            "ready",
        ):
            value[name] = getattr(xml, name)
        value["reasons"] = [reason for reason, _ in xml.reason_counts if reason in SAFE_REASONS]
        if hasattr(report, "metadata_complete"):
            value["metadata_complete"] = report.metadata_complete
    else:
        for name in (
            "observed",
            "not_enqueued",
            "pending",
            "leased",
            "retry_wait",
            "blocked",
            "ready",
        ):
            if type(previous.get(name)) is int:
                value[name] = previous[name]
        if type(previous.get("metadata_complete")) is bool:
            value["metadata_complete"] = previous["metadata_complete"]
        value["reasons"] = [
            reason for reason in previous.get("reasons", []) if reason in SAFE_REASONS
        ]
    if previous.get("failure") in {"deadline", "http", "sync", "assertion", "unexpected"}:
        value["failure"] = previous["failure"]
    if type(previous.get("http_status")) is int and 100 <= previous["http_status"] <= 599:
        value["http_status"] = previous["http_status"]
    if error is not None:
        value["failure"] = (
            "deadline"
            if isinstance(error, KsefRateLimitWaitTimeout)
            else "http"
            if isinstance(error, KsefHttpError)
            else "sync"
            if isinstance(error, KsefSyncRunError)
            else "assertion"
            if isinstance(error, AssertionError)
            else "unexpected"
        )
        if isinstance(error, KsefHttpError):
            value["http_status"] = error.status_code
        if hasattr(error, "xml_report"):
            value["reasons"] = [
                reason for reason, _ in error.xml_report.reason_counts if reason in SAFE_REASONS
            ]
    path.write_text(json.dumps(value), encoding="utf-8")
    return value


def run(phase: str) -> None:
    diagnostic(stage="connect")
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
        request_control(deadline=state["soft_deadline"], timeout_seconds=600),
        Ksef.connect(
            options=options,
            credentials=TokenCredentials(config.token),
            context_type=config.context_type,
            context_value=config.context_value,
        ) as client,
    ):
        query = m.InvoiceQueryFilters(
            subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
            date_range=m.InvoiceQueryDateRange(
                date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
                from_=state["since"],
                restrict_to_permanent_storage_hwm_date=True,
            ),
        )
        if phase == "metadata":
            # Use real, already indexed metadata. Fresh submission/HWM propagation is
            # exercised separately by the metadata restart gate; this gate verifies
            # the durable XML obligation across a process restart.
            while True:
                diagnostic(stage="observe")
                scan = client.api.invoices.search_invoice_metadata_range(
                    replace(
                        query,
                        date_range=replace(
                            query.date_range, to=datetime.now(timezone.utc).isoformat()
                        ),
                    ),
                    context_key=client.context_key,
                )
                selected: tuple[str, str] | None = None
                cursor, visible = None, 0
                try:
                    while True:
                        page = scan.observation_page(cursor)
                        visible += len(page.observations)
                        for item in page.observations:
                            if not item.ksef_number or not item.permanent_storage_date:
                                continue
                            try:
                                canonical_ksef_number(item.ksef_number)
                            except ValueError:
                                continue
                            if selected is None or _date(item.permanent_storage_date) >= _date(
                                selected[1]
                            ):
                                selected = (item.ksef_number, item.permanent_storage_date)
                        cursor = page.next_cursor
                        if cursor is None:
                            break
                    diagnostic(
                        stage="observe",
                        observation="visible" if selected else "not_visible",
                        visibility=(visible, selected is not None),
                    )
                except KsefIncompletePaginationError as error:
                    if error.reason_code != "hwm_before_start":
                        raise
                    selected = None
                    diagnostic(
                        stage="observe", observation="hwm_before_start", visibility=(0, False)
                    )
                if selected is not None:
                    state["number"] = canonical_ksef_number(selected[0])
                    state["metadata_from"] = selected[1]
                    state_path.write_text(json.dumps(state), encoding="utf-8")
                    break
                wait_seconds(30)
        query = replace(query, date_range=replace(query.date_range, from_=state["metadata_from"]))
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
                while True:
                    diagnostic(stage="metadata")
                    sync.metadata.run_once(store, time_budget=120)
                    report = sync.describe(store)
                    diagnostic(stage="metadata", report=report)
                    if report.xml.blocked:
                        raise KsefXmlRunError(report)
                    target = target_job(store, sync.xml.scopes, state["number"])
                    if target and target["status"] == "pending" and report.metadata_complete:
                        break
                    wait_seconds(30)
                assert report.xml.pending >= 1 and report.xml.ready == 0 and not report.complete
                diagnostic(stage="queued", report=report)
            else:
                target = target_job(store, sync.xml.scopes, state["number"])
                assert target is not None and target["status"] == "pending"
                while True:
                    diagnostic(stage="xml")
                    report_xml = sync.xml.run_once(store, storage, time_budget=120)
                    diagnostic(stage="xml", report=report_xml)
                    if report_xml.observed and report_xml.xml_ready_for_observed:
                        break
                    wait_seconds(30)
                again = sync.xml.run_once(store, storage)
                assert again.ready == report_xml.observed
                assert again.downloaded == 0 and again.claims == 0
                target = target_job(store, sync.xml.scopes, state["number"])
                assert target is not None and target["status"] == "ready"
                report = sync.describe(store)
                assert report.complete
                diagnostic(stage="ready", report=report)
                state["complete"] = True
                state_path.write_text(json.dumps(state), encoding="utf-8")
    verify()


if __name__ == "__main__":
    try:
        run(sys.argv[1])
    except BaseException as error:
        diagnostic(error=error)
        raise
