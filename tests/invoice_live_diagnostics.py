"""Bounded, redacted diagnostics shared by installed-wheel invoice live workers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ksef_client.exceptions import KsefHttpError, KsefSyncRunError
from ksef_client.invoice_sync import _SAFE_FAILURE_REASONS
from ksef_client.rate_limiting import KsefRateLimitWaitTimeout
from ksef_client.sqlite_store import SAFE_REASONS


def diagnostic(
    *,
    stage: str | None = None,
    phase: str | None = None,
    observation: str | None = None,
    report: Any = None,
    error: BaseException | None = None,
    visibility: tuple[int, bool] | None = None,
    metadata_report: Any = None,
    transport_error: BaseException | None = None,
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
    selected_phase = phase if phase is not None else previous.get("phase")
    if selected_phase in ("bootstrap", "incremental"):
        value["phase"] = selected_phase
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
    if metadata_report is not None:
        allowed = _SAFE_FAILURE_REASONS | {"time_budget", "step_time_budget", "work_limit"}
        value["metadata_streams"] = [
            {
                "status": stream.status
                if stream.status in {"completed", "partial", "failed"}
                else "unknown",
                "reason": stream.stop_reason if stream.stop_reason in allowed else None,
                "pages": stream.pages_committed,
                "records": stream.records_delivered,
            }
            for stream in metadata_report.streams[:4]
        ]
    elif isinstance(previous.get("metadata_streams"), list):
        # Re-sanitize persisted diagnostics instead of copying arbitrary file content.
        allowed = _SAFE_FAILURE_REASONS | {"time_budget", "step_time_budget", "work_limit"}
        value["metadata_streams"] = [
            {
                "status": row.get("status")
                if row.get("status") in {"completed", "partial", "failed"}
                else "unknown",
                "reason": row.get("reason") if row.get("reason") in allowed else None,
                "pages": row.get("pages") if type(row.get("pages")) is int else 0,
                "records": row.get("records") if type(row.get("records")) is int else 0,
            }
            for row in previous["metadata_streams"][:4]
            if isinstance(row, dict)
        ]
    previous_http = previous.get("metadata_http_status")
    if type(previous_http) is int and 100 <= previous_http <= 599:
        value["metadata_http_status"] = previous_http
    current = transport_error
    for _ in range(8):
        if current is None:
            break
        if isinstance(current, KsefHttpError) and 100 <= current.status_code <= 599:
            value["metadata_http_status"] = current.status_code
            break
        current = current.__cause__ or current.__context__
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
