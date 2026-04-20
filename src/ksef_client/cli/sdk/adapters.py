from __future__ import annotations

import json
import time
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ksef_client import models as m
from ksef_client.exceptions import KsefHttpError, KsefRateLimitError
from ksef_client.services.crypto import EncryptionData, build_encryption_data
from ksef_client.services.workflows import (
    BatchSessionWorkflow,
    ExportWorkflow,
    OnlineSessionWorkflow,
)
from ksef_client.utils.zip_utils import build_zip

from ..auth.keyring_store import get_tokens
from ..errors import CliError
from ..exit_codes import ExitCode
from ..policies.retry import RetryPolicy, compute_retry_delay_seconds, should_retry
from .factory import create_client

_TRANSIENT_UPO_CODES = {404, 409, 425}
_PENDING_STATUS_CODES = {100, 150}
_DEFAULT_INVOICE_QUERY_SUBJECT_TYPES = (
    m.InvoiceQuerySubjectType.SUBJECT1,
    m.InvoiceQuerySubjectType.SUBJECT2,
    m.InvoiceQuerySubjectType.SUBJECT3,
    m.InvoiceQuerySubjectType.SUBJECTAUTHORIZED,
)
_INVOICE_SORT_DATE_FIELDS = {
    m.InvoiceQueryDateType.ISSUE.value: (("issue_date", "issueDate"),),
    m.InvoiceQueryDateType.INVOICING.value: (
        ("invoicing_date", "invoicingDate"),
        ("acquisition_date", "acquisitionDate"),
    ),
    m.InvoiceQueryDateType.PERMANENTSTORAGE.value: (
        ("permanent_storage_date", "permanentStorageDate"),
    ),
}


def _is_transient_polling_http(status_code: int) -> bool:
    return status_code in _TRANSIENT_UPO_CODES or should_retry(status_code)


def _transient_retry_delay_seconds(
    *,
    attempt: int,
    poll_interval: float,
    exc: KsefHttpError,
) -> float:
    retry_after = exc.retry_after_raw if isinstance(exc, KsefRateLimitError) else None
    policy = RetryPolicy(
        max_retries=max(1, attempt),
        base_delay_ms=max(1, int(poll_interval * 1000)),
        jitter_ratio=0.0,
    )
    return max(
        poll_interval,
        compute_retry_delay_seconds(
            attempt,
            policy,
            retry_after=retry_after,
            random_value=0.5,
        ),
    )


def _require_access_token(profile: str) -> str:
    tokens = get_tokens(profile)
    if not tokens:
        raise CliError(
            "No stored access token for selected profile.",
            ExitCode.AUTH_ERROR,
            "Run `ksef auth login-token` first.",
        )
    return tokens[0]


def _normalize_date_range(date_from: str | None, date_to: str | None) -> tuple[str, str]:
    def _parse_date(value: str, option_name: str) -> datetime:
        try:
            return datetime.strptime(value, "%Y-%m-%d")
        except ValueError as exc:
            raise CliError(
                f"Invalid {option_name} date.",
                ExitCode.VALIDATION_ERROR,
                "Use format YYYY-MM-DD.",
            ) from exc

    if date_to:
        to_dt = _parse_date(date_to, "--to").replace(
            hour=23, minute=59, second=59, tzinfo=timezone.utc
        )
    else:
        to_dt = datetime.now(timezone.utc).replace(microsecond=0)

    if date_from:
        from_dt = _parse_date(date_from, "--from").replace(
            hour=0, minute=0, second=0, tzinfo=timezone.utc
        )
    else:
        from_dt = (to_dt - timedelta(days=30)).replace(hour=0, minute=0, second=0)

    if from_dt > to_dt:
        raise CliError(
            "Invalid date range.",
            ExitCode.VALIDATION_ERROR,
            "--from must be earlier than or equal to --to.",
        )

    return from_dt.isoformat().replace("+00:00", "Z"), to_dt.isoformat().replace("+00:00", "Z")


def _resolve_output_path(
    out: str,
    *,
    default_filename: str,
) -> Path:
    path = Path(out)
    if path.exists() and path.is_dir():
        return path / default_filename
    normalized_out = out.replace("\\", "/")
    if normalized_out.endswith("/"):
        return Path(normalized_out) / default_filename
    return path


def _save_bytes(path: Path, content: bytes, *, overwrite: bool) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise CliError(
            f"Output file already exists: {path}",
            ExitCode.IO_ERROR,
            "Use --overwrite to replace existing file.",
        )
    path.write_bytes(content)
    return path


def _safe_child_path(root: Path, relative_path: str) -> Path:
    candidate = (root / relative_path).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise CliError(
            "Export package contains unsafe file path.",
            ExitCode.IO_ERROR,
            "Unsafe path from exported archive was blocked.",
        )
    return candidate


def _to_output_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return value


def _get_value(
    payload: Any,
    attr_name: str,
    json_name: str | None = None,
    default: Any = None,
) -> Any:
    if isinstance(payload, dict):
        key = json_name or attr_name
        return payload.get(key, default)
    return getattr(payload, attr_name, default)


def _as_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    result: list[str] = []
    for item in values:
        value = getattr(item, "value", item)
        result.append(str(value))
    return result


def _extract_reference_number(payload: Any) -> str:
    value = _get_value(payload, "reference_number", "referenceNumber")
    return str(value or "")


def _extract_ksef_number(payload: Any) -> str:
    value = _get_value(payload, "ksef_number", "ksefNumber")
    return str(value or "")


def _extract_upo_reference(payload: Any) -> str:
    direct = _get_value(payload, "upo_reference_number", "upoReferenceNumber")
    if direct:
        return str(direct)
    upo = _get_value(payload, "upo")
    nested = _get_value(upo, "reference_number", "referenceNumber")
    return str(nested or "")


def _select_certificate(certs: list[Any], usage_name: str) -> str:
    for cert in certs:
        usage = _as_string_list(_get_value(cert, "usage", default=[]))
        certificate = _get_value(cert, "certificate")
        if usage_name in usage and certificate:
            return str(certificate)
    raise CliError(
        f"Missing KSeF public certificate usage: {usage_name}.",
        ExitCode.API_ERROR,
        "Try again later or verify environment availability.",
    )


def _build_form_code(system_code: str, schema_version: str, form_value: str) -> m.FormCode:
    normalized_system_code = system_code.strip()
    normalized_schema_version = schema_version.strip()
    normalized_form_value = form_value.strip()
    if not normalized_system_code or not normalized_schema_version or not normalized_form_value:
        raise CliError(
            "Invalid form code options.",
            ExitCode.VALIDATION_ERROR,
            "Use non-empty --system-code, --schema-version and --form-value.",
        )

    if (
        normalized_system_code == "FA_RR (1)"
        and normalized_schema_version == "1-1E"
        and normalized_form_value == "RR"
    ):
        normalized_form_value = "FA_RR"

    return m.FormCode(
        system_code=normalized_system_code,
        schema_version=normalized_schema_version,
        value=normalized_form_value,
    )


def _require_invoice_query_subject_type(value: str) -> m.InvoiceQuerySubjectType:
    for candidate in m.InvoiceQuerySubjectType:
        if value == candidate.value:
            return candidate
    raise CliError(
        "Invalid subject type.",
        ExitCode.VALIDATION_ERROR,
        "Use a valid KSeF InvoiceQuerySubjectType value such as Subject1.",
    )


def _require_invoice_query_date_type(value: str) -> m.InvoiceQueryDateType:
    for candidate in m.InvoiceQueryDateType:
        if value == candidate.value:
            return candidate
    raise CliError(
        "Invalid date type.",
        ExitCode.VALIDATION_ERROR,
        "Use a valid KSeF InvoiceQueryDateType value such as Issue.",
    )


def _require_export_sort_order(value: str) -> str:
    if value == "Asc":
        return value
    raise CliError(
        "Invalid sort order for export.",
        ExitCode.VALIDATION_ERROR,
        "For `ksef export run` use --sort-order Asc.",
    )


def _require_encryption_info(encryption: EncryptionData) -> m.EncryptionInfo:
    encryption_info = getattr(encryption, "encryption_info", None)
    if encryption_info is None:
        raise CliError(
            "Missing encryption metadata.",
            ExitCode.CONFIG_ERROR,
            "Regenerate encryption data before opening a session or export.",
        )
    return encryption_info


def _build_invoice_query_filters(
    *,
    subject_type: m.InvoiceQuerySubjectType,
    date_type: m.InvoiceQueryDateType,
    from_iso: str,
    to_iso: str,
) -> m.InvoiceQueryFilters:
    return m.InvoiceQueryFilters(
        subject_type=subject_type,
        date_range=m.InvoiceQueryDateRange(
            date_type=date_type,
            from_=from_iso,
            to=to_iso,
        ),
    )


def _extract_invoice_items(response: Any) -> list[Any]:
    invoices = _get_value(response, "invoices", default=[]) or []
    if isinstance(response, dict) and not invoices:
        invoices = response.get("invoiceList") or []
    return invoices if isinstance(invoices, list) else []


def _normalize_invoice_sort_value(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat()


def _invoice_identity_key(invoice: Any) -> str:
    for attr_name, json_name in (
        ("ksef_number", "ksefNumber"),
        ("invoice_hash", "invoiceHash"),
    ):
        value = _get_value(invoice, attr_name, json_name)
        if value:
            return f"{json_name}:{value}"
    payload = _to_output_payload(invoice)
    if isinstance(payload, dict):
        return json.dumps(payload, ensure_ascii=True, sort_keys=True)
    return repr(payload)


def _invoice_sort_key(invoice: Any, *, date_type: m.InvoiceQueryDateType) -> tuple[str, str, str]:
    date_value = ""
    for attr_name, json_name in _INVOICE_SORT_DATE_FIELDS.get(date_type.value, ()):
        candidate = _get_value(invoice, attr_name, json_name)
        if candidate:
            date_value = _normalize_invoice_sort_value(candidate)
            break
    reference = str(
        _get_value(invoice, "ksef_number", "ksefNumber")
        or _get_value(invoice, "invoice_number", "invoiceNumber")
        or _get_value(invoice, "invoice_hash", "invoiceHash")
        or ""
    )
    return (
        date_value,
        reference,
        _invoice_identity_key(invoice),
    )


def _query_invoice_metadata_page(
    *,
    client: Any,
    access_token: str,
    subject_type: m.InvoiceQuerySubjectType,
    date_type: m.InvoiceQueryDateType,
    from_iso: str,
    to_iso: str,
    page_size: int,
    page_offset: int,
    sort_order: str,
) -> Any:
    return client.invoices.query_invoice_metadata(
        _build_invoice_query_filters(
            subject_type=subject_type,
            date_type=date_type,
            from_iso=from_iso,
            to_iso=to_iso,
        ),
        access_token=access_token,
        page_offset=page_offset,
        page_size=page_size,
        sort_order=sort_order,
    )


def _query_all_invoice_subject_types(
    *,
    client: Any,
    access_token: str,
    date_type: m.InvoiceQueryDateType,
    from_iso: str,
    to_iso: str,
    page_size: int,
    page_offset: int,
    sort_order: str,
) -> list[Any]:
    batch_size = page_size if page_size > 0 else 0
    aggregated: list[Any] = []

    for subject_type in _DEFAULT_INVOICE_QUERY_SUBJECT_TYPES:
        request_offset = 0
        while True:
            response = _query_invoice_metadata_page(
                client=client,
                access_token=access_token,
                subject_type=subject_type,
                date_type=date_type,
                from_iso=from_iso,
                to_iso=to_iso,
                page_size=page_size,
                page_offset=request_offset,
                sort_order=sort_order,
            )
            invoices = _extract_invoice_items(response)
            if not invoices:
                break
            aggregated.extend(invoices)
            if batch_size <= 0 or len(invoices) < batch_size:
                break
            request_offset += batch_size

    unique_invoices: dict[str, Any] = {}
    for invoice in aggregated:
        unique_invoices.setdefault(_invoice_identity_key(invoice), invoice)

    sorted_invoices = sorted(
        unique_invoices.values(),
        key=lambda invoice: _invoice_sort_key(invoice, date_type=date_type),
        reverse=sort_order.casefold() == "desc",
    )
    if page_offset < 0:
        page_offset = 0
    if page_size <= 0:
        return sorted_invoices[page_offset:]
    return sorted_invoices[page_offset : page_offset + page_size]


def _load_invoice_xml(path: str) -> bytes:
    invoice_path = Path(path)
    if not invoice_path.exists() or not invoice_path.is_file():
        raise CliError(
            f"Invoice file does not exist: {invoice_path}",
            ExitCode.IO_ERROR,
            "Use --invoice with an existing XML file path.",
        )
    content = invoice_path.read_bytes()
    if not content:
        raise CliError(
            "Invoice file is empty.",
            ExitCode.IO_ERROR,
            "Provide a non-empty invoice XML file.",
        )
    return content


def _load_batch_zip(zip_path: str) -> bytes:
    path = Path(zip_path)
    if not path.exists() or not path.is_file():
        raise CliError(
            f"ZIP file does not exist: {path}",
            ExitCode.IO_ERROR,
            "Use --zip with an existing ZIP file path.",
        )
    data = path.read_bytes()
    if not data:
        raise CliError(
            "ZIP file is empty.",
            ExitCode.IO_ERROR,
            "Provide a non-empty ZIP file.",
        )
    return data


def _build_zip_from_directory(directory: str) -> bytes:
    root = Path(directory)
    if not root.exists() or not root.is_dir():
        raise CliError(
            f"Directory does not exist: {root}",
            ExitCode.IO_ERROR,
            "Use --dir with an existing directory path.",
        )

    files: dict[str, bytes] = {}
    for file_path in sorted(root.rglob("*.xml")):
        if file_path.is_file():
            rel = file_path.relative_to(root).as_posix()
            files[rel] = file_path.read_bytes()

    if not files:
        raise CliError(
            "No XML files found in batch directory.",
            ExitCode.VALIDATION_ERROR,
            "Add XML invoices to directory or use --zip.",
        )

    return build_zip(files)


def _validate_polling_options(poll_interval: float, max_attempts: int) -> None:
    if poll_interval <= 0:
        raise CliError(
            "Invalid poll interval.",
            ExitCode.VALIDATION_ERROR,
            "--poll-interval must be greater than zero.",
        )
    if max_attempts <= 0:
        raise CliError(
            "Invalid max attempts.",
            ExitCode.VALIDATION_ERROR,
            "--max-attempts must be greater than zero.",
        )


def _extract_status_fields(payload: Any) -> tuple[int, str, str]:
    status = _get_value(payload, "status", default={}) or {}
    code = int(_get_value(status, "code", default=0) or 0)
    description = str(_get_value(status, "description", default="") or "")
    details = _get_value(status, "details", default=[]) or []
    details_text = ", ".join(str(item) for item in details) if isinstance(details, list) else ""
    return code, description, details_text


def _wait_for_invoice_status(
    *,
    client: Any,
    session_ref: str,
    invoice_ref: str,
    access_token: str,
    poll_interval: float,
    max_attempts: int,
) -> Any:
    for _ in range(max_attempts):
        try:
            status_payload = client.sessions.get_session_invoice_status(
                session_ref,
                invoice_ref,
                access_token=access_token,
            )
        except KsefHttpError as exc:
            if _is_transient_polling_http(exc.status_code):
                time.sleep(poll_interval)
                continue
            raise
        code, description, details = _extract_status_fields(status_payload)
        if code == 200:
            return status_payload
        if code in _PENDING_STATUS_CODES:
            time.sleep(poll_interval)
            continue
        message = f"Invoice processing failed with status {code}."
        hint = description
        if details:
            hint = f"{description} Details: {details}".strip()
        raise CliError(message, ExitCode.API_ERROR, hint or None)

    raise CliError(
        "Invoice status is not ready within max attempts.",
        ExitCode.RETRY_EXHAUSTED,
        "Increase --max-attempts or retry later.",
    )


def _wait_for_invoice_upo(
    *,
    client: Any,
    session_ref: str,
    invoice_ref: str,
    access_token: str,
    poll_interval: float,
    max_attempts: int,
) -> bytes:
    for _ in range(max_attempts):
        try:
            upo_bytes = client.sessions.get_session_invoice_upo_by_ref(
                session_ref,
                invoice_ref,
                access_token=access_token,
            )
            if upo_bytes:
                return upo_bytes
        except KsefHttpError as exc:
            if not _is_transient_polling_http(exc.status_code):
                raise
        time.sleep(poll_interval)

    raise CliError(
        "Invoice UPO is not available within max attempts.",
        ExitCode.RETRY_EXHAUSTED,
        "Increase --max-attempts or retry later.",
    )


def _wait_for_session_status(
    *,
    client: Any,
    session_ref: str,
    access_token: str,
    poll_interval: float,
    max_attempts: int,
) -> Any:
    for _ in range(max_attempts):
        try:
            status_payload = client.sessions.get_session_status(
                session_ref, access_token=access_token
            )
        except KsefHttpError as exc:
            if _is_transient_polling_http(exc.status_code):
                time.sleep(poll_interval)
                continue
            raise
        code, description, details = _extract_status_fields(status_payload)
        if code == 200:
            return status_payload
        if code in _PENDING_STATUS_CODES:
            time.sleep(poll_interval)
            continue
        message = f"Session processing failed with status {code}."
        hint = description
        if details:
            hint = f"{description} Details: {details}".strip()
        raise CliError(message, ExitCode.API_ERROR, hint or None)

    raise CliError(
        "Session status is not ready within max attempts.",
        ExitCode.RETRY_EXHAUSTED,
        "Increase --max-attempts or retry later.",
    )


def _wait_for_batch_upo(
    *,
    client: Any,
    session_ref: str,
    upo_ref: str,
    access_token: str,
    poll_interval: float,
    max_attempts: int,
) -> bytes:
    for _ in range(max_attempts):
        try:
            upo_bytes = client.sessions.get_session_upo(
                session_ref, upo_ref, access_token=access_token
            )
            if upo_bytes:
                return upo_bytes
        except KsefHttpError as exc:
            if not _is_transient_polling_http(exc.status_code):
                raise
        time.sleep(poll_interval)

    raise CliError(
        "Batch UPO is not available within max attempts.",
        ExitCode.RETRY_EXHAUSTED,
        "Run `ksef upo wait --session-ref <SESSION_REF> --batch-auto`.",
    )


def _wait_for_export_status(
    *,
    client: Any,
    reference_number: str,
    access_token: str,
    poll_interval: float,
    max_attempts: int,
) -> Any:
    for attempt in range(1, max_attempts + 1):
        try:
            payload = client.invoices.get_export_status(reference_number, access_token=access_token)
        except KsefHttpError as exc:
            if _is_transient_polling_http(exc.status_code):
                time.sleep(
                    _transient_retry_delay_seconds(
                        attempt=attempt,
                        poll_interval=poll_interval,
                        exc=exc,
                    )
                )
                continue
            raise
        code, description, details = _extract_status_fields(payload)
        if code == 200:
            return payload
        if code in _PENDING_STATUS_CODES:
            time.sleep(poll_interval)
            continue
        hint = description
        if details:
            hint = f"{description} Details: {details}".strip()
        raise CliError(
            f"Export failed with status {code}.",
            ExitCode.API_ERROR,
            hint or None,
        )

    raise CliError(
        "Export status is not ready within max attempts.",
        ExitCode.RETRY_EXHAUSTED,
        "Increase --max-attempts or retry later.",
    )


def get_lighthouse_status(
    *,
    profile: str,
    base_url: str,
    lighthouse_base_url: str | None = None,
) -> dict[str, Any]:
    _ = profile
    with create_client(
        base_url,
        base_lighthouse_url=lighthouse_base_url,
    ) as client:
        status = client.lighthouse.get_status()

    messages = [message.to_dict() for message in (status.messages or [])]
    return {
        "status": status.status.value,
        "messages": messages,
    }


def get_lighthouse_messages(
    *,
    profile: str,
    base_url: str,
    lighthouse_base_url: str | None = None,
) -> dict[str, Any]:
    _ = profile
    with create_client(
        base_url,
        base_lighthouse_url=lighthouse_base_url,
    ) as client:
        messages = client.lighthouse.get_messages()

    items = [message.to_dict() for message in messages]
    return {
        "count": len(items),
        "items": items,
    }


def list_invoices(
    *,
    profile: str,
    base_url: str,
    date_from: str | None,
    date_to: str | None,
    subject_type: str | None,
    date_type: str,
    page_size: int,
    page_offset: int,
    sort_order: str,
) -> dict[str, Any]:
    access_token = _require_access_token(profile)
    from_iso, to_iso = _normalize_date_range(date_from, date_to)
    resolved_date_type = _require_invoice_query_date_type(date_type)

    with create_client(base_url, access_token=access_token) as client:
        continuation_token = ""
        if subject_type is None:
            invoices = _query_all_invoice_subject_types(
                client=client,
                access_token=access_token,
                date_type=resolved_date_type,
                from_iso=from_iso,
                to_iso=to_iso,
                page_size=page_size,
                page_offset=page_offset,
                sort_order=sort_order,
            )
        else:
            response = _query_invoice_metadata_page(
                client=client,
                access_token=access_token,
                subject_type=_require_invoice_query_subject_type(subject_type),
                date_type=resolved_date_type,
                from_iso=from_iso,
                to_iso=to_iso,
                page_size=page_size,
                page_offset=page_offset,
                sort_order=sort_order,
            )
            invoices = _extract_invoice_items(response)
            continuation_token = _get_value(response, "continuation_token", "continuationToken", "")
    return {
        "count": len(invoices),
        "from": from_iso,
        "to": to_iso,
        "items": [_to_output_payload(item) for item in invoices],
        "continuation_token": continuation_token or "",
    }


def download_invoice(
    *,
    profile: str,
    base_url: str,
    ksef_number: str,
    out: str,
    as_format: str,
    overwrite: bool,
) -> dict[str, Any]:
    access_token = _require_access_token(profile)
    if as_format not in {"xml", "bytes"}:
        raise CliError(
            "Unsupported format.",
            ExitCode.VALIDATION_ERROR,
            "Use --as xml or --as bytes.",
        )

    suffix = ".xml" if as_format == "xml" else ".bin"
    out_path = _resolve_output_path(out, default_filename=f"{ksef_number}{suffix}")

    with create_client(base_url, access_token=access_token) as client:
        if as_format == "xml":
            xml_invoice = client.invoices.get_invoice(ksef_number, access_token=access_token)
            content: bytes = xml_invoice.content.encode("utf-8")
            hash_value = xml_invoice.sha256_base64 or ""
        else:
            binary_invoice = client.invoices.get_invoice_bytes(
                ksef_number, access_token=access_token
            )
            content = binary_invoice.content
            hash_value = binary_invoice.sha256_base64 or ""

    saved_path = _save_bytes(out_path, content, overwrite=overwrite)
    return {
        "ksef_number": ksef_number,
        "path": str(saved_path),
        "sha256_base64": hash_value,
        "bytes": len(content),
    }


def get_upo(
    *,
    profile: str,
    base_url: str,
    session_ref: str,
    invoice_ref: str | None,
    ksef_number: str | None,
    upo_ref: str | None,
    out: str,
    overwrite: bool,
) -> dict[str, Any]:
    access_token = _require_access_token(profile)
    selected = [bool(invoice_ref), bool(ksef_number), bool(upo_ref)]
    if sum(1 for flag in selected if flag) != 1:
        raise CliError(
            "Select exactly one identifier for UPO download.",
            ExitCode.VALIDATION_ERROR,
            "Use one of: --invoice-ref, --ksef-number, --upo-ref.",
        )

    with create_client(base_url, access_token=access_token) as client:
        if invoice_ref:
            upo_bytes = client.sessions.get_session_invoice_upo_by_ref(
                session_ref, invoice_ref, access_token=access_token
            )
            default_name = f"upo-{session_ref}-{invoice_ref}.xml"
        elif ksef_number:
            upo_bytes = client.sessions.get_session_invoice_upo_by_ksef(
                session_ref, ksef_number, access_token=access_token
            )
            default_name = f"upo-{session_ref}-{ksef_number}.xml"
        else:
            upo_bytes = client.sessions.get_session_upo(
                session_ref, str(upo_ref), access_token=access_token
            )
            default_name = f"upo-{session_ref}-{upo_ref}.xml"

    path = _resolve_output_path(out, default_filename=default_name)
    saved_path = _save_bytes(path, upo_bytes, overwrite=overwrite)
    return {
        "session_ref": session_ref,
        "path": str(saved_path),
        "bytes": len(upo_bytes),
    }


def wait_for_upo(
    *,
    profile: str,
    base_url: str,
    session_ref: str,
    invoice_ref: str | None,
    upo_ref: str | None,
    batch_auto: bool,
    poll_interval: float,
    max_attempts: int,
    out: str | None,
    overwrite: bool = False,
) -> dict[str, Any]:
    access_token = _require_access_token(profile)
    _validate_polling_options(poll_interval, max_attempts)

    selected = [bool(invoice_ref), bool(upo_ref), bool(batch_auto)]
    if sum(1 for flag in selected if flag) != 1:
        raise CliError(
            "Select exactly one wait mode.",
            ExitCode.VALIDATION_ERROR,
            "Use one of: --invoice-ref, --upo-ref, --batch-auto.",
        )

    with create_client(base_url, access_token=access_token) as client:
        detected_upo_ref: str | None = upo_ref
        for _ in range(max_attempts):
            if invoice_ref:
                try:
                    status = client.sessions.get_session_invoice_status(
                        session_ref, invoice_ref, access_token=access_token
                    )
                except KsefHttpError as exc:
                    if _is_transient_polling_http(exc.status_code):
                        time.sleep(poll_interval)
                        continue
                    raise
                code, _, _ = _extract_status_fields(status)
                if code == 200:
                    upo_bytes = client.sessions.get_session_invoice_upo_by_ref(
                        session_ref, invoice_ref, access_token=access_token
                    )
                    target = (
                        _save_bytes(
                            _resolve_output_path(
                                out or ".",
                                default_filename=f"upo-{session_ref}-{invoice_ref}.xml",
                            ),
                            upo_bytes,
                            overwrite=overwrite,
                        )
                        if out
                        else None
                    )
                    return {
                        "session_ref": session_ref,
                        "invoice_ref": invoice_ref,
                        "path": str(target) if target else "",
                        "bytes": len(upo_bytes),
                    }

            elif detected_upo_ref:
                try:
                    upo_bytes = client.sessions.get_session_upo(
                        session_ref, detected_upo_ref, access_token=access_token
                    )
                except KsefHttpError as exc:
                    if _is_transient_polling_http(exc.status_code):
                        time.sleep(poll_interval)
                        continue
                    raise
                target = (
                    _save_bytes(
                        _resolve_output_path(
                            out or ".",
                            default_filename=f"upo-{session_ref}-{detected_upo_ref}.xml",
                        ),
                        upo_bytes,
                        overwrite=overwrite,
                    )
                    if out
                    else None
                )
                return {
                    "session_ref": session_ref,
                    "upo_ref": detected_upo_ref,
                    "path": str(target) if target else "",
                    "bytes": len(upo_bytes),
                }

            else:
                try:
                    session_status = client.sessions.get_session_status(
                        session_ref,
                        access_token=access_token,
                    )
                except KsefHttpError as exc:
                    if _is_transient_polling_http(exc.status_code):
                        time.sleep(poll_interval)
                        continue
                    raise
                detected_upo_ref = _extract_upo_reference(session_status) or None

            time.sleep(poll_interval)

    raise CliError(
        "UPO is not available within max attempts.",
        ExitCode.RETRY_EXHAUSTED,
        "Increase --max-attempts or retry later.",
    )


def send_online_invoice(
    *,
    profile: str,
    base_url: str,
    invoice: str,
    system_code: str,
    schema_version: str,
    form_value: str,
    upo_v43: bool,
    wait_status: bool,
    wait_upo: bool,
    poll_interval: float,
    max_attempts: int,
    save_upo: str | None,
    save_upo_overwrite: bool = False,
) -> dict[str, Any]:
    access_token = _require_access_token(profile)
    if save_upo and not wait_upo:
        raise CliError(
            "Option --save-upo requires --wait-upo.",
            ExitCode.VALIDATION_ERROR,
            "Use --wait-upo when saving UPO from send command.",
        )
    if wait_status or wait_upo:
        _validate_polling_options(poll_interval, max_attempts)

    form_code = _build_form_code(system_code, schema_version, form_value)
    invoice_xml = _load_invoice_xml(invoice)

    with create_client(base_url, access_token=access_token) as client:
        certs = client.security.get_public_key_certificates()
        symmetric_cert = _select_certificate(certs, "SymmetricKeyEncryption")
        workflow = OnlineSessionWorkflow(client.sessions)

        session = workflow.open_session(
            form_code=form_code,
            public_certificate=symmetric_cert,
            access_token=access_token,
            upo_v43=upo_v43,
        )
        session_ref = session.session_reference_number

        send_error: Exception | None = None
        try:
            send_response = workflow.send_invoice(
                session_reference_number=session_ref,
                invoice_xml=invoice_xml,
                encryption_data=session.encryption_data,
                access_token=access_token,
            )
            invoice_ref = _extract_reference_number(send_response)
            if not invoice_ref:
                raise CliError(
                    "Send response does not contain invoice reference number.",
                    ExitCode.API_ERROR,
                    "Check KSeF response payload.",
                )

            result: dict[str, Any] = {
                "session_ref": session_ref,
                "invoice_ref": invoice_ref,
            }

            if wait_status or wait_upo:
                status_payload = _wait_for_invoice_status(
                    client=client,
                    session_ref=session_ref,
                    invoice_ref=invoice_ref,
                    access_token=access_token,
                    poll_interval=poll_interval,
                    max_attempts=max_attempts,
                )
                code, description, _ = _extract_status_fields(status_payload)
                result["status_code"] = code
                result["status_description"] = description
                result["ksef_number"] = _extract_ksef_number(status_payload)

            if wait_upo:
                upo_bytes = _wait_for_invoice_upo(
                    client=client,
                    session_ref=session_ref,
                    invoice_ref=invoice_ref,
                    access_token=access_token,
                    poll_interval=poll_interval,
                    max_attempts=max_attempts,
                )
                result["upo_bytes"] = len(upo_bytes)
                if save_upo:
                    upo_path = _save_bytes(
                        _resolve_output_path(
                            save_upo,
                            default_filename=f"upo-{session_ref}-{invoice_ref}.xml",
                        ),
                        upo_bytes,
                        overwrite=save_upo_overwrite,
                    )
                    result["upo_path"] = str(upo_path)
                else:
                    result["upo_path"] = ""

            return result
        except Exception as exc:
            send_error = exc
            raise
        finally:
            if send_error is None:
                workflow.close_session(session_ref, access_token)
            else:
                with suppress(Exception):
                    workflow.close_session(session_ref, access_token)


def send_batch_invoices(
    *,
    profile: str,
    base_url: str,
    zip_path: str | None,
    directory: str | None,
    system_code: str,
    schema_version: str,
    form_value: str,
    parallelism: int,
    upo_v43: bool,
    wait_status: bool,
    wait_upo: bool,
    poll_interval: float,
    max_attempts: int,
    save_upo: str | None,
    save_upo_overwrite: bool = False,
) -> dict[str, Any]:
    access_token = _require_access_token(profile)
    selected = [bool(zip_path), bool(directory)]
    if sum(1 for flag in selected if flag) != 1:
        raise CliError(
            "Select exactly one batch input source.",
            ExitCode.VALIDATION_ERROR,
            "Use one of: --zip or --dir.",
        )
    if parallelism <= 0:
        raise CliError(
            "Invalid parallelism.",
            ExitCode.VALIDATION_ERROR,
            "--parallelism must be greater than zero.",
        )
    if save_upo and not wait_upo:
        raise CliError(
            "Option --save-upo requires --wait-upo.",
            ExitCode.VALIDATION_ERROR,
            "Use --wait-upo when saving UPO from send command.",
        )
    if wait_status or wait_upo:
        _validate_polling_options(poll_interval, max_attempts)

    form_code = _build_form_code(system_code, schema_version, form_value)
    zip_bytes = (
        _load_batch_zip(zip_path or "") if zip_path else _build_zip_from_directory(directory or "")
    )

    with create_client(base_url, access_token=access_token) as client:
        certs = client.security.get_public_key_certificates()
        symmetric_cert = _select_certificate(certs, "SymmetricKeyEncryption")
        workflow = BatchSessionWorkflow(client.sessions, client.http_client)
        session_ref = workflow.open_upload_and_close(
            form_code=form_code,
            zip_bytes=zip_bytes,
            public_certificate=symmetric_cert,
            access_token=access_token,
            upo_v43=upo_v43,
            parallelism=parallelism,
        )

        result: dict[str, Any] = {
            "session_ref": session_ref,
        }

        if wait_status or wait_upo:
            session_status = _wait_for_session_status(
                client=client,
                session_ref=session_ref,
                access_token=access_token,
                poll_interval=poll_interval,
                max_attempts=max_attempts,
            )
            code, description, _ = _extract_status_fields(session_status)
            result["status_code"] = code
            result["status_description"] = description

            upo_ref = _extract_upo_reference(session_status)
            result["upo_ref"] = str(upo_ref or "")

            if wait_upo:
                if not upo_ref:
                    raise CliError(
                        "UPO reference number is not available in session status.",
                        ExitCode.RETRY_EXHAUSTED,
                        "Run `ksef upo wait --session-ref <SESSION_REF> --batch-auto`.",
                    )
                upo_bytes = _wait_for_batch_upo(
                    client=client,
                    session_ref=session_ref,
                    upo_ref=str(upo_ref),
                    access_token=access_token,
                    poll_interval=poll_interval,
                    max_attempts=max_attempts,
                )
                result["upo_bytes"] = len(upo_bytes)
                if save_upo:
                    upo_path = _save_bytes(
                        _resolve_output_path(
                            save_upo,
                            default_filename=f"upo-{session_ref}-{upo_ref}.xml",
                        ),
                        upo_bytes,
                        overwrite=save_upo_overwrite,
                    )
                    result["upo_path"] = str(upo_path)
                else:
                    result["upo_path"] = ""

        return result


def get_send_status(
    *,
    profile: str,
    base_url: str,
    session_ref: str,
    invoice_ref: str | None,
) -> dict[str, Any]:
    access_token = _require_access_token(profile)
    with create_client(base_url, access_token=access_token) as client:
        payload: Any
        if invoice_ref:
            payload = client.sessions.get_session_invoice_status(
                session_ref,
                invoice_ref,
                access_token=access_token,
            )
        else:
            payload = client.sessions.get_session_status(
                session_ref,
                access_token=access_token,
            )

    code, description, details = _extract_status_fields(payload)
    return {
        "session_ref": session_ref,
        "invoice_ref": invoice_ref or "",
        "status_code": code,
        "status_description": description,
        "status_details": details,
        "ksef_number": _extract_ksef_number(payload),
        "upo_ref": _extract_upo_reference(payload),
        "response": _to_output_payload(payload),
    }


def run_export(
    *,
    profile: str,
    base_url: str,
    date_from: str | None,
    date_to: str | None,
    date_type: str = m.InvoiceQueryDateType.ISSUE.value,
    sort_order: str = "Asc",
    subject_type: str,
    restrict_to_permanent_storage_hwm_date: bool = False,
    only_metadata: bool = False,
    poll_interval: float,
    max_attempts: int,
    out: str,
) -> dict[str, Any]:
    access_token = _require_access_token(profile)
    _validate_polling_options(poll_interval, max_attempts)
    from_iso, to_iso = _normalize_date_range(date_from, date_to)
    date_type_enum = _require_invoice_query_date_type(date_type)
    normalized_sort_order = _require_export_sort_order(sort_order)
    out_dir = Path(out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    with create_client(base_url, access_token=access_token) as client:
        certs = client.security.get_public_key_certificates()
        symmetric_cert = _select_certificate(certs, "SymmetricKeyEncryption")
        encryption = build_encryption_data(symmetric_cert)
        encryption_info = _require_encryption_info(encryption)
        payload = m.InvoiceExportRequest(
            encryption=m.EncryptionInfo(
                encrypted_symmetric_key=encryption_info.encrypted_symmetric_key,
                initialization_vector=encryption_info.initialization_vector,
            ),
            only_metadata=only_metadata,
            filters=m.InvoiceQueryFilters(
                subject_type=_require_invoice_query_subject_type(subject_type),
                date_range=m.InvoiceQueryDateRange(
                    date_type=date_type_enum,
                    from_=from_iso,
                    to=to_iso,
                    restrict_to_permanent_storage_hwm_date=restrict_to_permanent_storage_hwm_date,
                ),
            ),
        )
        start = client.invoices.export_invoices(
            payload,
            access_token=access_token,
        )
        reference_number = _extract_reference_number(start)
        if not reference_number:
            raise CliError(
                "Export response does not contain reference number.",
                ExitCode.API_ERROR,
                "Check KSeF response payload.",
            )

        export_status = _wait_for_export_status(
            client=client,
            reference_number=reference_number,
            access_token=access_token,
            poll_interval=poll_interval,
            max_attempts=max_attempts,
        )
        package = _get_value(export_status, "package")
        if package is None:
            raise CliError(
                "Export completed but package metadata is missing.",
                ExitCode.API_ERROR,
                "Check KSeF export status response.",
            )
        if isinstance(package, dict):
            package = m.InvoicePackage.from_dict(package)

        workflow = ExportWorkflow(client.invoices, client.http_client)
        processed = workflow.download_and_process_package(package, encryption)

    metadata_path = out_dir / "_metadata.json"
    metadata_payload = {"invoices": processed.metadata_summaries}
    metadata_path.write_text(
        json.dumps(metadata_payload, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )

    files_saved = 0
    for file_name, content in processed.invoice_xml_files.items():
        file_path = _safe_child_path(out_dir, file_name)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")
        files_saved += 1

    code, description, _ = _extract_status_fields(export_status)
    return {
        "reference_number": reference_number,
        "status_code": code,
        "status_description": description,
        "metadata_file": str(metadata_path),
        "metadata_count": len(processed.metadata_summaries),
        "xml_files_count": files_saved,
        "only_metadata": only_metadata,
        "out_dir": str(out_dir),
        "from": from_iso,
        "to": to_iso,
        "date_type": date_type_enum.value,
        "sort_order": normalized_sort_order,
        "restrict_to_permanent_storage_hwm_date": restrict_to_permanent_storage_hwm_date,
    }


def get_export_status(
    *,
    profile: str,
    base_url: str,
    reference: str,
) -> dict[str, Any]:
    access_token = _require_access_token(profile)
    with create_client(base_url, access_token=access_token) as client:
        payload = client.invoices.get_export_status(reference, access_token=access_token)
    code, description, details = _extract_status_fields(payload)
    return {
        "reference_number": reference,
        "status_code": code,
        "status_description": description,
        "status_details": details,
        "response": _to_output_payload(payload),
    }


def run_health_check(
    *,
    profile: str,
    base_url: str,
    dry_run: bool,
    check_auth: bool,
    check_certs: bool,
) -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    checks.append(
        {
            "name": "base_url",
            "status": "PASS" if bool(base_url.strip()) else "FAIL",
            "message": base_url.strip() or "Missing base URL",
        }
    )

    token_present = bool(get_tokens(profile))
    checks.append(
        {
            "name": "auth",
            "status": "PASS" if token_present else "WARN",
            "message": "Token available" if token_present else "No stored token",
        }
    )
    if check_auth and not token_present:
        raise CliError(
            "Authentication token is required for this health check.",
            ExitCode.AUTH_ERROR,
            "Run `ksef auth login-token` first.",
        )

    if check_certs or dry_run:
        if not token_present:
            if check_certs:
                raise CliError(
                    "Authentication token is required for certificate check.",
                    ExitCode.AUTH_ERROR,
                    "Run `ksef auth login-token` first.",
                )
            checks.append(
                {
                    "name": "certificates",
                    "status": "WARN",
                    "message": "Skipped certificate check because no token is available.",
                }
            )
        else:
            token_for_client = _require_access_token(profile)
            with create_client(base_url, access_token=token_for_client) as client:
                certs = client.security.get_public_key_certificates()
            usages: set[str] = set()
            for cert in certs:
                usages.update(_as_string_list(_get_value(cert, "usage", default=[])))
            required = {"KsefTokenEncryption", "SymmetricKeyEncryption"}
            missing = sorted(required - usages)
            checks.append(
                {
                    "name": "certificates",
                    "status": "PASS" if not missing else "FAIL",
                    "message": "Required certificates available."
                    if not missing
                    else f"Missing: {', '.join(missing)}",
                }
            )
            if check_certs and missing:
                raise CliError(
                    "Required certificates are not available.",
                    ExitCode.API_ERROR,
                    "Check KSeF environment availability and try again.",
                )

    overall = "PASS"
    if any(item["status"] == "FAIL" for item in checks):
        overall = "FAIL"
    elif any(item["status"] == "WARN" for item in checks):
        overall = "WARN"

    return {
        "profile": profile,
        "dry_run": dry_run,
        "overall": overall,
        "checks": checks,
    }
