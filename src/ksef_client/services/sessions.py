from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from .. import models as m
from .batch import encrypt_batch_parts
from .crypto import EncryptionData, build_send_invoice_request

_SESSION_STATE_SCHEMA_VERSION = 1


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_base64(value: str, *, field_name: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError(f"Invalid {field_name}: expected Base64 data.") from exc


def _require_dict(value: Any, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Invalid {field_name}: expected JSON object.")
    return value


def _require_list(value: Any, *, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"Invalid {field_name}: expected JSON array.")
    return value


def _validate_session_header(*, payload: dict[str, Any], kind: str) -> None:
    schema_version = payload.get("schema_version")
    if schema_version != _SESSION_STATE_SCHEMA_VERSION:
        raise ValueError(
            "Unsupported session state schema_version: "
            f"{schema_version!r}. Expected {_SESSION_STATE_SCHEMA_VERSION}."
        )
    payload_kind = payload.get("kind")
    if payload_kind != kind:
        raise ValueError(f"Invalid session state kind: {payload_kind!r}. Expected {kind!r}.")


def _serialize_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


class _SessionsClient(Protocol):
    def send_online_invoice(
        self,
        reference_number: str,
        request_payload: m.SendInvoiceRequest,
        *,
        access_token: str | None = None,
    ) -> m.SendInvoiceResponse: ...

    def close_online_session(
        self, reference_number: str, access_token: str | None = None
    ) -> None: ...

    def close_batch_session(
        self, reference_number: str, access_token: str | None = None
    ) -> None: ...

    def get_session_status(
        self, reference_number: str, access_token: str | None = None
    ) -> m.SessionStatusResponse: ...

    def get_session_invoices(
        self,
        reference_number: str,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse: ...

    def get_session_failed_invoices(
        self,
        reference_number: str,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse: ...

    def get_session_invoice_status(
        self,
        reference_number: str,
        invoice_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> m.SessionInvoiceStatusResponse: ...

    def get_session_invoice_upo_by_ref(
        self,
        reference_number: str,
        invoice_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes: ...

    def get_session_invoice_upo_by_ksef(
        self,
        reference_number: str,
        ksef_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes: ...

    def get_session_upo(
        self,
        reference_number: str,
        upo_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes: ...


class _AsyncSessionsClient(Protocol):
    async def send_online_invoice(
        self,
        reference_number: str,
        request_payload: m.SendInvoiceRequest,
        *,
        access_token: str | None = None,
    ) -> m.SendInvoiceResponse: ...

    async def close_online_session(
        self, reference_number: str, access_token: str | None = None
    ) -> None: ...

    async def close_batch_session(
        self, reference_number: str, access_token: str | None = None
    ) -> None: ...

    async def get_session_status(
        self, reference_number: str, access_token: str | None = None
    ) -> m.SessionStatusResponse: ...

    async def get_session_invoices(
        self,
        reference_number: str,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse: ...

    async def get_session_failed_invoices(
        self,
        reference_number: str,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse: ...

    async def get_session_invoice_status(
        self,
        reference_number: str,
        invoice_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> m.SessionInvoiceStatusResponse: ...

    async def get_session_invoice_upo_by_ref(
        self,
        reference_number: str,
        invoice_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes: ...

    async def get_session_invoice_upo_by_ksef(
        self,
        reference_number: str,
        ksef_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes: ...

    async def get_session_upo(
        self,
        reference_number: str,
        upo_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes: ...


class _BatchUploader(Protocol):
    def upload_parts(
        self,
        part_upload_requests: list[m.PartUploadRequest],
        parts: Sequence[bytes] | Sequence[tuple[int, bytes]],
        *,
        parallelism: int = 1,
        skip_ordinals: Collection[int] | None = None,
        progress_callback: Callable[[int], None] | None = None,
    ) -> None: ...


class _AsyncBatchUploader(Protocol):
    async def upload_parts(
        self,
        part_upload_requests: list[m.PartUploadRequest],
        parts: Sequence[bytes] | Sequence[tuple[int, bytes]],
        *,
        skip_ordinals: Collection[int] | None = None,
        progress_callback: Callable[[int], None] | None = None,
    ) -> None: ...


@dataclass(frozen=True)
class OnlineSessionState:
    reference_number: str
    form_code: m.FormCode
    valid_until: str | None
    symmetric_key_base64: str
    iv_base64: str
    upo_v43: bool = False
    schema_version: int = _SESSION_STATE_SCHEMA_VERSION
    kind: str = "online"

    def __post_init__(self) -> None:
        if self.schema_version != _SESSION_STATE_SCHEMA_VERSION:
            raise ValueError(
                "Unsupported session state schema_version: "
                f"{self.schema_version!r}. Expected {_SESSION_STATE_SCHEMA_VERSION}."
            )
        if self.kind != "online":
            raise ValueError(f"Invalid session state kind: {self.kind!r}. Expected 'online'.")
        _ = self.symmetric_key
        _ = self.iv

    @property
    def symmetric_key(self) -> bytes:
        return _decode_base64(self.symmetric_key_base64, field_name="symmetric_key_base64")

    @property
    def iv(self) -> bytes:
        return _decode_base64(self.iv_base64, field_name="iv_base64")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "reference_number": self.reference_number,
            "form_code": self.form_code.to_dict(),
            "valid_until": self.valid_until,
            "symmetric_key_base64": self.symmetric_key_base64,
            "iv_base64": self.iv_base64,
            "upo_v43": self.upo_v43,
        }

    def to_json(self) -> str:
        return _serialize_json(self.to_dict())

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> OnlineSessionState:
        _validate_session_header(payload=payload, kind="online")
        form_code_payload = _require_dict(payload.get("form_code"), field_name="form_code")
        reference_number = payload.get("reference_number")
        if not isinstance(reference_number, str) or reference_number.strip() == "":
            raise ValueError("Invalid reference_number: expected non-empty string.")
        valid_until = payload.get("valid_until")
        if valid_until is not None and not isinstance(valid_until, str):
            raise ValueError("Invalid valid_until: expected string or null.")
        symmetric_key_base64 = payload.get("symmetric_key_base64")
        if not isinstance(symmetric_key_base64, str):
            raise ValueError("Invalid symmetric_key_base64: expected string.")
        iv_base64 = payload.get("iv_base64")
        if not isinstance(iv_base64, str):
            raise ValueError("Invalid iv_base64: expected string.")
        return cls(
            reference_number=reference_number,
            form_code=m.FormCode.from_dict(form_code_payload),
            valid_until=valid_until,
            symmetric_key_base64=symmetric_key_base64,
            iv_base64=iv_base64,
            upo_v43=bool(payload.get("upo_v43", False)),
        )

    @classmethod
    def from_json(cls, payload: str) -> OnlineSessionState:
        data = json.loads(payload)
        return cls.from_dict(_require_dict(data, field_name="session state"))

    @classmethod
    def from_runtime(
        cls,
        *,
        reference_number: str,
        form_code: m.FormCode,
        valid_until: str | None,
        encryption_data: EncryptionData,
        upo_v43: bool,
    ) -> OnlineSessionState:
        return cls(
            reference_number=reference_number,
            form_code=form_code,
            valid_until=valid_until,
            symmetric_key_base64=_encode_base64(encryption_data.key),
            iv_base64=_encode_base64(encryption_data.iv),
            upo_v43=upo_v43,
        )


@dataclass(frozen=True)
class BatchSessionState:
    reference_number: str
    form_code: m.FormCode
    batch_file: m.BatchFileInfo
    part_upload_requests: list[m.PartUploadRequest]
    symmetric_key_base64: str
    iv_base64: str
    upo_v43: bool = False
    offline_mode: bool | None = None
    schema_version: int = _SESSION_STATE_SCHEMA_VERSION
    kind: str = "batch"

    def __post_init__(self) -> None:
        if self.schema_version != _SESSION_STATE_SCHEMA_VERSION:
            raise ValueError(
                "Unsupported session state schema_version: "
                f"{self.schema_version!r}. Expected {_SESSION_STATE_SCHEMA_VERSION}."
            )
        if self.kind != "batch":
            raise ValueError(f"Invalid session state kind: {self.kind!r}. Expected 'batch'.")
        _ = self.symmetric_key
        _ = self.iv

    @property
    def symmetric_key(self) -> bytes:
        return _decode_base64(self.symmetric_key_base64, field_name="symmetric_key_base64")

    @property
    def iv(self) -> bytes:
        return _decode_base64(self.iv_base64, field_name="iv_base64")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "reference_number": self.reference_number,
            "form_code": self.form_code.to_dict(),
            "batch_file": self.batch_file.to_dict(),
            "part_upload_requests": [item.to_dict() for item in self.part_upload_requests],
            "symmetric_key_base64": self.symmetric_key_base64,
            "iv_base64": self.iv_base64,
            "upo_v43": self.upo_v43,
            "offline_mode": self.offline_mode,
        }

    def to_json(self) -> str:
        return _serialize_json(self.to_dict())

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> BatchSessionState:
        _validate_session_header(payload=payload, kind="batch")
        form_code_payload = _require_dict(payload.get("form_code"), field_name="form_code")
        batch_file_payload = _require_dict(payload.get("batch_file"), field_name="batch_file")
        requests_payload = _require_list(
            payload.get("part_upload_requests"),
            field_name="part_upload_requests",
        )
        reference_number = payload.get("reference_number")
        if not isinstance(reference_number, str) or reference_number.strip() == "":
            raise ValueError("Invalid reference_number: expected non-empty string.")
        symmetric_key_base64 = payload.get("symmetric_key_base64")
        if not isinstance(symmetric_key_base64, str):
            raise ValueError("Invalid symmetric_key_base64: expected string.")
        iv_base64 = payload.get("iv_base64")
        if not isinstance(iv_base64, str):
            raise ValueError("Invalid iv_base64: expected string.")
        offline_mode = payload.get("offline_mode")
        if offline_mode is not None and not isinstance(offline_mode, bool):
            raise ValueError("Invalid offline_mode: expected bool or null.")
        return cls(
            reference_number=reference_number,
            form_code=m.FormCode.from_dict(form_code_payload),
            batch_file=m.BatchFileInfo.from_dict(batch_file_payload),
            part_upload_requests=[
                m.PartUploadRequest.from_dict(
                    _require_dict(item, field_name="part_upload_requests[]")
                )
                for item in requests_payload
            ],
            symmetric_key_base64=symmetric_key_base64,
            iv_base64=iv_base64,
            upo_v43=bool(payload.get("upo_v43", False)),
            offline_mode=offline_mode,
        )

    @classmethod
    def from_json(cls, payload: str) -> BatchSessionState:
        data = json.loads(payload)
        return cls.from_dict(_require_dict(data, field_name="session state"))

    @classmethod
    def from_runtime(
        cls,
        *,
        reference_number: str,
        form_code: m.FormCode,
        batch_file: m.BatchFileInfo,
        part_upload_requests: list[m.PartUploadRequest],
        encryption_data: EncryptionData,
        upo_v43: bool,
        offline_mode: bool | None,
    ) -> BatchSessionState:
        return cls(
            reference_number=reference_number,
            form_code=form_code,
            batch_file=batch_file,
            part_upload_requests=list(part_upload_requests),
            symmetric_key_base64=_encode_base64(encryption_data.key),
            iv_base64=_encode_base64(encryption_data.iv),
            upo_v43=upo_v43,
            offline_mode=offline_mode,
        )


def _resolve_access_token(
    explicit_access_token: str | None,
    default_access_token: str | None,
) -> str | None:
    return explicit_access_token if explicit_access_token is not None else default_access_token


def _restore_encryption_data(
    *, symmetric_key_base64: str, iv_base64: str, encryption_info: m.EncryptionInfo | None = None
) -> EncryptionData:
    return EncryptionData(
        key=_decode_base64(symmetric_key_base64, field_name="symmetric_key_base64"),
        iv=_decode_base64(iv_base64, field_name="iv_base64"),
        encryption_info=encryption_info,
    )


@dataclass(frozen=True)
class OnlineSessionHandle:
    _sessions: _SessionsClient
    reference_number: str
    form_code: m.FormCode
    valid_until: str | None
    encryption_data: EncryptionData
    _access_token: str | None = None
    upo_v43: bool = False

    @property
    def session_reference_number(self) -> str:
        return self.reference_number

    def get_state(self) -> OnlineSessionState:
        return OnlineSessionState.from_runtime(
            reference_number=self.reference_number,
            form_code=self.form_code,
            valid_until=self.valid_until,
            encryption_data=self.encryption_data,
            upo_v43=self.upo_v43,
        )

    def send_invoice(
        self,
        invoice_xml: bytes,
        *,
        offline_mode: bool | None = None,
        hash_of_corrected_invoice: str | None = None,
        access_token: str | None = None,
    ) -> m.SendInvoiceResponse:
        request_payload = build_send_invoice_request(
            invoice_xml,
            self.encryption_data.key,
            self.encryption_data.iv,
            offline_mode=offline_mode,
            hash_of_corrected_invoice=hash_of_corrected_invoice,
        )
        return self._sessions.send_online_invoice(
            self.reference_number,
            request_payload,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def get_status(self, *, access_token: str | None = None) -> m.SessionStatusResponse:
        return self._sessions.get_session_status(
            self.reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def list_invoices(
        self,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse:
        return self._sessions.get_session_invoices(
            self.reference_number,
            page_size=page_size,
            continuation_token=continuation_token,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def list_failed_invoices(
        self,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse:
        return self._sessions.get_session_failed_invoices(
            self.reference_number,
            page_size=page_size,
            continuation_token=continuation_token,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def get_invoice_status(
        self,
        invoice_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> m.SessionInvoiceStatusResponse:
        return self._sessions.get_session_invoice_status(
            self.reference_number,
            invoice_reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def get_invoice_upo_by_ref(
        self,
        invoice_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes:
        return self._sessions.get_session_invoice_upo_by_ref(
            self.reference_number,
            invoice_reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def get_invoice_upo_by_ksef(
        self,
        ksef_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes:
        return self._sessions.get_session_invoice_upo_by_ksef(
            self.reference_number,
            ksef_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def get_upo(
        self,
        upo_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes:
        return self._sessions.get_session_upo(
            self.reference_number,
            upo_reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def close(self, *, access_token: str | None = None) -> None:
        self._sessions.close_online_session(
            self.reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    @classmethod
    def from_state(
        cls,
        state: OnlineSessionState,
        *,
        sessions_client: _SessionsClient,
        access_token: str | None = None,
    ) -> OnlineSessionHandle:
        return cls(
            _sessions=sessions_client,
            reference_number=state.reference_number,
            form_code=state.form_code,
            valid_until=state.valid_until,
            encryption_data=_restore_encryption_data(
                symmetric_key_base64=state.symmetric_key_base64,
                iv_base64=state.iv_base64,
            ),
            _access_token=access_token,
            upo_v43=state.upo_v43,
        )


@dataclass(frozen=True)
class AsyncOnlineSessionHandle:
    _sessions: _AsyncSessionsClient
    reference_number: str
    form_code: m.FormCode
    valid_until: str | None
    encryption_data: EncryptionData
    _access_token: str | None = None
    upo_v43: bool = False

    @property
    def session_reference_number(self) -> str:
        return self.reference_number

    def get_state(self) -> OnlineSessionState:
        return OnlineSessionState.from_runtime(
            reference_number=self.reference_number,
            form_code=self.form_code,
            valid_until=self.valid_until,
            encryption_data=self.encryption_data,
            upo_v43=self.upo_v43,
        )

    async def send_invoice(
        self,
        invoice_xml: bytes,
        *,
        offline_mode: bool | None = None,
        hash_of_corrected_invoice: str | None = None,
        access_token: str | None = None,
    ) -> m.SendInvoiceResponse:
        request_payload = build_send_invoice_request(
            invoice_xml,
            self.encryption_data.key,
            self.encryption_data.iv,
            offline_mode=offline_mode,
            hash_of_corrected_invoice=hash_of_corrected_invoice,
        )
        return await self._sessions.send_online_invoice(
            self.reference_number,
            request_payload,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def get_status(self, *, access_token: str | None = None) -> m.SessionStatusResponse:
        return await self._sessions.get_session_status(
            self.reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def list_invoices(
        self,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse:
        return await self._sessions.get_session_invoices(
            self.reference_number,
            page_size=page_size,
            continuation_token=continuation_token,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def list_failed_invoices(
        self,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse:
        return await self._sessions.get_session_failed_invoices(
            self.reference_number,
            page_size=page_size,
            continuation_token=continuation_token,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def get_invoice_status(
        self,
        invoice_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> m.SessionInvoiceStatusResponse:
        return await self._sessions.get_session_invoice_status(
            self.reference_number,
            invoice_reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def get_invoice_upo_by_ref(
        self,
        invoice_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes:
        return await self._sessions.get_session_invoice_upo_by_ref(
            self.reference_number,
            invoice_reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def get_invoice_upo_by_ksef(
        self,
        ksef_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes:
        return await self._sessions.get_session_invoice_upo_by_ksef(
            self.reference_number,
            ksef_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def get_upo(
        self,
        upo_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes:
        return await self._sessions.get_session_upo(
            self.reference_number,
            upo_reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def close(self, *, access_token: str | None = None) -> None:
        await self._sessions.close_online_session(
            self.reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    @classmethod
    def from_state(
        cls,
        state: OnlineSessionState,
        *,
        sessions_client: _AsyncSessionsClient,
        access_token: str | None = None,
    ) -> AsyncOnlineSessionHandle:
        return cls(
            _sessions=sessions_client,
            reference_number=state.reference_number,
            form_code=state.form_code,
            valid_until=state.valid_until,
            encryption_data=_restore_encryption_data(
                symmetric_key_base64=state.symmetric_key_base64,
                iv_base64=state.iv_base64,
            ),
            _access_token=access_token,
            upo_v43=state.upo_v43,
        )


def _indexed_parts(parts: Sequence[bytes]) -> list[tuple[int, bytes]]:
    return [(index, part) for index, part in enumerate(parts, start=1)]


@dataclass(frozen=True)
class BatchSessionHandle:
    _sessions: _SessionsClient
    _uploader: _BatchUploader
    reference_number: str
    form_code: m.FormCode
    batch_file: m.BatchFileInfo
    part_upload_requests: list[m.PartUploadRequest]
    encryption_data: EncryptionData
    _access_token: str | None = None
    upo_v43: bool = False
    offline_mode: bool | None = None
    _encrypted_parts: list[tuple[int, bytes]] | None = None

    @property
    def session_reference_number(self) -> str:
        return self.reference_number

    def get_state(self) -> BatchSessionState:
        return BatchSessionState.from_runtime(
            reference_number=self.reference_number,
            form_code=self.form_code,
            batch_file=self.batch_file,
            part_upload_requests=self.part_upload_requests,
            encryption_data=self.encryption_data,
            upo_v43=self.upo_v43,
            offline_mode=self.offline_mode,
        )

    def upload_parts(
        self,
        *,
        parallelism: int = 1,
        skip_ordinals: Collection[int] | None = None,
        progress_callback: Callable[[int], None] | None = None,
    ) -> None:
        if self._encrypted_parts is None:
            raise ValueError(
                "Batch session handle has no prepared parts attached. "
                "Resume the session with zip_bytes or open it via "
                "BatchSessionWorkflow.open_session()."
            )
        self._uploader.upload_parts(
            self.part_upload_requests,
            self._encrypted_parts,
            parallelism=parallelism,
            skip_ordinals=skip_ordinals,
            progress_callback=progress_callback,
        )

    def get_status(self, *, access_token: str | None = None) -> m.SessionStatusResponse:
        return self._sessions.get_session_status(
            self.reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def list_invoices(
        self,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse:
        return self._sessions.get_session_invoices(
            self.reference_number,
            page_size=page_size,
            continuation_token=continuation_token,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def list_failed_invoices(
        self,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse:
        return self._sessions.get_session_failed_invoices(
            self.reference_number,
            page_size=page_size,
            continuation_token=continuation_token,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def get_upo(
        self,
        upo_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes:
        return self._sessions.get_session_upo(
            self.reference_number,
            upo_reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    def close(self, *, access_token: str | None = None) -> None:
        self._sessions.close_batch_session(
            self.reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    @classmethod
    def from_state(
        cls,
        state: BatchSessionState,
        *,
        sessions_client: _SessionsClient,
        uploader: _BatchUploader,
        access_token: str | None = None,
        zip_bytes: bytes | None = None,
    ) -> BatchSessionHandle:
        encryption_data = _restore_encryption_data(
            symmetric_key_base64=state.symmetric_key_base64,
            iv_base64=state.iv_base64,
        )
        encrypted_parts: list[tuple[int, bytes]] | None = None
        if zip_bytes is not None:
            prepared_parts, prepared_batch_file = encrypt_batch_parts(
                zip_bytes,
                encryption_data.key,
                encryption_data.iv,
            )
            if prepared_batch_file.to_dict() != state.batch_file.to_dict():
                raise ValueError(
                    "Provided ZIP content does not match stored batch session state."
                )
            encrypted_parts = _indexed_parts(prepared_parts)
        return cls(
            _sessions=sessions_client,
            _uploader=uploader,
            reference_number=state.reference_number,
            form_code=state.form_code,
            batch_file=state.batch_file,
            part_upload_requests=list(state.part_upload_requests),
            encryption_data=encryption_data,
            _access_token=access_token,
            upo_v43=state.upo_v43,
            offline_mode=state.offline_mode,
            _encrypted_parts=encrypted_parts,
        )


@dataclass(frozen=True)
class AsyncBatchSessionHandle:
    _sessions: _AsyncSessionsClient
    _uploader: _AsyncBatchUploader
    reference_number: str
    form_code: m.FormCode
    batch_file: m.BatchFileInfo
    part_upload_requests: list[m.PartUploadRequest]
    encryption_data: EncryptionData
    _access_token: str | None = None
    upo_v43: bool = False
    offline_mode: bool | None = None
    _encrypted_parts: list[tuple[int, bytes]] | None = None

    @property
    def session_reference_number(self) -> str:
        return self.reference_number

    def get_state(self) -> BatchSessionState:
        return BatchSessionState.from_runtime(
            reference_number=self.reference_number,
            form_code=self.form_code,
            batch_file=self.batch_file,
            part_upload_requests=self.part_upload_requests,
            encryption_data=self.encryption_data,
            upo_v43=self.upo_v43,
            offline_mode=self.offline_mode,
        )

    async def upload_parts(
        self,
        *,
        skip_ordinals: Collection[int] | None = None,
        progress_callback: Callable[[int], None] | None = None,
    ) -> None:
        if self._encrypted_parts is None:
            raise ValueError(
                "Batch session handle has no prepared parts attached. "
                "Resume the session with zip_bytes or open it via "
                "AsyncBatchSessionWorkflow.open_session()."
            )
        await self._uploader.upload_parts(
            self.part_upload_requests,
            self._encrypted_parts,
            skip_ordinals=skip_ordinals,
            progress_callback=progress_callback,
        )

    async def get_status(self, *, access_token: str | None = None) -> m.SessionStatusResponse:
        return await self._sessions.get_session_status(
            self.reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def list_invoices(
        self,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse:
        return await self._sessions.get_session_invoices(
            self.reference_number,
            page_size=page_size,
            continuation_token=continuation_token,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def list_failed_invoices(
        self,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> m.SessionInvoicesResponse:
        return await self._sessions.get_session_failed_invoices(
            self.reference_number,
            page_size=page_size,
            continuation_token=continuation_token,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def get_upo(
        self,
        upo_reference_number: str,
        *,
        access_token: str | None = None,
    ) -> bytes:
        return await self._sessions.get_session_upo(
            self.reference_number,
            upo_reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    async def close(self, *, access_token: str | None = None) -> None:
        await self._sessions.close_batch_session(
            self.reference_number,
            access_token=_resolve_access_token(access_token, self._access_token),
        )

    @classmethod
    def from_state(
        cls,
        state: BatchSessionState,
        *,
        sessions_client: _AsyncSessionsClient,
        uploader: _AsyncBatchUploader,
        access_token: str | None = None,
        zip_bytes: bytes | None = None,
    ) -> AsyncBatchSessionHandle:
        encryption_data = _restore_encryption_data(
            symmetric_key_base64=state.symmetric_key_base64,
            iv_base64=state.iv_base64,
        )
        encrypted_parts: list[tuple[int, bytes]] | None = None
        if zip_bytes is not None:
            prepared_parts, prepared_batch_file = encrypt_batch_parts(
                zip_bytes,
                encryption_data.key,
                encryption_data.iv,
            )
            if prepared_batch_file.to_dict() != state.batch_file.to_dict():
                raise ValueError(
                    "Provided ZIP content does not match stored batch session state."
                )
            encrypted_parts = _indexed_parts(prepared_parts)
        return cls(
            _sessions=sessions_client,
            _uploader=uploader,
            reference_number=state.reference_number,
            form_code=state.form_code,
            batch_file=state.batch_file,
            part_upload_requests=list(state.part_upload_requests),
            encryption_data=encryption_data,
            _access_token=access_token,
            upo_v43=state.upo_v43,
            offline_mode=state.offline_mode,
            _encrypted_parts=encrypted_parts,
        )


__all__ = [
    "OnlineSessionState",
    "BatchSessionState",
    "OnlineSessionHandle",
    "BatchSessionHandle",
    "AsyncOnlineSessionHandle",
    "AsyncBatchSessionHandle",
]
