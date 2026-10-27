"""Typed, resumable polling shared by the high-level sync and async facades."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections.abc import Awaitable, Callable
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import ErrorCode, KsefError, KsefHttpError
from .rate_limiting import KsefRateLimitWaitTimeout
from .request_control import request_control, wait_seconds, wait_seconds_async

T = TypeVar("T")
STATE_MAX_BYTES = 4 * 1024 * 1024
STATE_ENVELOPE = b"KSEFSTATE\x01"
KINDS = frozenset(
    {"auth", "invoice", "online", "batch", "upo", "export", "permission", "certificate"}
)
PENDING = {
    "auth": {100},
    "invoice": {100, 150},
    "online": {100, 170},
    "batch": {100, 150},
    "upo": {100, 150, 170, 200},
    "export": {100},
    "permission": {100},
    "certificate": {100},
}
FAILURES = {
    "auth": {415, 425, 450, 460, 470, 480, 500, 550},
    "invoice": {405, 410, 415, 430, 435, 440, 450, 500, 550},
    "online": {415, 440, 445, 500, 550},
    "batch": {405, 415, 420, 430, 435, 440, 445, 500, 550},
    "export": {210, 415, 420, 500, 550},
    "permission": {400, 410, 420, 430, 440, 450, 500, 550},
    "certificate": {400, 500, 550},
}


def environment_key(base_url: str) -> str:
    return hashlib.sha256(base_url.rstrip("/").encode()).hexdigest()


@dataclass(frozen=True)
class OperationState:
    """Explicit persistence data; payload may contain credentials or encryption keys.

    Store only in an application-controlled secret store. Never accept this state
    as an authorization credential. It is neither signed nor encrypted.
    """

    kind: str
    environment: str = field(repr=False)
    context_key: str = field(repr=False)
    reference_number: str = field(repr=False)
    payload: dict[str, Any] = field(default_factory=dict, repr=False)
    version: int = 1

    def __post_init__(self) -> None:
        if (
            type(self.version) is not int
            or self.version != 1
            or type(self.kind) is not str
            or self.kind not in KINDS
        ):
            raise ValueError("Unsupported operation state")
        if any(
            type(v) is not str or not v or len(v) > 4096
            for v in (self.environment, self.context_key, self.reference_number)
        ):
            raise ValueError("Invalid operation identity")
        if type(self.payload) is not dict:
            raise ValueError("Invalid operation payload")
        if re.fullmatch(r"[A-Za-z0-9_-]{1,256}", self.reference_number) is None:
            raise ValueError("Invalid operation reference")
        if self.kind == "invoice" and (
            type(self.payload.get("session_reference")) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,256}", self.payload["session_reference"]) is None
        ):
            raise ValueError("Invalid invoice session reference")
        # Validate JSON and bound input before copying or replaying it.
        try:
            encoded = json.dumps(self.to_dict(), allow_nan=False).encode()
        except (TypeError, ValueError, RecursionError):
            raise ValueError("Operation payload must contain finite JSON values") from None
        if len(encoded) > STATE_MAX_BYTES:
            raise ValueError("Operation state exceeds size limit")
        object.__setattr__(self, "payload", deepcopy(self.payload))

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "kind": self.kind,
            "environment": self.environment,
            "context_key": self.context_key,
            "reference_number": self.reference_number,
            "payload": deepcopy(self.payload),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), allow_nan=False)

    def to_encrypted_bytes(self, encryption_key: bytes) -> bytes:
        """Authenticated persistence; the application keeps the key separately."""
        if type(encryption_key) is not bytes or len(encryption_key) != 32:
            raise ValueError("State encryption requires a 32-byte key")
        nonce = os.urandom(12)
        return (
            STATE_ENVELOPE
            + nonce
            + AESGCM(encryption_key).encrypt(nonce, self.to_json().encode(), STATE_ENVELOPE)
        )

    @classmethod
    def from_json(cls, value: str) -> OperationState:
        if type(value) is not str or len(value.encode()) > STATE_MAX_BYTES:
            raise ValueError("Invalid or oversized operation state JSON")
        try:
            payload = json.loads(value)
        except (ValueError, RecursionError):
            raise ValueError("Invalid operation state JSON") from None
        return cls.from_dict(payload)

    @classmethod
    def from_encrypted_bytes(cls, value: bytes, encryption_key: bytes) -> OperationState:
        if type(encryption_key) is not bytes or len(encryption_key) != 32:
            raise ValueError("State encryption requires a 32-byte key")
        header_size = len(STATE_ENVELOPE)
        if (
            type(value) is not bytes
            or not header_size + 28 <= len(value) <= STATE_MAX_BYTES + header_size + 28
            or not value.startswith(STATE_ENVELOPE)
        ):
            raise ValueError("Invalid encrypted operation state envelope")
        nonce = value[header_size : header_size + 12]
        try:
            plaintext = AESGCM(encryption_key).decrypt(
                nonce, value[header_size + 12 :], STATE_ENVELOPE
            )
            return cls.from_json(plaintext.decode())
        except (InvalidTag, UnicodeError):
            raise ValueError("Operation state authentication failed") from None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> OperationState:
        if type(value) is not dict or set(value) != {
            "version",
            "kind",
            "environment",
            "context_key",
            "reference_number",
            "payload",
        }:
            raise ValueError("Invalid operation state structure")
        return cls(**value)

    def bind(self, environment: str, context_key: str) -> None:
        if self.environment != environment or self.context_key != context_key:
            raise ValueError("Operation belongs to a different environment or context")


class KsefOperationError(KsefError):
    code = ErrorCode.WORKFLOW_ERROR

    def __init__(self, reason: str, state: OperationState, status: Any = None) -> None:
        super().__init__(f"Operation {state.kind}: {reason}")
        self.reason_code = reason
        self.state = state
        self.last_status = status
        self.status_code = getattr(getattr(status, "status", None), "code", None)


class KsefOperationTimeout(KsefOperationError, TimeoutError):
    """Local deadline, not a cancellation of the operation in KSeF."""


class InvoiceOperationError(KsefOperationError):
    code = ErrorCode.INVOICE_REJECTED


class AuthenticationOperationError(KsefOperationError):
    code = ErrorCode.AUTHENTICATION_FAILED


class SessionOperationError(KsefOperationError):
    code = ErrorCode.SESSION_ERROR


class UpoOperationError(KsefOperationError):
    code = ErrorCode.UPO_NOT_FOUND


class ExportOperationError(KsefOperationError):
    code = ErrorCode.EXPORT_ERROR


class PermissionOperationError(KsefOperationError):
    code = ErrorCode.PERMISSION_ERROR


class CertificateOperationError(KsefOperationError):
    code = ErrorCode.CERTIFICATE_ERROR


def operation_failure(reason: str, state: OperationState, status: Any) -> KsefOperationError:
    if reason == "unsupported_status":
        return KsefOperationError(reason, state, status)
    cls = {
        "invoice": InvoiceOperationError,
        "auth": AuthenticationOperationError,
        "online": SessionOperationError,
        "batch": SessionOperationError,
        "upo": UpoOperationError,
        "export": ExportOperationError,
        "permission": PermissionOperationError,
        "certificate": CertificateOperationError,
    }[state.kind]
    return cls(reason, state, status)


def outcome(kind: str, result: Any) -> str:
    code = getattr(getattr(result, "status", None), "code", None)
    if type(code) is not int:
        return "unsupported_status"
    if kind == "upo":
        if code == 200 and result.upo is not None:
            return "success"
        if code in FAILURES["online"] | FAILURES["batch"]:
            return "rejected"
    elif code == 200:
        if kind in {"online", "batch"} and (result.failed_invoice_count or 0) > 0:
            return "invoices_rejected"
        return "success"
    if code in PENDING[kind]:
        return "pending"
    return "rejected" if code in FAILURES.get(kind, set()) else "unsupported_status"


def validate_wait(timeout: float, poll_interval: float) -> None:
    if any(
        type(x) not in (float, int) or not math.isfinite(x) or x <= 0
        for x in (timeout, poll_interval)
    ):
        raise ValueError("timeout and poll_interval must be positive finite seconds")


class Operation(Generic[T]):
    def __init__(
        self,
        state: OperationState,
        fetch: Callable[[], Any],
        finish: Callable[[Any], T] | None = None,
    ) -> None:
        self._state, self._fetch, self._finish = (
            OperationState.from_dict(state.to_dict()),
            fetch,
            finish,
        )
        self._done = False
        self._result: Any = None
        self._last_status: Any = None
        self._failure: KsefOperationError | None = None

    def resume_state(self) -> OperationState:
        return OperationState.from_dict(self._state.to_dict())

    def get_status(self) -> Any:
        self._last_status = self._fetch()
        return self._last_status

    def wait(self, timeout: float = 120, poll_interval: float = 2) -> T:
        validate_wait(timeout, poll_interval)
        if self._failure is not None:
            raise self._failure
        if self._done:
            return self._result
        try:
            with request_control(timeout_seconds=timeout) as control:
                while True:
                    control.check()
                    status = self.get_status()
                    decision = outcome(self._state.kind, status)
                    if decision == "success":
                        self._result = self._finish(status) if self._finish else status
                        self._done = True
                        return self._result
                    if decision != "pending":
                        self._failure = operation_failure(decision, self.resume_state(), status)
                        raise self._failure
                    wait_seconds(min(poll_interval, control.remaining() or poll_interval))
        except KsefRateLimitWaitTimeout:
            raise KsefOperationTimeout("timeout", self.resume_state(), self._last_status) from None
        except KsefHttpError:
            if control.remaining() == 0:
                raise KsefOperationTimeout(
                    "timeout", self.resume_state(), self._last_status
                ) from None
            raise

    def __repr__(self) -> str:
        return f"{type(self).__name__}(kind={self._state.kind!r}, completed={self._done})"


class AsyncOperation(Generic[T]):
    def __init__(
        self,
        state: OperationState,
        fetch: Callable[[], Awaitable[Any]],
        finish: Callable[[Any], Awaitable[T]] | None = None,
    ) -> None:
        self._state, self._fetch, self._finish = (
            OperationState.from_dict(state.to_dict()),
            fetch,
            finish,
        )
        self._done = False
        self._result: Any = None
        self._last_status: Any = None
        self._failure: KsefOperationError | None = None

    def resume_state(self) -> OperationState:
        return OperationState.from_dict(self._state.to_dict())

    async def get_status(self) -> Any:
        self._last_status = await self._fetch()
        return self._last_status

    async def wait(self, timeout: float = 120, poll_interval: float = 2) -> T:
        validate_wait(timeout, poll_interval)
        if self._failure is not None:
            raise self._failure
        if self._done:
            return self._result
        try:
            with request_control(timeout_seconds=timeout) as control:
                while True:
                    control.check()
                    status = await self.get_status()
                    decision = outcome(self._state.kind, status)
                    if decision == "success":
                        self._result = await self._finish(status) if self._finish else status
                        self._done = True
                        return self._result
                    if decision != "pending":
                        self._failure = operation_failure(decision, self.resume_state(), status)
                        raise self._failure
                    await wait_seconds_async(
                        min(poll_interval, control.remaining() or poll_interval)
                    )
        except KsefRateLimitWaitTimeout:
            raise KsefOperationTimeout("timeout", self.resume_state(), self._last_status) from None
        except KsefHttpError:
            if control.remaining() == 0:
                raise KsefOperationTimeout(
                    "timeout", self.resume_state(), self._last_status
                ) from None
            raise

    def __repr__(self) -> str:
        return f"{type(self).__name__}(kind={self._state.kind!r}, completed={self._done})"
