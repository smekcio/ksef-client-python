from __future__ import annotations

from typing import Any

from ..models import (
    OpenBatchSessionRequest,
    OpenBatchSessionResponse,
    OpenOnlineSessionRequest,
    OpenOnlineSessionResponse,
    SendInvoiceRequest,
    SendInvoiceResponse,
    SessionInvoicesResponse,
    SessionInvoiceStatusResponse,
    SessionsQueryResponse,
    SessionStatusResponse,
)
from .base import AsyncBaseApiClient, BaseApiClient


class SessionsClient(BaseApiClient):
    def get_sessions(
        self,
        *,
        session_type: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
        reference_number: str | None = None,
        date_created_from: str | None = None,
        date_created_to: str | None = None,
        date_closed_from: str | None = None,
        date_closed_to: str | None = None,
        date_modified_from: str | None = None,
        date_modified_to: str | None = None,
        statuses: list[str] | None = None,
        access_token: str | None = None,
    ) -> SessionsQueryResponse:
        params: dict[str, Any] = {"sessionType": session_type}
        if page_size is not None:
            params["pageSize"] = page_size
        if reference_number:
            params["referenceNumber"] = reference_number
        if date_created_from:
            params["dateCreatedFrom"] = date_created_from
        if date_created_to:
            params["dateCreatedTo"] = date_created_to
        if date_closed_from:
            params["dateClosedFrom"] = date_closed_from
        if date_closed_to:
            params["dateClosedTo"] = date_closed_to
        if date_modified_from:
            params["dateModifiedFrom"] = date_modified_from
        if date_modified_to:
            params["dateModifiedTo"] = date_modified_to
        if statuses:
            params["statuses"] = statuses

        headers = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token

        return self._request_model(
            "GET",
            "/sessions",
            response_model=SessionsQueryResponse,
            params=params,
            headers=headers or None,
            access_token=access_token,
        )

    def open_online_session(
        self,
        request_payload: OpenOnlineSessionRequest,
        *,
        access_token: str,
        upo_v43: bool = False,
    ) -> OpenOnlineSessionResponse:
        headers = {}
        if upo_v43:
            headers["X-KSeF-Feature"] = "upo-v4-3"
        return self._request_model(
            "POST",
            "/sessions/online",
            response_model=OpenOnlineSessionResponse,
            json=request_payload,
            headers=headers or None,
            access_token=access_token,
            expected_status={201},
        )

    def close_online_session(self, reference_number: str, access_token: str) -> None:
        self._request_json(
            "POST",
            f"/sessions/online/{reference_number}/close",
            access_token=access_token,
            expected_status={204},
        )

    def send_online_invoice(
        self,
        reference_number: str,
        request_payload: SendInvoiceRequest,
        *,
        access_token: str,
    ) -> SendInvoiceResponse:
        return self._request_model(
            "POST",
            f"/sessions/online/{reference_number}/invoices",
            response_model=SendInvoiceResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def open_batch_session(
        self,
        request_payload: OpenBatchSessionRequest,
        *,
        access_token: str,
        upo_v43: bool = False,
    ) -> OpenBatchSessionResponse:
        headers = {}
        if upo_v43:
            headers["X-KSeF-Feature"] = "upo-v4-3"
        return self._request_model(
            "POST",
            "/sessions/batch",
            response_model=OpenBatchSessionResponse,
            json=request_payload,
            headers=headers or None,
            access_token=access_token,
            expected_status={201},
        )

    def close_batch_session(self, reference_number: str, access_token: str) -> None:
        self._request_json(
            "POST",
            f"/sessions/batch/{reference_number}/close",
            access_token=access_token,
            expected_status={204},
        )

    def get_session_status(self, reference_number: str, access_token: str) -> SessionStatusResponse:
        return self._request_model(
            "GET",
            f"/sessions/{reference_number}",
            response_model=SessionStatusResponse,
            access_token=access_token,
        )

    def get_session_invoices(
        self,
        reference_number: str,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str,
    ) -> SessionInvoicesResponse:
        headers = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token
        params = {}
        if page_size is not None:
            params["pageSize"] = page_size
        return self._request_model(
            "GET",
            f"/sessions/{reference_number}/invoices",
            response_model=SessionInvoicesResponse,
            headers=headers or None,
            params=params or None,
            access_token=access_token,
        )

    def get_session_failed_invoices(
        self,
        reference_number: str,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str,
    ) -> SessionInvoicesResponse:
        headers = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token
        params = {}
        if page_size is not None:
            params["pageSize"] = page_size
        return self._request_model(
            "GET",
            f"/sessions/{reference_number}/invoices/failed",
            response_model=SessionInvoicesResponse,
            headers=headers or None,
            params=params or None,
            access_token=access_token,
        )

    def get_session_invoice_status(
        self,
        reference_number: str,
        invoice_reference_number: str,
        *,
        access_token: str,
    ) -> SessionInvoiceStatusResponse:
        return self._request_model(
            "GET",
            f"/sessions/{reference_number}/invoices/{invoice_reference_number}",
            response_model=SessionInvoiceStatusResponse,
            access_token=access_token,
        )

    def get_session_invoice_upo_by_ref(
        self,
        reference_number: str,
        invoice_reference_number: str,
        *,
        access_token: str,
    ) -> bytes:
        return self._request_bytes(
            "GET",
            f"/sessions/{reference_number}/invoices/{invoice_reference_number}/upo",
            access_token=access_token,
        )

    def get_session_invoice_upo_by_ksef(
        self,
        reference_number: str,
        ksef_number: str,
        *,
        access_token: str,
    ) -> bytes:
        return self._request_bytes(
            "GET",
            f"/sessions/{reference_number}/invoices/ksef/{ksef_number}/upo",
            access_token=access_token,
        )

    def get_session_upo(
        self,
        reference_number: str,
        upo_reference_number: str,
        *,
        access_token: str,
    ) -> bytes:
        return self._request_bytes(
            "GET",
            f"/sessions/{reference_number}/upo/{upo_reference_number}",
            access_token=access_token,
        )


class AsyncSessionsClient(AsyncBaseApiClient):
    async def get_sessions(
        self,
        *,
        session_type: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
        reference_number: str | None = None,
        date_created_from: str | None = None,
        date_created_to: str | None = None,
        date_closed_from: str | None = None,
        date_closed_to: str | None = None,
        date_modified_from: str | None = None,
        date_modified_to: str | None = None,
        statuses: list[str] | None = None,
        access_token: str | None = None,
    ) -> SessionsQueryResponse:
        params: dict[str, Any] = {"sessionType": session_type}
        if page_size is not None:
            params["pageSize"] = page_size
        if reference_number:
            params["referenceNumber"] = reference_number
        if date_created_from:
            params["dateCreatedFrom"] = date_created_from
        if date_created_to:
            params["dateCreatedTo"] = date_created_to
        if date_closed_from:
            params["dateClosedFrom"] = date_closed_from
        if date_closed_to:
            params["dateClosedTo"] = date_closed_to
        if date_modified_from:
            params["dateModifiedFrom"] = date_modified_from
        if date_modified_to:
            params["dateModifiedTo"] = date_modified_to
        if statuses:
            params["statuses"] = statuses

        headers = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token

        return await self._request_model(
            "GET",
            "/sessions",
            response_model=SessionsQueryResponse,
            params=params,
            headers=headers or None,
            access_token=access_token,
        )

    async def open_online_session(
        self,
        request_payload: OpenOnlineSessionRequest,
        *,
        access_token: str,
        upo_v43: bool = False,
    ) -> OpenOnlineSessionResponse:
        headers = {}
        if upo_v43:
            headers["X-KSeF-Feature"] = "upo-v4-3"
        return await self._request_model(
            "POST",
            "/sessions/online",
            response_model=OpenOnlineSessionResponse,
            json=request_payload,
            headers=headers or None,
            access_token=access_token,
            expected_status={201},
        )

    async def close_online_session(self, reference_number: str, access_token: str) -> None:
        await self._request_json(
            "POST",
            f"/sessions/online/{reference_number}/close",
            access_token=access_token,
            expected_status={204},
        )

    async def send_online_invoice(
        self,
        reference_number: str,
        request_payload: SendInvoiceRequest,
        *,
        access_token: str,
    ) -> SendInvoiceResponse:
        return await self._request_model(
            "POST",
            f"/sessions/online/{reference_number}/invoices",
            response_model=SendInvoiceResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def open_batch_session(
        self,
        request_payload: OpenBatchSessionRequest,
        *,
        access_token: str,
        upo_v43: bool = False,
    ) -> OpenBatchSessionResponse:
        headers = {}
        if upo_v43:
            headers["X-KSeF-Feature"] = "upo-v4-3"
        return await self._request_model(
            "POST",
            "/sessions/batch",
            response_model=OpenBatchSessionResponse,
            json=request_payload,
            headers=headers or None,
            access_token=access_token,
            expected_status={201},
        )

    async def close_batch_session(self, reference_number: str, access_token: str) -> None:
        await self._request_json(
            "POST",
            f"/sessions/batch/{reference_number}/close",
            access_token=access_token,
            expected_status={204},
        )

    async def get_session_status(
        self, reference_number: str, access_token: str
    ) -> SessionStatusResponse:
        return await self._request_model(
            "GET",
            f"/sessions/{reference_number}",
            response_model=SessionStatusResponse,
            access_token=access_token,
        )

    async def get_session_invoices(
        self,
        reference_number: str,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str,
    ) -> SessionInvoicesResponse:
        headers = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token
        params = {}
        if page_size is not None:
            params["pageSize"] = page_size
        return await self._request_model(
            "GET",
            f"/sessions/{reference_number}/invoices",
            response_model=SessionInvoicesResponse,
            headers=headers or None,
            params=params or None,
            access_token=access_token,
        )

    async def get_session_failed_invoices(
        self,
        reference_number: str,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str,
    ) -> SessionInvoicesResponse:
        headers = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token
        params = {}
        if page_size is not None:
            params["pageSize"] = page_size
        return await self._request_model(
            "GET",
            f"/sessions/{reference_number}/invoices/failed",
            response_model=SessionInvoicesResponse,
            headers=headers or None,
            params=params or None,
            access_token=access_token,
        )

    async def get_session_invoice_status(
        self,
        reference_number: str,
        invoice_reference_number: str,
        *,
        access_token: str,
    ) -> SessionInvoiceStatusResponse:
        return await self._request_model(
            "GET",
            f"/sessions/{reference_number}/invoices/{invoice_reference_number}",
            response_model=SessionInvoiceStatusResponse,
            access_token=access_token,
        )

    async def get_session_invoice_upo_by_ref(
        self,
        reference_number: str,
        invoice_reference_number: str,
        *,
        access_token: str,
    ) -> bytes:
        return await self._request_bytes(
            "GET",
            f"/sessions/{reference_number}/invoices/{invoice_reference_number}/upo",
            access_token=access_token,
        )

    async def get_session_invoice_upo_by_ksef(
        self,
        reference_number: str,
        ksef_number: str,
        *,
        access_token: str,
    ) -> bytes:
        return await self._request_bytes(
            "GET",
            f"/sessions/{reference_number}/invoices/ksef/{ksef_number}/upo",
            access_token=access_token,
        )

    async def get_session_upo(
        self,
        reference_number: str,
        upo_reference_number: str,
        *,
        access_token: str,
    ) -> bytes:
        return await self._request_bytes(
            "GET",
            f"/sessions/{reference_number}/upo/{upo_reference_number}",
            access_token=access_token,
        )
