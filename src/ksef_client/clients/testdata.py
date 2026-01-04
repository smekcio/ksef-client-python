from __future__ import annotations

from typing import Any

from .base import AsyncBaseApiClient, BaseApiClient


class TestDataClient(BaseApiClient):
    __test__ = False

    def create_subject(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/subject",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def remove_subject(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/subject/remove",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def create_person(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/person",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def remove_person(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/person/remove",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def grant_permissions(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/permissions",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def revoke_permissions(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/permissions/revoke",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def enable_attachment(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/attachment",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def disable_attachment(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/attachment/revoke",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def change_session_limits(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/testdata/limits/context/session",
            json=request_payload,
            access_token=access_token,
        )

    def reset_session_limits(self, *, access_token: str) -> Any:
        return self._request_json(
            "DELETE",
            "/testdata/limits/context/session",
            access_token=access_token,
        )

    def change_certificate_limits(
        self, request_payload: dict[str, Any], *, access_token: str
    ) -> Any:
        return self._request_json(
            "POST",
            "/testdata/limits/subject/certificate",
            json=request_payload,
            access_token=access_token,
        )

    def reset_certificate_limits(self, *, access_token: str) -> Any:
        return self._request_json(
            "DELETE",
            "/testdata/limits/subject/certificate",
            access_token=access_token,
        )

    def set_rate_limits(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/testdata/rate-limits",
            json=request_payload,
            access_token=access_token,
        )

    def reset_rate_limits(self, *, access_token: str) -> Any:
        return self._request_json(
            "DELETE",
            "/testdata/rate-limits",
            access_token=access_token,
        )

    def restore_production_rate_limits(self, *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/testdata/rate-limits/production",
            access_token=access_token,
        )


class AsyncTestDataClient(AsyncBaseApiClient):
    async def create_subject(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/subject",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def remove_subject(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/subject/remove",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def create_person(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/person",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def remove_person(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/person/remove",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def grant_permissions(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/permissions",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def revoke_permissions(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/permissions/revoke",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def enable_attachment(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/attachment",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def disable_attachment(
        self, request_payload: dict[str, Any], *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/attachment/revoke",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def change_session_limits(
        self, request_payload: dict[str, Any], *, access_token: str
    ) -> Any:
        return await self._request_json(
            "POST",
            "/testdata/limits/context/session",
            json=request_payload,
            access_token=access_token,
        )

    async def reset_session_limits(self, *, access_token: str) -> Any:
        return await self._request_json(
            "DELETE",
            "/testdata/limits/context/session",
            access_token=access_token,
        )

    async def change_certificate_limits(
        self, request_payload: dict[str, Any], *, access_token: str
    ) -> Any:
        return await self._request_json(
            "POST",
            "/testdata/limits/subject/certificate",
            json=request_payload,
            access_token=access_token,
        )

    async def reset_certificate_limits(self, *, access_token: str) -> Any:
        return await self._request_json(
            "DELETE",
            "/testdata/limits/subject/certificate",
            access_token=access_token,
        )

    async def set_rate_limits(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            "/testdata/rate-limits",
            json=request_payload,
            access_token=access_token,
        )

    async def reset_rate_limits(self, *, access_token: str) -> Any:
        return await self._request_json(
            "DELETE",
            "/testdata/rate-limits",
            access_token=access_token,
        )

    async def restore_production_rate_limits(self, *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            "/testdata/rate-limits/production",
            access_token=access_token,
        )
