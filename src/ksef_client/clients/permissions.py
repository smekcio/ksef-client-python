from __future__ import annotations

from typing import Any

from .base import AsyncBaseApiClient, BaseApiClient


def _page_params(page_offset: int | None, page_size: int | None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if page_offset is not None:
        params["pageOffset"] = page_offset
    if page_size is not None:
        params["pageSize"] = page_size
    return params


class PermissionsClient(BaseApiClient):
    def check_attachment_permission_status(self, access_token: str) -> Any:
        return self._request_json(
            "GET",
            "/permissions/attachments/status",
            access_token=access_token,
        )

    def grant_authorization(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/permissions/authorizations/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def revoke_authorization(self, permission_id: str, *, access_token: str) -> Any:
        return self._request_json(
            "DELETE",
            f"/permissions/authorizations/grants/{permission_id}",
            access_token=access_token,
            expected_status={202},
        )

    def revoke_common_permission(self, permission_id: str, *, access_token: str) -> Any:
        return self._request_json(
            "DELETE",
            f"/permissions/common/grants/{permission_id}",
            access_token=access_token,
            expected_status={202},
        )

    def grant_entity(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/permissions/entities/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def grant_eu_entity(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/permissions/eu-entities/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def grant_eu_entity_admin(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/permissions/eu-entities/administration/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def grant_indirect(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/permissions/indirect/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def grant_person(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/permissions/persons/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def grant_subunit(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/permissions/subunits/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def get_operation_status(self, reference_number: str, *, access_token: str) -> Any:
        return self._request_json(
            "GET",
            f"/permissions/operations/{reference_number}",
            access_token=access_token,
        )

    def query_authorizations_grants(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return self._request_json(
            "POST",
            "/permissions/query/authorizations/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def query_entities_roles(
        self,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return self._request_json(
            "GET",
            "/permissions/query/entities/roles",
            params=params or None,
            access_token=access_token,
        )

    def query_eu_entities_grants(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return self._request_json(
            "POST",
            "/permissions/query/eu-entities/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def query_personal_grants(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return self._request_json(
            "POST",
            "/permissions/query/personal/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def query_persons_grants(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return self._request_json(
            "POST",
            "/permissions/query/persons/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def query_subordinate_entities_roles(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return self._request_json(
            "POST",
            "/permissions/query/subordinate-entities/roles",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def query_subunits_grants(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return self._request_json(
            "POST",
            "/permissions/query/subunits/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )


class AsyncPermissionsClient(AsyncBaseApiClient):
    async def check_attachment_permission_status(self, access_token: str) -> Any:
        return await self._request_json(
            "GET",
            "/permissions/attachments/status",
            access_token=access_token,
        )

    async def grant_authorization(
        self, request_payload: dict[str, Any], *, access_token: str
    ) -> Any:
        return await self._request_json(
            "POST",
            "/permissions/authorizations/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def revoke_authorization(self, permission_id: str, *, access_token: str) -> Any:
        return await self._request_json(
            "DELETE",
            f"/permissions/authorizations/grants/{permission_id}",
            access_token=access_token,
            expected_status={202},
        )

    async def revoke_common_permission(self, permission_id: str, *, access_token: str) -> Any:
        return await self._request_json(
            "DELETE",
            f"/permissions/common/grants/{permission_id}",
            access_token=access_token,
            expected_status={202},
        )

    async def grant_entity(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            "/permissions/entities/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_eu_entity(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            "/permissions/eu-entities/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_eu_entity_admin(
        self, request_payload: dict[str, Any], *, access_token: str
    ) -> Any:
        return await self._request_json(
            "POST",
            "/permissions/eu-entities/administration/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_indirect(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            "/permissions/indirect/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_person(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            "/permissions/persons/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_subunit(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            "/permissions/subunits/grants",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def get_operation_status(self, reference_number: str, *, access_token: str) -> Any:
        return await self._request_json(
            "GET",
            f"/permissions/operations/{reference_number}",
            access_token=access_token,
        )

    async def query_authorizations_grants(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return await self._request_json(
            "POST",
            "/permissions/query/authorizations/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def query_entities_roles(
        self,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return await self._request_json(
            "GET",
            "/permissions/query/entities/roles",
            params=params or None,
            access_token=access_token,
        )

    async def query_eu_entities_grants(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return await self._request_json(
            "POST",
            "/permissions/query/eu-entities/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def query_personal_grants(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return await self._request_json(
            "POST",
            "/permissions/query/personal/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def query_persons_grants(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return await self._request_json(
            "POST",
            "/permissions/query/persons/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def query_subordinate_entities_roles(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return await self._request_json(
            "POST",
            "/permissions/query/subordinate-entities/roles",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def query_subunits_grants(
        self,
        request_payload: dict[str, Any],
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> Any:
        params = _page_params(page_offset, page_size)
        return await self._request_json(
            "POST",
            "/permissions/query/subunits/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )
