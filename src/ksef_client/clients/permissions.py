from __future__ import annotations

from typing import Any

from ..models import (
    CheckAttachmentPermissionStatusResponse,
    EntityAuthorizationPermissionsGrantRequest,
    EntityAuthorizationPermissionsQueryRequest,
    EntityPermissionsGrantRequest,
    EntityPermissionsQueryRequest,
    EuEntityAdministrationPermissionsGrantRequest,
    EuEntityPermissionsGrantRequest,
    EuEntityPermissionsQueryRequest,
    IndirectPermissionsGrantRequest,
    PermissionsOperationResponse,
    PermissionsOperationStatusResponse,
    PersonalPermissionsQueryRequest,
    PersonPermissionsGrantRequest,
    PersonPermissionsQueryRequest,
    QueryEntityAuthorizationPermissionsResponse,
    QueryEntityPermissionsResponse,
    QueryEntityRolesResponse,
    QueryEuEntityPermissionsResponse,
    QueryPersonalPermissionsResponse,
    QueryPersonPermissionsResponse,
    QuerySubordinateEntityRolesResponse,
    QuerySubunitPermissionsResponse,
    SubordinateEntityRolesQueryRequest,
    SubunitPermissionsGrantRequest,
    SubunitPermissionsQueryRequest,
)
from .base import AsyncBaseApiClient, BaseApiClient


def _page_params(page_offset: int | None, page_size: int | None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if page_offset is not None:
        params["pageOffset"] = page_offset
    if page_size is not None:
        params["pageSize"] = page_size
    return params


class PermissionsClient(BaseApiClient):
    def check_attachment_permission_status(
        self, access_token: str
    ) -> CheckAttachmentPermissionStatusResponse:
        return self._request_model(
            "GET",
            "/permissions/attachments/status",
            response_model=CheckAttachmentPermissionStatusResponse,
            access_token=access_token,
        )

    def grant_authorization(
        self, request_payload: EntityAuthorizationPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return self._request_model(
            "POST",
            "/permissions/authorizations/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def revoke_authorization(
        self, permission_id: str, *, access_token: str
    ) -> PermissionsOperationResponse:
        return self._request_model(
            "DELETE",
            f"/permissions/authorizations/grants/{permission_id}",
            response_model=PermissionsOperationResponse,
            access_token=access_token,
            expected_status={202},
        )

    def revoke_common_permission(
        self, permission_id: str, *, access_token: str
    ) -> PermissionsOperationResponse:
        return self._request_model(
            "DELETE",
            f"/permissions/common/grants/{permission_id}",
            response_model=PermissionsOperationResponse,
            access_token=access_token,
            expected_status={202},
        )

    def grant_entity(
        self, request_payload: EntityPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return self._request_model(
            "POST",
            "/permissions/entities/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def grant_eu_entity(
        self, request_payload: EuEntityPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return self._request_model(
            "POST",
            "/permissions/eu-entities/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def grant_eu_entity_admin(
        self,
        request_payload: EuEntityAdministrationPermissionsGrantRequest,
        *,
        access_token: str,
    ) -> PermissionsOperationResponse:
        return self._request_model(
            "POST",
            "/permissions/eu-entities/administration/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def grant_indirect(
        self, request_payload: IndirectPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return self._request_model(
            "POST",
            "/permissions/indirect/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def grant_person(
        self, request_payload: PersonPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return self._request_model(
            "POST",
            "/permissions/persons/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def grant_subunit(
        self, request_payload: SubunitPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return self._request_model(
            "POST",
            "/permissions/subunits/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def get_operation_status(
        self, reference_number: str, *, access_token: str
    ) -> PermissionsOperationStatusResponse:
        return self._request_model(
            "GET",
            f"/permissions/operations/{reference_number}",
            response_model=PermissionsOperationStatusResponse,
            access_token=access_token,
        )

    def query_authorizations_grants(
        self,
        request_payload: EntityAuthorizationPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QueryEntityAuthorizationPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return self._request_model(
            "POST",
            "/permissions/query/authorizations/grants",
            response_model=QueryEntityAuthorizationPermissionsResponse,
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
    ) -> QueryEntityRolesResponse:
        params = _page_params(page_offset, page_size)
        return self._request_model(
            "GET",
            "/permissions/query/entities/roles",
            response_model=QueryEntityRolesResponse,
            params=params or None,
            access_token=access_token,
        )

    def query_entities_grants(
        self,
        request_payload: EntityPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QueryEntityPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return self._request_model(
            "POST",
            "/permissions/query/entities/grants",
            response_model=QueryEntityPermissionsResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def query_eu_entities_grants(
        self,
        request_payload: EuEntityPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QueryEuEntityPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return self._request_model(
            "POST",
            "/permissions/query/eu-entities/grants",
            response_model=QueryEuEntityPermissionsResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def query_personal_grants(
        self,
        request_payload: PersonalPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QueryPersonalPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return self._request_model(
            "POST",
            "/permissions/query/personal/grants",
            response_model=QueryPersonalPermissionsResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def query_persons_grants(
        self,
        request_payload: PersonPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QueryPersonPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return self._request_model(
            "POST",
            "/permissions/query/persons/grants",
            response_model=QueryPersonPermissionsResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def query_subordinate_entities_roles(
        self,
        request_payload: SubordinateEntityRolesQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QuerySubordinateEntityRolesResponse:
        params = _page_params(page_offset, page_size)
        return self._request_model(
            "POST",
            "/permissions/query/subordinate-entities/roles",
            response_model=QuerySubordinateEntityRolesResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def query_subunits_grants(
        self,
        request_payload: SubunitPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QuerySubunitPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return self._request_model(
            "POST",
            "/permissions/query/subunits/grants",
            response_model=QuerySubunitPermissionsResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )


class AsyncPermissionsClient(AsyncBaseApiClient):
    async def check_attachment_permission_status(
        self, access_token: str
    ) -> CheckAttachmentPermissionStatusResponse:
        return await self._request_model(
            "GET",
            "/permissions/attachments/status",
            response_model=CheckAttachmentPermissionStatusResponse,
            access_token=access_token,
        )

    async def grant_authorization(
        self, request_payload: EntityAuthorizationPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return await self._request_model(
            "POST",
            "/permissions/authorizations/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def revoke_authorization(
        self, permission_id: str, *, access_token: str
    ) -> PermissionsOperationResponse:
        return await self._request_model(
            "DELETE",
            f"/permissions/authorizations/grants/{permission_id}",
            response_model=PermissionsOperationResponse,
            access_token=access_token,
            expected_status={202},
        )

    async def revoke_common_permission(
        self, permission_id: str, *, access_token: str
    ) -> PermissionsOperationResponse:
        return await self._request_model(
            "DELETE",
            f"/permissions/common/grants/{permission_id}",
            response_model=PermissionsOperationResponse,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_entity(
        self, request_payload: EntityPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return await self._request_model(
            "POST",
            "/permissions/entities/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_eu_entity(
        self, request_payload: EuEntityPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return await self._request_model(
            "POST",
            "/permissions/eu-entities/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_eu_entity_admin(
        self,
        request_payload: EuEntityAdministrationPermissionsGrantRequest,
        *,
        access_token: str,
    ) -> PermissionsOperationResponse:
        return await self._request_model(
            "POST",
            "/permissions/eu-entities/administration/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_indirect(
        self, request_payload: IndirectPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return await self._request_model(
            "POST",
            "/permissions/indirect/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_person(
        self, request_payload: PersonPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return await self._request_model(
            "POST",
            "/permissions/persons/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_subunit(
        self, request_payload: SubunitPermissionsGrantRequest, *, access_token: str
    ) -> PermissionsOperationResponse:
        return await self._request_model(
            "POST",
            "/permissions/subunits/grants",
            response_model=PermissionsOperationResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def get_operation_status(
        self, reference_number: str, *, access_token: str
    ) -> PermissionsOperationStatusResponse:
        return await self._request_model(
            "GET",
            f"/permissions/operations/{reference_number}",
            response_model=PermissionsOperationStatusResponse,
            access_token=access_token,
        )

    async def query_authorizations_grants(
        self,
        request_payload: EntityAuthorizationPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QueryEntityAuthorizationPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return await self._request_model(
            "POST",
            "/permissions/query/authorizations/grants",
            response_model=QueryEntityAuthorizationPermissionsResponse,
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
    ) -> QueryEntityRolesResponse:
        params = _page_params(page_offset, page_size)
        return await self._request_model(
            "GET",
            "/permissions/query/entities/roles",
            response_model=QueryEntityRolesResponse,
            params=params or None,
            access_token=access_token,
        )

    async def query_entities_grants(
        self,
        request_payload: EntityPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QueryEntityPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return await self._request_model(
            "POST",
            "/permissions/query/entities/grants",
            response_model=QueryEntityPermissionsResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def query_eu_entities_grants(
        self,
        request_payload: EuEntityPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QueryEuEntityPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return await self._request_model(
            "POST",
            "/permissions/query/eu-entities/grants",
            response_model=QueryEuEntityPermissionsResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def query_personal_grants(
        self,
        request_payload: PersonalPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QueryPersonalPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return await self._request_model(
            "POST",
            "/permissions/query/personal/grants",
            response_model=QueryPersonalPermissionsResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def query_persons_grants(
        self,
        request_payload: PersonPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QueryPersonPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return await self._request_model(
            "POST",
            "/permissions/query/persons/grants",
            response_model=QueryPersonPermissionsResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def query_subordinate_entities_roles(
        self,
        request_payload: SubordinateEntityRolesQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QuerySubordinateEntityRolesResponse:
        params = _page_params(page_offset, page_size)
        return await self._request_model(
            "POST",
            "/permissions/query/subordinate-entities/roles",
            response_model=QuerySubordinateEntityRolesResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def query_subunits_grants(
        self,
        request_payload: SubunitPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str,
    ) -> QuerySubunitPermissionsResponse:
        params = _page_params(page_offset, page_size)
        return await self._request_model(
            "POST",
            "/permissions/query/subunits/grants",
            response_model=QuerySubunitPermissionsResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )
