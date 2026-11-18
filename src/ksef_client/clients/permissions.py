from __future__ import annotations

import re
from typing import Any, TypeGuard

from .._json_bounds import check_json_structure
from ..exceptions import KsefPaginationError
from ..invoice_sync_state import _loads
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
from ..pagination import validate_page_size
from .base import AsyncBaseApiClient, BaseApiClient

_PERSONAL_PAGE_BYTES = 4 * 1024 * 1024
_IDENTIFIER_FORMATS = {
    "Nip": re.compile(r"[0-9]{10}"),
    "Pesel": re.compile(r"[0-9]{11}"),
    "InternalId": re.compile(r"[0-9]{10}-[0-9]{5}"),
}


def _page_params(page_offset: int | None, page_size: int | None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if page_offset is not None:
        params["pageOffset"] = page_offset
    if page_size is not None:
        params["pageSize"] = page_size
    return params


def _personal_page_params(page_offset: int | None, page_size: int | None) -> dict[str, Any]:
    if page_size is not None:
        validate_page_size(page_size, maximum=100)
    return _page_params(page_offset, page_size)


def _parse_personal_grants(body: bytes, page_size: int | None) -> QueryPersonalPermissionsResponse:
    try:
        check_json_structure(body, max_nodes=100_000, max_depth=32)
        data = _loads(body)
        if not isinstance(data, dict) or not isinstance(data.get("hasMore"), bool):
            raise ValueError
        grants = data.get("permissions")
        if (
            not isinstance(grants, list)
            or len(grants) > (10 if page_size is None else page_size)
            or not all(_valid_personal_grant(grant) for grant in grants)
        ):
            raise ValueError
        owners = data.get("ownerPermissions")
        if owners is not None and not (
            isinstance(owners, list) and all(_nonempty_string(scope) for scope in owners)
        ):
            raise ValueError
        return QueryPersonalPermissionsResponse.from_dict(data)
    except (TypeError, ValueError):
        raise KsefPaginationError("KSeF returned an invalid personal permissions page.") from None


def _nonempty_string(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and bool(value.strip())


def _string_fields(value: Any, *required: str) -> bool:
    return isinstance(value, dict) and all(isinstance(value.get(key), str) for key in required)


def _valid_subject_details(grant: dict[str, Any]) -> bool:
    person = grant.get("subjectPersonDetails")
    if person is not None:
        if not _string_fields(person, "subjectDetailsType", "firstName", "lastName"):
            return False
        if person.get("birthDate") is not None and not isinstance(person["birthDate"], str):
            return False
        for key, fields in (
            ("personIdentifier", ("type", "value")),
            ("idDocument", ("type", "number", "country")),
        ):
            if person.get(key) is not None and not _string_fields(person[key], *fields):
                return False
    entity = grant.get("subjectEntityDetails")
    return entity is None or (
        _string_fields(entity, "subjectDetailsType", "fullName")
        and (entity.get("address") is None or isinstance(entity["address"], str))
    )


def _valid_grant_identifier(key: str, identifier: Any) -> bool:
    if identifier is None:
        return True
    if not isinstance(identifier, dict) or not _nonempty_string(identifier.get("type")):
        return False
    kind, value = identifier["type"], identifier.get("value")
    if kind == "AllPartners":
        return key == "targetIdentifier" and value is None
    max_length = 64 if key == "authorizedIdentifier" else 16
    if not _nonempty_string(value) or not 10 <= len(value) <= max_length:
        return False
    pattern = _IDENTIFIER_FORMATS.get(kind)
    return pattern is None or pattern.fullmatch(value) is not None


def _valid_personal_grant(grant: Any) -> bool:
    return (
        _string_fields(grant, "id", "description", "startDate")
        and len(grant["id"]) == 36
        and all(_nonempty_string(grant.get(key)) for key in ("permissionScope", "permissionState"))
        and isinstance(grant.get("canDelegate"), bool)
        and all(
            _valid_grant_identifier(key, grant.get(key))
            for key in ("contextIdentifier", "authorizedIdentifier", "targetIdentifier")
        )
        and _valid_subject_details(grant)
    )


class PermissionsClient(BaseApiClient):
    def check_attachment_permission_status(
        self, access_token: str | None = None
    ) -> CheckAttachmentPermissionStatusResponse:
        return self._request_model(
            "GET",
            "/permissions/attachments/status",
            response_model=CheckAttachmentPermissionStatusResponse,
            access_token=access_token,
        )

    def grant_authorization(
        self,
        request_payload: EntityAuthorizationPermissionsGrantRequest,
        *,
        access_token: str | None = None,
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
        self, permission_id: str, *, access_token: str | None = None
    ) -> PermissionsOperationResponse:
        return self._request_model(
            "DELETE",
            f"/permissions/authorizations/grants/{permission_id}",
            response_model=PermissionsOperationResponse,
            access_token=access_token,
            expected_status={202},
        )

    def revoke_common_permission(
        self, permission_id: str, *, access_token: str | None = None
    ) -> PermissionsOperationResponse:
        return self._request_model(
            "DELETE",
            f"/permissions/common/grants/{permission_id}",
            response_model=PermissionsOperationResponse,
            access_token=access_token,
            expected_status={202},
        )

    def grant_entity(
        self, request_payload: EntityPermissionsGrantRequest, *, access_token: str | None = None
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
        self, request_payload: EuEntityPermissionsGrantRequest, *, access_token: str | None = None
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
        access_token: str | None = None,
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
        self, request_payload: IndirectPermissionsGrantRequest, *, access_token: str | None = None
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
        self, request_payload: PersonPermissionsGrantRequest, *, access_token: str | None = None
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
        self, request_payload: SubunitPermissionsGrantRequest, *, access_token: str | None = None
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
        self, reference_number: str, *, access_token: str | None = None
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
        access_token: str | None = None,
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
        access_token: str | None = None,
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
        access_token: str | None = None,
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
        access_token: str | None = None,
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
        access_token: str | None = None,
    ) -> QueryPersonalPermissionsResponse:
        params = _personal_page_params(page_offset, page_size)
        payload = self._request_bytes(
            "POST",
            "/permissions/query/personal/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
            expected_status={200},
            max_bytes=_PERSONAL_PAGE_BYTES,
        )
        return _parse_personal_grants(payload, page_size)

    def query_persons_grants(
        self,
        request_payload: PersonPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str | None = None,
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
        access_token: str | None = None,
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
        access_token: str | None = None,
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
        self, access_token: str | None = None
    ) -> CheckAttachmentPermissionStatusResponse:
        return await self._request_model(
            "GET",
            "/permissions/attachments/status",
            response_model=CheckAttachmentPermissionStatusResponse,
            access_token=access_token,
        )

    async def grant_authorization(
        self,
        request_payload: EntityAuthorizationPermissionsGrantRequest,
        *,
        access_token: str | None = None,
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
        self, permission_id: str, *, access_token: str | None = None
    ) -> PermissionsOperationResponse:
        return await self._request_model(
            "DELETE",
            f"/permissions/authorizations/grants/{permission_id}",
            response_model=PermissionsOperationResponse,
            access_token=access_token,
            expected_status={202},
        )

    async def revoke_common_permission(
        self, permission_id: str, *, access_token: str | None = None
    ) -> PermissionsOperationResponse:
        return await self._request_model(
            "DELETE",
            f"/permissions/common/grants/{permission_id}",
            response_model=PermissionsOperationResponse,
            access_token=access_token,
            expected_status={202},
        )

    async def grant_entity(
        self, request_payload: EntityPermissionsGrantRequest, *, access_token: str | None = None
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
        self, request_payload: EuEntityPermissionsGrantRequest, *, access_token: str | None = None
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
        access_token: str | None = None,
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
        self, request_payload: IndirectPermissionsGrantRequest, *, access_token: str | None = None
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
        self, request_payload: PersonPermissionsGrantRequest, *, access_token: str | None = None
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
        self, request_payload: SubunitPermissionsGrantRequest, *, access_token: str | None = None
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
        self, reference_number: str, *, access_token: str | None = None
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
        access_token: str | None = None,
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
        access_token: str | None = None,
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
        access_token: str | None = None,
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
        access_token: str | None = None,
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
        access_token: str | None = None,
    ) -> QueryPersonalPermissionsResponse:
        params = _personal_page_params(page_offset, page_size)
        payload = await self._request_bytes(
            "POST",
            "/permissions/query/personal/grants",
            params=params or None,
            json=request_payload,
            access_token=access_token,
            expected_status={200},
            max_bytes=_PERSONAL_PAGE_BYTES,
        )
        return _parse_personal_grants(payload, page_size)

    async def query_persons_grants(
        self,
        request_payload: PersonPermissionsQueryRequest,
        *,
        page_offset: int | None = None,
        page_size: int | None = None,
        access_token: str | None = None,
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
        access_token: str | None = None,
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
        access_token: str | None = None,
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
