from __future__ import annotations

from ..models import (
    AttachmentPermissionGrantRequest,
    AttachmentPermissionRevokeRequest,
    BlockContextAuthenticationRequest,
    EffectiveApiRateLimits,
    EffectiveContextLimits,
    EffectiveSubjectLimits,
    PersonCreateRequest,
    PersonRemoveRequest,
    SetRateLimitsRequest,
    SetSessionLimitsRequest,
    SetSubjectLimitsRequest,
    SubjectCreateRequest,
    SubjectRemoveRequest,
    TestDataPermissionsGrantRequest,
    TestDataPermissionsRevokeRequest,
    UnblockContextAuthenticationRequest,
)
from .base import AsyncBaseApiClient, BaseApiClient


class TestDataClient(BaseApiClient):
    __test__ = False

    def create_subject(
        self, request_payload: SubjectCreateRequest, *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/subject",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def remove_subject(
        self, request_payload: SubjectRemoveRequest, *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/subject/remove",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def create_person(
        self, request_payload: PersonCreateRequest, *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/person",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def remove_person(
        self, request_payload: PersonRemoveRequest, *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/person/remove",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def grant_permissions(
        self, request_payload: TestDataPermissionsGrantRequest, *, access_token: str | None = None
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/permissions",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def revoke_permissions(
        self,
        request_payload: TestDataPermissionsRevokeRequest,
        *,
        access_token: str | None = None,
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/permissions/revoke",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def enable_attachment(
        self,
        request_payload: AttachmentPermissionGrantRequest,
        *,
        access_token: str | None = None,
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/attachment",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def disable_attachment(
        self,
        request_payload: AttachmentPermissionRevokeRequest,
        *,
        access_token: str | None = None,
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/attachment/revoke",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    def block_context_authentication(
        self,
        request_payload: BlockContextAuthenticationRequest,
        *,
        access_token: str | None = None,
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/context/block",
            json=request_payload,
            access_token=access_token,
            expected_status={200},
        )

    def unblock_context_authentication(
        self,
        request_payload: UnblockContextAuthenticationRequest,
        *,
        access_token: str | None = None,
    ) -> None:
        self._request_json(
            "POST",
            "/testdata/context/unblock",
            json=request_payload,
            access_token=access_token,
            expected_status={200},
        )

    def change_session_limits(
        self, request_payload: SetSessionLimitsRequest, *, access_token: str
    ) -> EffectiveContextLimits:
        return self._request_model(
            "POST",
            "/testdata/limits/context/session",
            response_model=EffectiveContextLimits,
            json=request_payload,
            access_token=access_token,
        )

    def reset_session_limits(self, *, access_token: str) -> EffectiveContextLimits:
        return self._request_model(
            "DELETE",
            "/testdata/limits/context/session",
            response_model=EffectiveContextLimits,
            access_token=access_token,
        )

    def change_certificate_limits(
        self, request_payload: SetSubjectLimitsRequest, *, access_token: str
    ) -> EffectiveSubjectLimits:
        return self._request_model(
            "POST",
            "/testdata/limits/subject/certificate",
            response_model=EffectiveSubjectLimits,
            json=request_payload,
            access_token=access_token,
        )

    def reset_certificate_limits(self, *, access_token: str) -> EffectiveSubjectLimits:
        return self._request_model(
            "DELETE",
            "/testdata/limits/subject/certificate",
            response_model=EffectiveSubjectLimits,
            access_token=access_token,
        )

    def set_rate_limits(
        self, request_payload: SetRateLimitsRequest, *, access_token: str
    ) -> EffectiveApiRateLimits:
        return self._request_model(
            "POST",
            "/testdata/rate-limits",
            response_model=EffectiveApiRateLimits,
            json=request_payload,
            access_token=access_token,
        )

    def reset_rate_limits(self, *, access_token: str) -> EffectiveApiRateLimits:
        return self._request_model(
            "DELETE",
            "/testdata/rate-limits",
            response_model=EffectiveApiRateLimits,
            access_token=access_token,
        )

    def restore_production_rate_limits(self, *, access_token: str) -> EffectiveApiRateLimits:
        return self._request_model(
            "POST",
            "/testdata/rate-limits/production",
            response_model=EffectiveApiRateLimits,
            access_token=access_token,
        )


class AsyncTestDataClient(AsyncBaseApiClient):
    async def create_subject(
        self, request_payload: SubjectCreateRequest, *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/subject",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def remove_subject(
        self, request_payload: SubjectRemoveRequest, *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/subject/remove",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def create_person(
        self, request_payload: PersonCreateRequest, *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/person",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def remove_person(
        self, request_payload: PersonRemoveRequest, *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/person/remove",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def grant_permissions(
        self, request_payload: TestDataPermissionsGrantRequest, *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/permissions",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def revoke_permissions(
        self,
        request_payload: TestDataPermissionsRevokeRequest,
        *,
        access_token: str | None = None,
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/permissions/revoke",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def enable_attachment(
        self,
        request_payload: AttachmentPermissionGrantRequest,
        *,
        access_token: str | None = None,
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/attachment",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def disable_attachment(
        self,
        request_payload: AttachmentPermissionRevokeRequest,
        *,
        access_token: str | None = None,
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/attachment/revoke",
            json=request_payload,
            access_token=access_token,
            expected_status={200, 204},
        )

    async def block_context_authentication(
        self,
        request_payload: BlockContextAuthenticationRequest,
        *,
        access_token: str | None = None,
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/context/block",
            json=request_payload,
            access_token=access_token,
            expected_status={200},
        )

    async def unblock_context_authentication(
        self,
        request_payload: UnblockContextAuthenticationRequest,
        *,
        access_token: str | None = None,
    ) -> None:
        await self._request_json(
            "POST",
            "/testdata/context/unblock",
            json=request_payload,
            access_token=access_token,
            expected_status={200},
        )

    async def change_session_limits(
        self, request_payload: SetSessionLimitsRequest, *, access_token: str
    ) -> EffectiveContextLimits:
        return await self._request_model(
            "POST",
            "/testdata/limits/context/session",
            response_model=EffectiveContextLimits,
            json=request_payload,
            access_token=access_token,
        )

    async def reset_session_limits(self, *, access_token: str) -> EffectiveContextLimits:
        return await self._request_model(
            "DELETE",
            "/testdata/limits/context/session",
            response_model=EffectiveContextLimits,
            access_token=access_token,
        )

    async def change_certificate_limits(
        self, request_payload: SetSubjectLimitsRequest, *, access_token: str
    ) -> EffectiveSubjectLimits:
        return await self._request_model(
            "POST",
            "/testdata/limits/subject/certificate",
            response_model=EffectiveSubjectLimits,
            json=request_payload,
            access_token=access_token,
        )

    async def reset_certificate_limits(self, *, access_token: str) -> EffectiveSubjectLimits:
        return await self._request_model(
            "DELETE",
            "/testdata/limits/subject/certificate",
            response_model=EffectiveSubjectLimits,
            access_token=access_token,
        )

    async def set_rate_limits(
        self, request_payload: SetRateLimitsRequest, *, access_token: str
    ) -> EffectiveApiRateLimits:
        return await self._request_model(
            "POST",
            "/testdata/rate-limits",
            response_model=EffectiveApiRateLimits,
            json=request_payload,
            access_token=access_token,
        )

    async def reset_rate_limits(self, *, access_token: str) -> EffectiveApiRateLimits:
        return await self._request_model(
            "DELETE",
            "/testdata/rate-limits",
            response_model=EffectiveApiRateLimits,
            access_token=access_token,
        )

    async def restore_production_rate_limits(
        self, *, access_token: str
    ) -> EffectiveApiRateLimits:
        return await self._request_model(
            "POST",
            "/testdata/rate-limits/production",
            response_model=EffectiveApiRateLimits,
            access_token=access_token,
        )
