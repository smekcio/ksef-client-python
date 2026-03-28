from __future__ import annotations

from typing import Any, Protocol, TypeVar

from ..http import HttpResponse


class _RequestClient(Protocol):
    def request(self, *args: Any, **kwargs: Any) -> HttpResponse: ...


class _AsyncRequestClient(Protocol):
    async def request(self, *args: Any, **kwargs: Any) -> HttpResponse: ...


class _SerializableModel(Protocol):
    def to_dict(self, omit_none: bool = True) -> dict[str, Any]: ...


ModelT = TypeVar("ModelT")
ModelT_co = TypeVar("ModelT_co", covariant=True)


class _ModelType(Protocol[ModelT_co]):
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ModelT_co: ...


def _serialize_json_payload(payload: _SerializableModel | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    if isinstance(payload, dict):
        raise TypeError(
            "Expected typed model payload with to_dict(), got dict. Construct the appropriate "
            "ksef_client.models.* request model before calling the client."
        )
    return payload.to_dict()


def _validate_model_payload(payload: Any, *, path: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise TypeError(f"Expected JSON object response for {path}, got {type(payload).__name__}")
    return payload


def _validate_model_list_payload(payload: Any, *, path: str) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        raise TypeError(f"Expected JSON array response for {path}, got {type(payload).__name__}")
    items: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            raise TypeError(
                f"Expected array of JSON objects for {path}, got item {type(item).__name__}"
            )
        items.append(item)
    return items


class BaseApiClient:
    def __init__(self, http_client: _RequestClient) -> None:
        self._http = http_client

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: _SerializableModel | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> Any:
        response = self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=_serialize_json_payload(json),
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        if response.content:
            return response.json()
        return None

    def _request_model(
        self,
        method: str,
        path: str,
        *,
        response_model: _ModelType[ModelT],
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: _SerializableModel | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> ModelT:
        payload = self._request_json(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        return response_model.from_dict(_validate_model_payload(payload, path=path))

    def _request_optional_model(
        self,
        method: str,
        path: str,
        *,
        response_model: _ModelType[ModelT],
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: _SerializableModel | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> ModelT | None:
        payload = self._request_json(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        if payload is None:
            return None
        return response_model.from_dict(_validate_model_payload(payload, path=path))

    def _request_model_list(
        self,
        method: str,
        path: str,
        *,
        response_model: _ModelType[ModelT],
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: _SerializableModel | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> list[ModelT]:
        payload = self._request_json(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        return [
            response_model.from_dict(item)
            for item in _validate_model_list_payload(payload, path=path)
        ]

    def _request_bytes(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: _SerializableModel | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> bytes:
        response = self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=_serialize_json_payload(json),
            data=data,
            access_token=access_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        return response.content

    def _request_raw(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: _SerializableModel | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> HttpResponse:
        return self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=_serialize_json_payload(json),
            data=data,
            access_token=access_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )


class AsyncBaseApiClient:
    def __init__(self, http_client: _AsyncRequestClient) -> None:
        self._http = http_client

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: _SerializableModel | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> Any:
        response = await self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=_serialize_json_payload(json),
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        if response.content:
            return response.json()
        return None

    async def _request_model(
        self,
        method: str,
        path: str,
        *,
        response_model: _ModelType[ModelT],
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: _SerializableModel | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> ModelT:
        payload = await self._request_json(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        return response_model.from_dict(_validate_model_payload(payload, path=path))

    async def _request_optional_model(
        self,
        method: str,
        path: str,
        *,
        response_model: _ModelType[ModelT],
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: _SerializableModel | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> ModelT | None:
        payload = await self._request_json(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        if payload is None:
            return None
        return response_model.from_dict(_validate_model_payload(payload, path=path))

    async def _request_model_list(
        self,
        method: str,
        path: str,
        *,
        response_model: _ModelType[ModelT],
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: _SerializableModel | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> list[ModelT]:
        payload = await self._request_json(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        return [
            response_model.from_dict(item)
            for item in _validate_model_list_payload(payload, path=path)
        ]

    async def _request_bytes(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | _SerializableModel | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> bytes:
        response = await self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=_serialize_json_payload(json),
            data=data,
            access_token=access_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        return response.content

    async def _request_raw(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | _SerializableModel | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> HttpResponse:
        return await self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=_serialize_json_payload(json),
            data=data,
            access_token=access_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
