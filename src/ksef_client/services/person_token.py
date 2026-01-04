from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..utils.base64url import b64url_decode


@dataclass(frozen=True)
class PersonToken:
    issuer: Optional[str]
    audiences: List[str]
    issued_at: Optional[datetime]
    expires_at: Optional[datetime]
    roles: List[str]
    token_type: Optional[str]
    context_id_type: Optional[str]
    context_id_value: Optional[str]
    auth_method: Optional[str]
    auth_request_number: Optional[str]
    subject_details: Optional[dict[str, Any]]
    permissions: List[str]
    permissions_excluded: List[str]
    roles_raw: List[str]
    permissions_effective: List[str]
    ip_policy: Optional[dict[str, Any]]


class PersonTokenService:
    """
    Lightweight JWT claims parser for KSeF person tokens.

    Security note: this service does NOT verify the JWT signature and MUST NOT be used
    for security decisions (authentication/authorization). Use it only for inspecting
    already-trusted tokens (e.g. debugging, displaying metadata).
    """

    def parse(self, jwt_token: str) -> PersonToken:
        """Parse JWT claims without verifying the signature."""
        header, payload, _sig = _split_jwt(jwt_token)
        claims = json.loads(payload)

        def get(name: str) -> Optional[str]:
            for k, v in claims.items():
                if k.lower() == name.lower():
                    return v
            return None

        def get_many(*names: str) -> List[str]:
            values: List[str] = []
            for k, v in claims.items():
                if any(k.lower() == n.lower() for n in names):
                    if isinstance(v, list):
                        values.extend(v)
                    else:
                        values.append(str(v))
            return _distinct(values)

        exp = _unix_to_datetime(claims.get("exp"))
        iat = _unix_to_datetime(claims.get("iat"))

        subject_details = _try_parse_json(get("sud"))
        ip_policy = _try_parse_json(get("ipp"))

        per = _parse_json_string_array(get("per"))
        pec = _parse_json_string_array(get("pec"))
        rol = _parse_json_string_array(get("rol"))
        pep = _parse_json_string_array(get("pep"))

        classic_roles = get_many(
            "role",
            "roles",
            "permissions",
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
        )
        unified_roles = _distinct(classic_roles + per + rol)

        return PersonToken(
            issuer=claims.get("iss"),
            audiences=_ensure_list(claims.get("aud")),
            issued_at=iat,
            expires_at=exp,
            roles=unified_roles,
            token_type=get("typ"),
            context_id_type=get("cit"),
            context_id_value=get("civ"),
            auth_method=get("aum"),
            auth_request_number=get("arn"),
            subject_details=subject_details,
            permissions=per,
            permissions_excluded=pec,
            roles_raw=rol,
            permissions_effective=pep,
            ip_policy=ip_policy,
        )


def _split_jwt(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid JWT format")
    header_json = b64url_decode(parts[0]).decode("utf-8")
    payload_json = b64url_decode(parts[1]).decode("utf-8")
    return header_json, payload_json, parts[2]


def _unix_to_datetime(value: Any) -> Optional[datetime]:
    try:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        if isinstance(value, str) and value.isdigit():
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except Exception:
        return None
    return None


def _try_parse_json(value: Optional[str]) -> Optional[dict[str, Any]]:
    if not value:
        return None
    try:
        value = _unwrap_if_quoted_json(value)
        return json.loads(value)
    except Exception:
        return None


def _parse_json_string_array(value: Optional[str]) -> List[str]:
    if not value:
        return []
    try:
        value = _unwrap_if_quoted_json(value)
        data = json.loads(value)
        if isinstance(data, list):
            return _distinct([str(x) for x in data if str(x).strip()])
    except Exception:
        pass
    if "," in value:
        return _distinct([x.strip().strip('"') for x in value.split(",") if x.strip()])
    return [value.strip().strip('"')]


def _unwrap_if_quoted_json(value: str) -> str:
    if len(value) > 1 and value[0] == '"' and value[-1] == '"':
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def _distinct(values: List[str]) -> List[str]:
    seen = set()
    result = []
    for v in values:
        key = v.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(v)
    return result


def _ensure_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value]
    return [str(value)]
