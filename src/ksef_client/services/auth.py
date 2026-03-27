from __future__ import annotations

import base64

from ..models import (
    AuthenticationContextIdentifier,
    AuthenticationContextIdentifierType,
    AuthorizationPolicy,
    InitTokenAuthenticationRequest,
)
from .crypto import encrypt_ksef_token_ec, encrypt_ksef_token_rsa

AUTH_NS = "http://ksef.mf.gov.pl/auth/token/2.0"


def build_auth_token_request_xml(
    *,
    challenge: str,
    context_identifier_type: str,
    context_identifier_value: str,
    subject_identifier_type: str = "certificateSubject",
    authorization_policy_xml: str | None = None,
) -> str:
    context_tag = _context_tag(context_identifier_type)
    auth_policy = f"\n  {authorization_policy_xml}" if authorization_policy_xml else ""
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<AuthTokenRequest xmlns="{AUTH_NS}">\n'
        f"  <Challenge>{challenge}</Challenge>\n"
        "  <ContextIdentifier>\n"
        f"    <{context_tag}>{context_identifier_value}</{context_tag}>\n"
        "  </ContextIdentifier>\n"
        f"  <SubjectIdentifierType>{subject_identifier_type}</SubjectIdentifierType>"
        f"{auth_policy}\n"
        "</AuthTokenRequest>"
    )
    return xml


def build_ksef_token_auth_request(
    *,
    challenge: str,
    context_identifier_type: str,
    context_identifier_value: str,
    encrypted_token_base64: str,
    authorization_policy: AuthorizationPolicy | None = None,
) -> InitTokenAuthenticationRequest:
    return InitTokenAuthenticationRequest(
        challenge=challenge,
        context_identifier=AuthenticationContextIdentifier(
            type=_normalize_context_identifier_type(context_identifier_type),
            value=context_identifier_value,
        ),
        encrypted_token=encrypted_token_base64,
        authorization_policy=authorization_policy,
    )


def encrypt_ksef_token(
    *,
    public_certificate: str,
    token: str,
    timestamp_ms: int,
    method: str = "rsa",
    ec_output_format: str = "java",
) -> str:
    token = token.strip()
    if method.lower() == "rsa":
        encrypted = encrypt_ksef_token_rsa(public_certificate, token, timestamp_ms)
    elif method.lower() in {"ec", "ecdsa"}:
        encrypted = encrypt_ksef_token_ec(
            public_certificate, token, timestamp_ms, output_format=ec_output_format
        )
    else:
        raise ValueError("Unsupported method: use 'rsa' or 'ec'")

    return base64.b64encode(encrypted).decode("ascii")


def _context_tag(context_identifier_type: str) -> str:
    return _normalize_context_identifier_type(context_identifier_type).value


def _normalize_context_identifier_type(
    context_identifier_type: str,
) -> AuthenticationContextIdentifierType:
    key = context_identifier_type.strip().lower()
    if key == "nip":
        return AuthenticationContextIdentifierType.NIP
    if key == "internalid":
        return AuthenticationContextIdentifierType.INTERNALID
    if key == "nipvatue":
        return AuthenticationContextIdentifierType.NIPVATUE
    if key == "peppolid":
        return AuthenticationContextIdentifierType.PEPPOLID
    raise ValueError("Unsupported context identifier type")
