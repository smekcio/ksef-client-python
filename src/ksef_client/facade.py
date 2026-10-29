"""Additive application-facing API. Low-level clients remain available as ``api``."""

from __future__ import annotations

import base64
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization

from . import models as m
from .certificates import CertificateStore, FileCertificateStore
from .client import AuthenticatedClient, KsefClient
from .config import KsefClientOptions
from .operations import (
    KsefOperationError,
    Operation,
    OperationState,
    environment_key,
    validate_wait,
)
from .profiles import Profile, ProfileStore
from .request_control import request_control
from .services.auth import (
    DEFAULT_AUTH_TOKEN_REQUEST_SCHEMA_VERSION,
    build_auth_token_request_xml,
    build_ksef_token_auth_request,
    encrypt_ksef_token,
)
from .services.crypto import build_encryption_data
from .services.sessions import BatchSessionState, OnlineSessionState
from .services.workflows import AuthResult, BatchSessionWorkflow, OnlineSessionWorkflow
from .services.xades import XadesKeyPair, sign_xades_enveloped
from .token_manager import DEFAULT_REFRESH_MARGIN_SECONDS

FA3 = m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")

if TYPE_CHECKING:
    from .invoice_sync import InvoiceSync
    from .invoice_xml_sync import InvoiceDocumentSync, InvoiceXmlSync
    from .streaming_export import ExportOperation


@dataclass(frozen=True)
class TokenCredentials:
    token: str = field(repr=False)
    public_key_id: str | None = None
    public_certificate: str | None = field(default=None, repr=False)
    method: str = "rsa"
    ec_output_format: str = "java"
    authorization_policy: m.AuthorizationPolicy | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.token) is not str or not self.token:
            raise ValueError("A KSeF token is required")
        if self.method not in {"rsa", "ec", "ecdsa"}:
            raise ValueError("Unsupported token encryption method: use rsa or ec")


@dataclass(frozen=True)
class XadesCredentials:
    key_pair: XadesKeyPair = field(repr=False)
    subject_identifier_type: str = "certificateSubject"
    verify_certificate_chain: bool | None = None
    enforce_xades_compliance: bool = False
    authorization_policy_xml: str | None = field(default=None, repr=False)
    auth_request_schema_version: str = DEFAULT_AUTH_TOKEN_REQUEST_SCHEMA_VERSION

    @classmethod
    def from_store(
        cls,
        name: str,
        *,
        store: CertificateStore | None = None,
        password: str | bytes | None = None,
        **kwargs: Any,
    ) -> XadesCredentials:
        certificate = (store or FileCertificateStore.default()).load(name, password=password)
        key = certificate.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        return cls(XadesKeyPair(certificate.certificate_pem.decode(), key), **kwargs)


Credentials = TokenCredentials | XadesCredentials


def safe_options(options: KsefClientOptions) -> KsefClientOptions:
    """Preserve idempotent PUT uploads, never replay non-idempotent API mutations."""
    if options.retry is None:
        return options
    retry = replace(
        options.retry,
        retryable_methods=options.retry.retryable_methods
        & frozenset({"GET", "HEAD", "OPTIONS", "PUT"}),
        retryable_post_paths=options.retry.retryable_post_paths
        & frozenset({"/invoices/query/metadata"}),
    )
    return replace(options, retry=retry)


def connection_options(
    *,
    profile: str | Profile | None = None,
    options: KsefClientOptions | None = None,
    context_type: str | None = None,
    context_value: str | None = None,
    profile_store: ProfileStore | None = None,
) -> tuple[KsefClientOptions, str, str]:
    if profile is not None:
        if options is not None or context_type is not None or context_value is not None:
            raise ValueError("Choose a profile or explicit options and context")
        current = (
            (profile_store or ProfileStore.default()).get(profile)
            if isinstance(profile, str)
            else profile
        )
        options, context_type, context_value = (
            current.to_options(),
            current.context_type,
            current.context_value,
        )
    if options is None or not context_type or not context_value:
        raise ValueError("Options and authentication context are required")
    from .services.auth import _normalize_context_identifier_type

    context_type = _normalize_context_identifier_type(context_type).value
    return safe_options(options), context_type, context_value


def auth_payload(
    challenge: m.AuthenticationChallengeResponse,
    credentials: Credentials,
    context_type: str,
    context_value: str,
    certificate: str | None = None,
) -> Any:
    if isinstance(credentials, TokenCredentials):
        assert certificate is not None
        return build_ksef_token_auth_request(
            challenge=challenge.challenge,
            context_identifier_type=context_type,
            context_identifier_value=context_value,
            encrypted_token_base64=encrypt_ksef_token(
                public_certificate=certificate,
                token=credentials.token,
                timestamp_ms=challenge.timestamp_ms,
                method=credentials.method,
                ec_output_format=credentials.ec_output_format,
            ),
            public_key_id=credentials.public_key_id,
            authorization_policy=credentials.authorization_policy,
        )
    if not isinstance(credentials, XadesCredentials):
        raise TypeError("Use TokenCredentials or XadesCredentials")
    xml = build_auth_token_request_xml(
        challenge=challenge.challenge,
        context_identifier_type=context_type,
        context_identifier_value=context_value,
        subject_identifier_type=credentials.subject_identifier_type,
        authorization_policy_xml=credentials.authorization_policy_xml,
        schema_version=credentials.auth_request_schema_version,
    )
    return sign_xades_enveloped(
        xml, credentials.key_pair.certificate_pem, credentials.key_pair.private_key_pem
    )


def validate_auth_state(state: OperationState) -> None:
    token = state.payload.get("authentication_token")
    if (
        state.kind != "auth"
        or type(token) is not str
        or not 1 <= len(token) <= 16384
        or type(state.payload.get("redeem_started", False)) is not bool
    ):
        raise ValueError("Invalid authentication operation state")


class AuthenticationOperation(Operation[AuthResult]):
    def __init__(self, api: KsefClient, state: OperationState, options: KsefClientOptions) -> None:
        validate_auth_state(state)
        self.api, self.options = api, options
        token = state.payload["authentication_token"]
        super().__init__(
            state, lambda: api.auth.get_auth_status(state.reference_number, token), self._redeem
        )

    def _redeem(self, status: Any) -> AuthResult:
        if self._state.payload.get("redeem_started"):
            raise KsefOperationError("redeem_outcome_unknown", self.resume_state(), status)
        self._state.payload["redeem_started"] = True
        tokens = self.api.auth.redeem_token(self._state.payload["authentication_token"])
        return AuthResult(
            self._state.reference_number, self._state.payload["authentication_token"], tokens
        )

    def close(self) -> None:
        self.api.close()

    def __enter__(self) -> AuthenticationOperation:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class Session(Operation[m.SessionStatusResponse]):
    """Session context; exiting closes without polling. Batch errors preserve upload state."""

    def __init__(
        self,
        owner: Ksef,
        handle: Any,
        *,
        batch: bool = False,
        completed_parts: list[int] | None = None,
        closed: bool = False,
    ) -> None:
        self.owner, self.handle, self.batch = owner, handle, batch
        if completed_parts is not None and (
            type(completed_parts) is not list
            or any(type(p) is not int or p <= 0 for p in completed_parts)
            or len(set(completed_parts)) != len(completed_parts)
        ):
            raise ValueError("Invalid completed upload parts")
        if type(closed) is not bool:
            raise ValueError("Invalid session close state")
        self.completed_parts = set(completed_parts or [])
        if self.completed_parts and (
            not batch
            or not self.completed_parts <= {p.ordinal_number for p in handle.part_upload_requests}
        ):
            raise ValueError("Unknown completed upload part")
        self.closed = closed
        self._close_started = closed
        super().__init__(
            owner._state("batch" if batch else "online", handle.reference_number), handle.get_status
        )

    def resume_state(self) -> OperationState:
        return self.owner._state(
            self._state.kind,
            self.handle.reference_number,
            session=self.handle.get_state().to_dict(),
            completed_parts=sorted(self.completed_parts),
            closed=self.closed,
            close_started=self._close_started,
        )

    def send_invoice(
        self,
        invoice_xml: bytes,
        *,
        offline_mode: bool | None = None,
        hash_of_corrected_invoice: str | None = None,
    ) -> Operation[m.SessionInvoiceStatusResponse]:
        if self.batch or self._close_started:
            raise ValueError("Sending requires an open online session")
        response = self.handle.send_invoice(
            invoice_xml,
            offline_mode=offline_mode,
            hash_of_corrected_invoice=hash_of_corrected_invoice,
        )
        state = self.owner._state(
            "invoice", response.reference_number, session_reference=self.handle.reference_number
        )
        return self.owner.resume_operation(state)

    def upload_parts(
        self, *, parallelism: int = 1, progress_callback: Callable[[int], None] | None = None
    ) -> None:
        if not self.batch or self._close_started:
            raise ValueError("Uploading requires an open batch session")
        if self.completed_parts == {p.ordinal_number for p in self.handle.part_upload_requests}:
            return

        def confirmed(ordinal: int) -> None:
            self.completed_parts.add(ordinal)
            if progress_callback is not None:
                progress_callback(ordinal)

        self.handle.upload_parts(
            parallelism=parallelism, skip_ordinals=self.completed_parts, progress_callback=confirmed
        )

    def close(self) -> None:
        if self.closed:
            return
        if self._close_started:
            raise KsefOperationError("close_outcome_unknown", self.resume_state())
        if self.batch and self.completed_parts != {
            p.ordinal_number for p in self.handle.part_upload_requests
        }:
            raise KsefOperationError("incomplete_upload", self.resume_state())
        self._close_started = True
        self.handle.close()
        self.closed = True

    def upo(self) -> Operation[m.UpoResponse]:
        state = self.owner._state("upo", self.handle.reference_number)
        return Operation(state, self.handle.get_status, lambda status: status.upo)

    def __enter__(self) -> Session:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc is None:
            self.close()
        elif not self.batch:
            with suppress(Exception):
                self.close()


class Invoices:
    def __init__(self, owner: Ksef) -> None:
        self.owner = owner

    def sync(
        self,
        *,
        namespace: str,
        sync_key: str,
        since: str | None = None,
        subject_types: Sequence[m.InvoiceQuerySubjectType | str] | None = None,
        queries: Sequence[m.InvoiceQueryFilters] | None = None,
        page_size: int = 100,
        window_days: int = 100,
    ) -> InvoiceSync:
        return self.owner.api.invoices.sync(
            namespace=namespace,
            sync_key=sync_key,
            context_key=self.owner.context_key,
            since=since,
            subject_types=subject_types,
            queries=queries,
            page_size=page_size,
            window_days=window_days,
        )

    def sync_documents(
        self,
        *,
        namespace: str,
        sync_key: str,
        since: str | None = None,
        subject_types: Sequence[m.InvoiceQuerySubjectType | str] | None = None,
        queries: Sequence[m.InvoiceQueryFilters] | None = None,
        page_size: int = 100,
        window_days: int = 100,
        xml_options: dict[str, Any] | None = None,
    ) -> InvoiceDocumentSync:
        return self.owner.api.invoices.sync_documents(
            namespace=namespace,
            sync_key=sync_key,
            context_key=self.owner.context_key,
            since=since,
            subject_types=subject_types,
            queries=queries,
            page_size=page_size,
            window_days=window_days,
            xml_options=xml_options,
        )

    def xml_sync(self, metadata_sync: InvoiceSync, **options: Any) -> InvoiceXmlSync:
        if any(s.scope.context_key != self.owner.context_key for s in metadata_sync.streams):
            raise ValueError("XML worker context differs from connection")
        return self.owner.api.invoices.xml_sync(metadata_sync, **options)

    def download(self, ksef_number: str) -> bytes:
        return self.owner.api.invoices.get_invoice_bytes(ksef_number).content


class Exports:
    def __init__(self, owner: Ksef) -> None:
        self.owner = owner

    def start(
        self,
        filters: m.InvoiceQueryFilters,
        *,
        only_metadata: bool = False,
        compression_type: m.CompressionType = m.CompressionType.ZIP,
        public_certificate: str | None = None,
        public_key_id: str | None = None,
    ) -> ExportOperation:
        from .streaming_export import ExportOperation

        encryption = build_encryption_data(
            public_certificate or self.owner._certificate(public_key_id=public_key_id),
            public_key_id=public_key_id,
        )
        assert encryption.encryption_info is not None
        response = self.owner.api.invoices.export_invoices(
            m.InvoiceExportRequest(
                filters=filters,
                encryption=encryption.encryption_info,
                only_metadata=only_metadata,
                compression_type=compression_type,
            )
        )
        state = self.owner._state(
            "export",
            response.reference_number,
            key=base64.b64encode(encryption.key).decode(),
            iv=base64.b64encode(encryption.iv).decode(),
            only_metadata=only_metadata,
        )
        return ExportOperation(self.owner, state)


class Ksef:
    """High-level facade. ``api`` preserves access to the complete low-level SDK."""

    def __init__(
        self,
        api: AuthenticatedClient,
        options: KsefClientOptions,
        *,
        context_type: str,
        context_value: str,
    ) -> None:
        self.api, self.options = api, options
        self.context_key = f"{context_type}:{context_value}"
        self.environment = environment_key(options.normalized_base_url())
        self.invoices, self.exports = Invoices(self), Exports(self)
        self.permissions, self.certificates = Permissions(self), Certificates(self)

    @classmethod
    def begin_auth(
        cls,
        *,
        credentials: Credentials,
        profile: str | Profile | None = None,
        options: KsefClientOptions | None = None,
        context_type: str | None = None,
        context_value: str | None = None,
        profile_store: ProfileStore | None = None,
    ) -> AuthenticationOperation:
        if not isinstance(credentials, (TokenCredentials, XadesCredentials)):
            raise TypeError("Use TokenCredentials or XadesCredentials")
        options, kind, value = connection_options(
            profile=profile,
            options=options,
            context_type=context_type,
            context_value=context_value,
            profile_store=profile_store,
        )
        api = KsefClient(options)
        try:
            challenge = api.auth.get_challenge()
            certificate = (
                credentials.public_certificate
                or api.security.get_public_key_certificate_pem(
                    m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
                    algorithm=credentials.method,
                    public_key_id=credentials.public_key_id,
                )
                if isinstance(credentials, TokenCredentials)
                else None
            )
            payload = auth_payload(challenge, credentials, kind, value, certificate)
            response: m.AuthenticationInitResponse | None
            if isinstance(credentials, TokenCredentials):
                response = api.auth.submit_ksef_token_auth(payload)
            else:
                response = api.auth.submit_xades_auth_request(
                    payload,
                    verify_certificate_chain=credentials.verify_certificate_chain,
                    enforce_xades_compliance=credentials.enforce_xades_compliance,
                )
            if response is None:
                raise ValueError("Authentication returned no operation reference")
            state = OperationState(
                "auth",
                environment_key(options.normalized_base_url()),
                f"{kind}:{value}",
                response.reference_number,
                {"authentication_token": response.authentication_token.token},
            )
            return AuthenticationOperation(api, state, options)
        except BaseException:
            api.close()
            raise

    @classmethod
    def connect(
        cls,
        *,
        credentials: Credentials,
        timeout: float = 120,
        poll_interval: float = 2,
        profile: str | Profile | None = None,
        options: KsefClientOptions | None = None,
        context_type: str | None = None,
        context_value: str | None = None,
        profile_store: ProfileStore | None = None,
        refresh_margin_seconds: float = DEFAULT_REFRESH_MARGIN_SECONDS,
        on_refresh: Callable[[m.TokenInfo], None] | None = None,
    ) -> Ksef:
        validate_wait(timeout, poll_interval)
        with request_control(timeout_seconds=timeout):  # noqa: SIM117
            with cls.begin_auth(
                credentials=credentials,
                profile=profile,
                options=options,
                context_type=context_type,
                context_value=context_value,
                profile_store=profile_store,
            ) as operation:
                result = operation.wait(timeout, poll_interval)
                return cls.from_auth_result(
                    operation.options,
                    result,
                    context_key=operation.resume_state().context_key,
                    refresh_margin_seconds=refresh_margin_seconds,
                    on_refresh=on_refresh,
                )

    @classmethod
    def from_auth_result(
        cls,
        options: KsefClientOptions,
        result: AuthResult,
        *,
        context_key: str,
        refresh_margin_seconds: float = DEFAULT_REFRESH_MARGIN_SECONDS,
        on_refresh: Callable[[m.TokenInfo], None] | None = None,
    ) -> Ksef:
        options = safe_options(options)
        kind, value = context_key.split(":", 1)
        return cls(
            AuthenticatedClient.from_auth_result(
                options,
                result,
                refresh_margin_seconds=refresh_margin_seconds,
                on_refresh=on_refresh,
            ),
            options,
            context_type=kind,
            context_value=value,
        )

    def _state(self, kind: str, reference: str, **payload: Any) -> OperationState:
        return OperationState(kind, self.environment, self.context_key, reference, payload)

    def _certificate(self, *, public_key_id: str | None = None) -> str:
        return self.api.security.get_public_key_certificate_pem(
            m.PublicKeyCertificateUsage.SYMMETRICKEYENCRYPTION,
            algorithm="rsa",
            public_key_id=public_key_id,
        )

    def online_session(
        self,
        *,
        form_code: m.FormCode = FA3,
        upo_v43: bool = False,
        public_certificate: str | None = None,
        public_key_id: str | None = None,
    ) -> Session:
        handle = OnlineSessionWorkflow(self.api.sessions).open_session(
            form_code=form_code,
            public_certificate=public_certificate or self._certificate(public_key_id=public_key_id),
            public_key_id=public_key_id,
            upo_v43=upo_v43,
        )
        return Session(self, handle)

    def batch_session(
        self,
        archive_bytes: bytes,
        *,
        form_code: m.FormCode = FA3,
        compression_type: m.CompressionType = m.CompressionType.ZIP,
        offline_mode: bool | None = None,
        upo_v43: bool = False,
        public_certificate: str | None = None,
        public_key_id: str | None = None,
    ) -> Session:
        handle = BatchSessionWorkflow(self.api.sessions, self.api.http_client).open_session(
            form_code=form_code,
            archive_bytes=archive_bytes,
            compression_type=compression_type,
            public_certificate=public_certificate or self._certificate(public_key_id=public_key_id),
            public_key_id=public_key_id,
            offline_mode=offline_mode,
            upo_v43=upo_v43,
        )
        return Session(self, handle, batch=True)

    def resume_session(
        self, state: OperationState, *, archive_bytes: bytes | None = None
    ) -> Session:
        state.bind(self.environment, self.context_key)
        if state.kind not in {"online", "batch"}:
            raise ValueError("Expected a session state")
        saved = state.payload
        if type(saved.get("session")) is not dict:
            raise ValueError("Invalid session state payload")
        if type(saved.get("close_started", False)) is not bool:
            raise ValueError("Invalid session close attempt state")
        if saved.get("closed") is True and saved.get("close_started") is False:
            raise ValueError("Closed session cannot have an unstarted close attempt")
        handle: Any
        if state.kind == "online":
            handle = OnlineSessionWorkflow(self.api.sessions).resume_session(
                OnlineSessionState.from_dict(saved["session"])
            )
        else:
            parsed = BatchSessionState.from_dict(saved["session"])
            handle = BatchSessionWorkflow(self.api.sessions, self.api.http_client).resume_session(
                parsed,
                archive_bytes=archive_bytes,
                compression_type=parsed.batch_file.compression_type or m.CompressionType.ZIP,
            )
        if handle.reference_number != state.reference_number:
            raise ValueError("Inconsistent session reference")
        session = Session(
            self,
            handle,
            batch=state.kind == "batch",
            completed_parts=saved.get("completed_parts"),
            closed=saved.get("closed", False),
        )
        session._close_started = saved.get("close_started", session.closed)
        return session

    def resume_operation(self, state: OperationState) -> Any:
        state.bind(self.environment, self.context_key)
        ref = state.reference_number
        if state.kind == "invoice":
            session_ref = state.payload["session_reference"]
            return Operation[m.SessionInvoiceStatusResponse](
                state, lambda: self.api.sessions.get_session_invoice_status(session_ref, ref)
            )
        if state.kind in {"online", "batch", "upo"}:
            finish = (lambda status: status.upo) if state.kind == "upo" else None
            return Operation(state, lambda: self.api.sessions.get_session_status(ref), finish)
        if state.kind == "permission":
            return Operation[m.PermissionsOperationStatusResponse](
                state, lambda: self.api.permissions.get_operation_status(ref)
            )
        if state.kind == "certificate":
            return Operation[m.CertificateEnrollmentStatusResponse](
                state, lambda: self.api.certificates.get_enrollment_status(ref)
            )
        if state.kind == "export":
            from .streaming_export import ExportOperation

            return ExportOperation(self, state)
        raise ValueError("Use resume_auth for an authentication operation")

    @classmethod
    def resume_auth(
        cls,
        state: OperationState,
        *,
        profile: str | Profile | None = None,
        options: KsefClientOptions | None = None,
        context_type: str | None = None,
        context_value: str | None = None,
        profile_store: ProfileStore | None = None,
    ) -> AuthenticationOperation:
        options, kind, value = connection_options(
            profile=profile,
            options=options,
            context_type=context_type,
            context_value=context_value,
            profile_store=profile_store,
        )
        state.bind(environment_key(options.normalized_base_url()), f"{kind}:{value}")
        validate_auth_state(state)
        return AuthenticationOperation(KsefClient(options), state, options)

    def close(self) -> None:
        self.api.close()

    def __enter__(self) -> Ksef:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class Permissions:
    def __init__(self, owner: Ksef) -> None:
        self.owner = owner

    def _operation(
        self, response: m.PermissionsOperationResponse
    ) -> Operation[m.PermissionsOperationStatusResponse]:
        return self.owner.resume_operation(
            self.owner._state("permission", response.reference_number)
        )

    def grant_authorization(
        self, request_payload: m.EntityAuthorizationPermissionsGrantRequest
    ) -> Operation[m.PermissionsOperationStatusResponse]:
        return self._operation(self.owner.api.permissions.grant_authorization(request_payload))

    def grant_entity(
        self, request_payload: m.EntityPermissionsGrantRequest
    ) -> Operation[m.PermissionsOperationStatusResponse]:
        return self._operation(self.owner.api.permissions.grant_entity(request_payload))

    def grant_eu_entity(
        self, request_payload: m.EuEntityPermissionsGrantRequest
    ) -> Operation[m.PermissionsOperationStatusResponse]:
        return self._operation(self.owner.api.permissions.grant_eu_entity(request_payload))

    def grant_eu_entity_admin(
        self, request_payload: m.EuEntityAdministrationPermissionsGrantRequest
    ) -> Operation[m.PermissionsOperationStatusResponse]:
        return self._operation(self.owner.api.permissions.grant_eu_entity_admin(request_payload))

    def grant_indirect(
        self, request_payload: m.IndirectPermissionsGrantRequest
    ) -> Operation[m.PermissionsOperationStatusResponse]:
        return self._operation(self.owner.api.permissions.grant_indirect(request_payload))

    def grant_person(
        self, request_payload: m.PersonPermissionsGrantRequest
    ) -> Operation[m.PermissionsOperationStatusResponse]:
        return self._operation(self.owner.api.permissions.grant_person(request_payload))

    def grant_subunit(
        self, request_payload: m.SubunitPermissionsGrantRequest
    ) -> Operation[m.PermissionsOperationStatusResponse]:
        return self._operation(self.owner.api.permissions.grant_subunit(request_payload))

    def revoke_authorization(
        self, permission_id: str
    ) -> Operation[m.PermissionsOperationStatusResponse]:
        return self._operation(self.owner.api.permissions.revoke_authorization(permission_id))

    def revoke_common_permission(
        self, permission_id: str
    ) -> Operation[m.PermissionsOperationStatusResponse]:
        return self._operation(self.owner.api.permissions.revoke_common_permission(permission_id))


class Certificates:
    def __init__(self, owner: Ksef) -> None:
        self.owner = owner

    def send_enrollment(
        self, request_payload: m.EnrollCertificateRequest
    ) -> Operation[m.CertificateEnrollmentStatusResponse]:
        response = self.owner.api.certificates.send_enrollment(request_payload)
        return self.owner.resume_operation(
            self.owner._state("certificate", response.reference_number)
        )

    def get_limits(self) -> m.CertificateLimitsResponse:
        return self.owner.api.certificates.get_limits()

    def get_enrollment_data(self) -> m.CertificateEnrollmentDataResponse:
        return self.owner.api.certificates.get_enrollment_data()

    def query_certificates(
        self,
        request_payload: m.QueryCertificatesRequest,
        *,
        page_size: int | None = None,
        page_offset: int | None = None,
    ) -> m.QueryCertificatesResponse:
        return self.owner.api.certificates.query_certificates(
            request_payload, page_size=page_size, page_offset=page_offset
        )

    def retrieve_certificate(
        self, request_payload: m.RetrieveCertificatesRequest
    ) -> m.RetrieveCertificatesResponse:
        return self.owner.api.certificates.retrieve_certificate(request_payload)

    def revoke_certificate(
        self, certificate_serial_number: str, request_payload: m.RevokeCertificateRequest
    ) -> None:
        self.owner.api.certificates.revoke_certificate(certificate_serial_number, request_payload)
