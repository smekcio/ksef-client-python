"""Consumer contracts for resumable operation polling, including async parity."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest

from ksef_client import AsyncKsef, Ksef, KsefClientOptions, TokenCredentials, XadesCredentials
from ksef_client import models as m
from ksef_client.async_facade import AsyncSession
from ksef_client.facade import AuthenticationOperation, Session, connection_options
from ksef_client.operations import (
    FAILURES,
    PENDING,
    AsyncOperation,
    KsefOperationError,
    KsefOperationTimeout,
    Operation,
    OperationState,
    environment_key,
    outcome,
)
from ksef_client.profiles import Profile
from ksef_client.rate_limiting import CancellationToken, KsefRequestCancelledError
from ksef_client.request_control import request_control
from ksef_client.services.xades import XadesKeyPair

OPTIONS = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")


def state(kind="invoice", **payload):
    if kind == "invoice":
        payload.setdefault("session_reference", "SESSION")
    return OperationState(
        kind, environment_key(OPTIONS.normalized_base_url()), "Nip:DUMMY", "REF", payload
    )


def status(code=200, *, failed=0, upo=None):
    return SimpleNamespace(
        status=m.StatusInfo(code=code, description="DUMMY"), failed_invoice_count=failed, upo=upo
    )


@pytest.mark.parametrize("kind", sorted(PENDING))
@pytest.mark.parametrize("asynchronous", [False, True])
def test_polling_wait_returns_typed_status_and_caches_success(kind, asynchronous):
    final = status(200, upo=m.UpoResponse.from_dict({"pages": []}))
    pending = status(min(PENDING[kind]))
    if kind == "upo":
        pending = status(200)
    if asynchronous:

        async def run():
            fetch = AsyncMock(side_effect=[pending, final])
            operation = AsyncOperation[Any](state(kind), fetch)
            assert await operation.wait(poll_interval=0.001) is final
            assert await operation.wait() is final
            assert fetch.await_count == 2
            assert "DUMMY" not in repr(operation)

        asyncio.run(run())
    else:
        fetch = Mock(side_effect=[pending, final])
        operation = Operation[Any](state(kind), fetch)
        assert operation.wait(poll_interval=0.001) is final
        assert operation.wait() is final
        assert fetch.call_count == 2
        assert "DUMMY" not in repr(operation)


@pytest.mark.parametrize("kind,code", [(k, c) for k, values in FAILURES.items() for c in values])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_business_failures_and_repeated_wait_do_not_resubmit(kind, code, asynchronous):
    final = status(code)
    if asynchronous:

        async def run():
            fetch = AsyncMock(return_value=final)
            operation = AsyncOperation[Any](state(kind), fetch)
            for _ in range(2):
                with pytest.raises(KsefOperationError) as caught:
                    await operation.wait()
                assert caught.value.last_status is final
                assert caught.value.status_code == code
                assert "DUMMY" not in str(caught.value.to_dict())
            fetch.assert_awaited_once()

        asyncio.run(run())
    else:
        fetch = Mock(return_value=final)
        operation = Operation[Any](state(kind), fetch)
        for _ in range(2):
            with pytest.raises(KsefOperationError) as caught:
                operation.wait()
            assert caught.value.last_status is final
        fetch.assert_called_once()


@pytest.mark.parametrize("kind", sorted(PENDING))
def test_unknown_codes_and_failed_session_invoices_are_not_success(kind):
    assert outcome(kind, status(999)) == "unsupported_status"
    assert outcome(kind, SimpleNamespace(status=None)) == "unsupported_status"
    assert outcome("online", status(failed=1)) == "invoices_rejected"
    assert outcome("batch", status(failed=2)) == "invoices_rejected"
    assert outcome("upo", status(440)) == "rejected"


@pytest.mark.parametrize("asynchronous", [False, True])
def test_deadline_preserves_replay_and_parent_cancellation(asynchronous):
    async def run():
        operation = AsyncOperation[Any](state(), AsyncMock(return_value=status(100)))
        with pytest.raises(KsefOperationTimeout) as caught:
            await operation.wait(timeout=0.005, poll_interval=0.001)
        assert caught.value.state == state()
        token = CancellationToken()
        with request_control(cancellation=token):
            token.cancel()
            with pytest.raises(KsefRequestCancelledError):
                await operation.wait()

    if asynchronous:
        asyncio.run(run())
    else:
        operation = Operation[Any](state(), Mock(return_value=status(100)))
        with pytest.raises(KsefOperationTimeout) as caught:
            operation.wait(timeout=0.005, poll_interval=0.001)
        assert caught.value.state == state()
        token = CancellationToken()
        with request_control(cancellation=token):
            token.cancel()
            with pytest.raises(KsefRequestCancelledError):
                operation.wait()


@pytest.mark.parametrize("value", [0, -1, True, float("nan"), float("inf"), "bad"])
def test_invalid_polling_options_fail_before_http(value):
    fetch = Mock()
    with pytest.raises(ValueError):
        Operation[Any](state(), fetch).wait(timeout=value)
    with pytest.raises(ValueError):
        asyncio.run(AsyncOperation[Any](state(), AsyncMock()).wait(poll_interval=value))
    fetch.assert_not_called()


def test_persistence_is_explicit_bounded_and_bound_to_environment():
    original = state(key="SECRET")
    assert "SECRET" not in repr(original)
    assert "SECRET" in original.to_json()
    assert OperationState.from_dict(original.to_dict()) == original
    with pytest.raises(ValueError):
        original.bind("other", original.context_key)
    for raw in [
        {},
        {**original.to_dict(), "version": True},
        {**original.to_dict(), "kind": "unknown"},
        {**original.to_dict(), "reference_number": ""},
        {**original.to_dict(), "payload": []},
        {**original.to_dict(), "payload": {"large": "x" * (4 * 1024 * 1024)}},
    ]:
        with pytest.raises(ValueError):
            OperationState.from_dict(raw)


def owner(asynchronous=False):
    api = Mock()
    cls = AsyncKsef if asynchronous else Ksef
    return cls(api, OPTIONS, context_type="Nip", context_value="DUMMY")


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_session_context_close_upload_checkpoint_and_no_wait(batch, asynchronous):
    facade = owner(asynchronous)
    handle = Mock(
        reference_number="SESSION", part_upload_requests=[SimpleNamespace(ordinal_number=1)]
    )
    handle.get_state.return_value.to_dict.return_value = {"saved": "state"}
    calls: list[int] = []

    def upload(**kwargs):
        kwargs["progress_callback"](1)

    if asynchronous:
        handle.close = AsyncMock()
        handle.upload_parts = AsyncMock(side_effect=upload)
        handle.send_invoice = AsyncMock(return_value=SimpleNamespace(reference_number="INVOICE"))
        facade.api.sessions.get_session_invoice_status = AsyncMock(return_value=status())

        async def run():
            session = AsyncSession(facade, handle, batch=batch)
            async with session:
                if batch:
                    await session.upload_parts(progress_callback=calls.append)
                else:
                    result = await session.send_invoice(b"<xml/>")
                    assert await result.wait() is not None
            await session.close()
            assert session.resume_state().payload["closed"]
            handle.close.assert_awaited_once()

        asyncio.run(run())
    else:
        handle.upload_parts.side_effect = upload
        handle.send_invoice.return_value = SimpleNamespace(reference_number="INVOICE")
        facade.api.sessions.get_session_invoice_status.return_value = status()
        session = Session(facade, handle, batch=batch)
        with session:
            if batch:
                session.upload_parts(progress_callback=calls.append)
            else:
                assert session.send_invoice(b"<xml/>").wait() is not None
        session.close()
        handle.close.assert_called_once()
        assert session.resume_state().payload["closed"]
    assert calls == ([1] if batch else [])
    handle.get_status.assert_not_called()


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_exception_preserves_batch_and_online_keeps_primary_error(batch, asynchronous):
    handle = Mock(
        reference_number="SESSION", part_upload_requests=[SimpleNamespace(ordinal_number=1)]
    )
    handle.get_state.return_value.to_dict.return_value = {}
    if asynchronous:
        handle.close = AsyncMock(side_effect=OSError("close failed"))

        async def run():
            session = AsyncSession(owner(True), handle, batch=batch)
            with pytest.raises(RuntimeError, match="primary"):
                async with session:
                    raise RuntimeError("primary")
            assert handle.close.await_count == (0 if batch else 1)

        asyncio.run(run())
    else:
        handle.close.side_effect = OSError("close failed")
        session = Session(owner(), handle, batch=batch)
        with pytest.raises(RuntimeError, match="primary"), session:
            raise RuntimeError("primary")
        assert handle.close.call_count == (0 if batch else 1)


def test_incomplete_upload_ambiguous_close_and_invalid_session_actions():
    handle = Mock(
        reference_number="SESSION", part_upload_requests=[SimpleNamespace(ordinal_number=1)]
    )
    handle.get_state.return_value.to_dict.return_value = {}
    session = Session(owner(), handle, batch=True)
    with pytest.raises(KsefOperationError, match="incomplete_upload"):
        session.close()
    with pytest.raises(ValueError):
        session.send_invoice(b"xml")
    online = Session(owner(), handle)
    with pytest.raises(ValueError):
        online.upload_parts()
    handle.close.side_effect = OSError()
    with pytest.raises(OSError):
        online.close()
    with pytest.raises(KsefOperationError, match="close_outcome_unknown"):
        online.close()
    with pytest.raises(ValueError):
        online.send_invoice(b"xml")


def test_profiles_and_explicit_credentials_validation():
    profile = Profile("dummy", OPTIONS.base_url, "nip", "DUMMY")
    assert connection_options(profile=profile) == (OPTIONS, "Nip", "DUMMY")
    store = Mock()
    store.get.return_value = profile
    assert connection_options(profile="dummy", profile_store=store)[1:] == ("Nip", "DUMMY")
    with pytest.raises(ValueError):
        connection_options(profile=profile, options=OPTIONS)
    with pytest.raises(ValueError):
        connection_options()
    with pytest.raises(ValueError):
        TokenCredentials("")
    assert "SECRET" not in repr(TokenCredentials("SECRET"))
    assert "SECRET" not in repr(XadesCredentials(XadesKeyPair("CERT", "SECRET")))


def test_facade_cannot_inherit_mutation_retries_from_sdk_options():
    from dataclasses import replace

    from ksef_client import RetryConfig

    configured = replace(
        OPTIONS,
        retry=RetryConfig(
            retryable_methods=frozenset({"GET", "PUT", "DELETE"}),
            retryable_post_paths=frozenset(
                {"/invoices/query/metadata", "/auth/token/redeem", "/sessions/online"}
            ),
        ),
    )
    guarded, _, _ = connection_options(
        options=configured, context_type="nip", context_value="DUMMY"
    )
    assert guarded.retry is not None and configured.retry is not None
    assert guarded.retry.retryable_methods == frozenset({"GET"})
    assert guarded.retry.retryable_post_paths == frozenset({"/invoices/query/metadata"})
    assert "DELETE" in configured.retry.retryable_methods


def test_auth_redeem_unknown_is_not_repeated():
    api = Mock()
    api.auth.get_auth_status.return_value = status()
    api.auth.redeem_token.side_effect = OSError("uncertain")
    operation = AuthenticationOperation(api, state("auth", authentication_token="SECRET"), OPTIONS)
    with pytest.raises(OSError):
        operation.wait()
    with pytest.raises(KsefOperationError, match="redeem_outcome_unknown"):
        operation.wait()
    api.auth.redeem_token.assert_called_once()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("expired", [False, True])
def test_wire_timeout_preserves_operation_state_only_at_deadline(asynchronous, expired):
    from contextlib import nullcontext

    from ksef_client.exceptions import KsefTransportError

    failure = KsefTransportError(status_code=0, message="transport timeout")
    control = Mock()
    control.remaining.return_value = 0 if expired else 1
    with patch("ksef_client.operations.request_control", return_value=nullcontext(control)):
        if asynchronous:
            op = AsyncOperation[Any](state(), AsyncMock(side_effect=failure))
            with pytest.raises(KsefOperationTimeout if expired else KsefTransportError):
                asyncio.run(op.wait())
        else:
            op_sync = Operation[Any](state(), Mock(side_effect=failure))
            with pytest.raises(KsefOperationTimeout if expired else KsefTransportError):
                op_sync.wait()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "parts,closed", [([True], False), ([1, 1], False), ([2], False), ([1], False), ([], 1)]
)
def test_resumed_session_rejects_corrupt_progress(asynchronous, parts, closed):
    handle = Mock(reference_number="REF", part_upload_requests=[SimpleNamespace(ordinal_number=1)])
    cls = AsyncSession if asynchronous else Session
    with pytest.raises(ValueError):
        cls(owner(asynchronous), handle, batch=parts != [1], completed_parts=parts, closed=closed)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_resumed_session_rejects_nonboolean_close_attempt(asynchronous):
    facade = owner(asynchronous)
    with pytest.raises(ValueError):
        facade.resume_session(state("online", close_started="bad"))


def test_oversized_operation_state_and_generated_async_parity():
    import subprocess
    import sys
    from pathlib import Path

    with pytest.raises(ValueError):
        state("permission", data="x" * (4 * 1024 * 1024))
    subprocess.run(
        [sys.executable, "tools/generate_async_facade.py", "--check"],
        cwd=Path(__file__).resolve().parents[1],
        check=True,
    )


@pytest.mark.parametrize("asynchronous", [False, True])
def test_unknown_status_raises_explicit_error_and_auth_state_is_validated(asynchronous):
    from ksef_client import ErrorCode
    from ksef_client.facade import validate_auth_state

    for payload in [
        {},
        {"authentication_token": ""},
        {"authentication_token": "x" * 16385},
        {"authentication_token": "TOKEN", "redeem_started": "bad"},
    ]:
        with pytest.raises(ValueError):
            validate_auth_state(state("auth", **payload))
    with pytest.raises(KsefOperationError) as caught:
        if asynchronous:
            asyncio.run(AsyncOperation[Any](state(), AsyncMock(return_value=status(999))).wait())
        else:
            Operation[Any](state(), Mock(return_value=status(999))).wait()
    assert caught.value.reason_code == "unsupported_status"
    assert caught.value.code == ErrorCode.WORKFLOW_ERROR


@pytest.mark.parametrize("asynchronous", [False, True])
def test_authentication_connect_closes_bootstrap_and_preserves_low_level_api(asynchronous):
    module = "ksef_client.async_facade" if asynchronous else "ksef_client.facade"
    bootstrap, authenticated = Mock(), Mock()
    init = m.AuthenticationInitResponse.from_dict(
        {
            "referenceNumber": "AUTH",
            "authenticationToken": {"token": "SECRET", "validUntil": "2099-01-01"},
        }
    )
    tokens = m.AuthenticationTokensResponse.from_dict(
        {"accessToken": {"token": "ACCESS"}, "refreshToken": {"token": "REFRESH"}}
    )
    methods = {
        "get_challenge": m.AuthenticationChallengeResponse.from_dict(
            {"challenge": "DUMMY", "timestampMs": 1}
        ),
        "submit_ksef_token_auth": init,
        "get_auth_status": status(),
        "redeem_token": tokens,
    }
    for name, result in methods.items():
        setattr(
            bootstrap.auth,
            name,
            AsyncMock(return_value=result) if asynchronous else Mock(return_value=result),
        )
    bootstrap.security.get_public_key_certificate_pem = (
        AsyncMock(return_value="CERT") if asynchronous else Mock(return_value="CERT")
    )
    if asynchronous:
        bootstrap.aclose = AsyncMock()
        authenticated.aclose = AsyncMock()
    with (
        patch(
            module + (".AsyncKsefClient" if asynchronous else ".KsefClient"), return_value=bootstrap
        ),
        patch(
            module + (".AsyncAuthenticatedClient" if asynchronous else ".AuthenticatedClient")
        ) as cls,
        patch("ksef_client.facade.encrypt_ksef_token", return_value="CIPHER"),
    ):
        cls.from_auth_result.return_value = authenticated
        if asynchronous:

            async def run():
                connected = await AsyncKsef.connect(
                    credentials=TokenCredentials("SECRET"),
                    options=OPTIONS,
                    context_type="nip",
                    context_value="DUMMY",
                )
                async with connected:
                    assert connected.api is authenticated

            asyncio.run(run())
            bootstrap.aclose.assert_awaited_once()
        else:
            with Ksef.connect(
                credentials=TokenCredentials("SECRET"),
                options=OPTIONS,
                context_type="nip",
                context_value="DUMMY",
            ) as connected:
                assert connected.api is authenticated
            bootstrap.close.assert_called_once()


def test_resume_validates_identity_before_io_and_administrative_operations():
    facade = owner()
    with pytest.raises(ValueError):
        facade.resume_operation(OperationState("invoice", "wrong", "Nip:DUMMY", "REF"))
    for kind, api, method in [
        ("permission", facade.api.permissions, "get_operation_status"),
        ("certificate", facade.api.certificates, "get_enrollment_status"),
        ("online", facade.api.sessions, "get_session_status"),
        ("batch", facade.api.sessions, "get_session_status"),
    ]:
        getattr(api, method).return_value = status()
        assert facade.resume_operation(state(kind)).wait().status.code == 200
    facade.api.sessions.get_session_status.return_value = status(
        upo=m.UpoResponse.from_dict({"pages": []})
    )
    assert facade.resume_operation(state("upo")).wait().pages == []
    with pytest.raises(ValueError):
        facade.resume_operation(state("auth"))
    with pytest.raises(ValueError):
        facade.resume_session(state("invoice"))
    with pytest.raises(ValueError):
        Ksef.resume_auth(state(), options=OPTIONS, context_type="nip", context_value="DUMMY")


def resolve(value, asynchronous):
    return asyncio.run(value) if asynchronous else value


@pytest.mark.parametrize("asynchronous", [False, True])
def test_all_administrative_handles_and_sync_certificate_endpoints(asynchronous):
    client = owner(asynchronous)
    methods = [
        "grant_authorization",
        "grant_entity",
        "grant_eu_entity",
        "grant_eu_entity_admin",
        "grant_indirect",
        "grant_person",
        "grant_subunit",
        "revoke_authorization",
        "revoke_common_permission",
    ]
    for name in methods:
        response = m.PermissionsOperationResponse(reference_number="REF")
        method = AsyncMock(return_value=response) if asynchronous else Mock(return_value=response)
        setattr(client.api.permissions, name, method)
        op = resolve(getattr(client.permissions, name)(Mock()), asynchronous)
        assert op.resume_state().kind == "permission"
    client.api.certificates.send_enrollment = (
        AsyncMock(
            return_value=m.EnrollCertificateResponse(reference_number="REF", timestamp="2026-01-01")
        )
        if asynchronous
        else Mock(
            return_value=m.EnrollCertificateResponse(reference_number="REF", timestamp="2026-01-01")
        )
    )
    assert (
        resolve(client.certificates.send_enrollment(Mock()), asynchronous).resume_state().kind
        == "certificate"
    )
    for name, args in [
        ("get_limits", ()),
        ("get_enrollment_data", ()),
        ("query_certificates", (Mock(),)),
        ("retrieve_certificate", (Mock(),)),
        ("revoke_certificate", ("SERIAL", Mock())),
    ]:
        method = AsyncMock(return_value=None) if asynchronous else Mock(return_value=None)
        setattr(client.api.certificates, name, method)
        resolve(getattr(client.certificates, name)(*args), asynchronous)
    client.api.invoices.get_invoice_bytes = (
        AsyncMock(return_value=m.BinaryContent(b"xml"))
        if asynchronous
        else Mock(return_value=m.BinaryContent(b"xml"))
    )
    assert resolve(client.invoices.download("NUMBER"), asynchronous) == b"xml"
    client.api.permissions.get_operation_status = (
        AsyncMock(return_value=status()) if asynchronous else Mock(return_value=status())
    )
    client.api.certificates.get_enrollment_status = (
        AsyncMock(return_value=status()) if asynchronous else Mock(return_value=status())
    )
    client.api.sessions.get_session_status = (
        AsyncMock(return_value=status(upo=m.UpoResponse(pages=[])))
        if asynchronous
        else Mock(return_value=status(upo=m.UpoResponse(pages=[])))
    )
    for kind in ["permission", "certificate", "online", "batch", "upo"]:
        assert resolve(client.resume_operation(state(kind)).wait(), asynchronous) is not None
    with pytest.raises(ValueError):
        client.resume_operation(state("auth"))
    with pytest.raises(ValueError):
        client.resume_session(state("invoice"))


@pytest.mark.parametrize("asynchronous", [False, True])
def test_session_factories_resume_and_upo_use_existing_workflows(asynchronous):
    module = "ksef_client.async_facade" if asynchronous else "ksef_client.facade"
    client = owner(asynchronous)
    client.api.security.get_public_key_certificate_pem = (
        AsyncMock(return_value="CERT") if asynchronous else Mock(return_value="CERT")
    )
    from ksef_client.services.crypto import EncryptionData

    encryption = EncryptionData(
        b"k" * 32,
        b"i" * 16,
        m.EncryptionInfo.from_dict(
            {"encryptedSymmetricKey": "AA==", "initializationVector": "AA=="}
        ),
    )
    client.api.sessions.open_online_session = (
        AsyncMock(
            return_value=SimpleNamespace(reference_number="SESSION", valid_until="2099-01-01")
        )
        if asynchronous
        else Mock(
            return_value=SimpleNamespace(reference_number="SESSION", valid_until="2099-01-01")
        )
    )
    client.api.sessions.open_batch_session = (
        AsyncMock(return_value=SimpleNamespace(reference_number="BATCH", part_upload_requests=[]))
        if asynchronous
        else Mock(return_value=SimpleNamespace(reference_number="BATCH", part_upload_requests=[]))
    )
    with patch("ksef_client.services.workflows.build_encryption_data", return_value=encryption):
        online = resolve(client.online_session(), asynchronous)
        resumed = client.resume_session(online.resume_state())
        assert resumed.handle.reference_number == "SESSION"
        saved = online.resume_state().to_dict()
        saved["reference_number"] = "WRONG"
        with pytest.raises(ValueError):
            client.resume_session(OperationState.from_dict(saved))
        batch = resolve(client.batch_session(b"archive"), asynchronous)
        resumed_batch = client.resume_session(batch.resume_state(), archive_bytes=b"archive")
        assert resumed_batch.batch
    client.api.sessions.get_session_status = (
        AsyncMock(return_value=status(upo=m.UpoResponse(pages=[])))
        if asynchronous
        else Mock(return_value=status(upo=m.UpoResponse(pages=[])))
    )
    assert resolve(online.upo().wait(), asynchronous).pages == []
    filters: Any = Mock()
    client.api.invoices.export_invoices = (
        AsyncMock(return_value=SimpleNamespace(reference_number="EXPORT"))
        if asynchronous
        else Mock(return_value=SimpleNamespace(reference_number="EXPORT"))
    )
    with patch(module + ".build_encryption_data", return_value=encryption):
        exported = resolve(client.exports.start(filters), asynchronous)
        assert (
            client.resume_operation(exported.resume_state()).resume_state()
            == exported.resume_state()
        )


@pytest.mark.parametrize("asynchronous", [False, True])
def test_auth_xades_resume_failure_cleanup_and_store_credentials(asynchronous):
    cls = AsyncKsef if asynchronous else Ksef
    module = "ksef_client.async_facade" if asynchronous else "ksef_client.facade"
    bootstrap = Mock()
    bootstrap.aclose = AsyncMock()

    def setting(name, result):
        setattr(
            bootstrap.auth,
            name,
            AsyncMock(return_value=result) if asynchronous else Mock(return_value=result),
        )

    setting(
        "get_challenge",
        m.AuthenticationChallengeResponse.from_dict({"challenge": "DUMMY", "timestampMs": 1}),
    )
    setting(
        "submit_xades_auth_request",
        m.AuthenticationInitResponse.from_dict(
            {
                "referenceNumber": "REF",
                "authenticationToken": {"token": "SECRET", "validUntil": "2099-01-01"},
            }
        ),
    )
    tokens = m.AuthenticationTokensResponse.from_dict(
        {"accessToken": {"token": "ACCESS"}, "refreshToken": {"token": "REFRESH"}}
    )
    setting("get_auth_status", status())
    setting("redeem_token", tokens)
    settings: dict[str, Any] = {"options": OPTIONS, "context_type": "nip", "context_value": "DUMMY"}
    cred = XadesCredentials(XadesKeyPair("CERT", "SECRET"))
    with (
        patch(
            module + (".AsyncKsefClient" if asynchronous else ".KsefClient"), return_value=bootstrap
        ),
        patch("ksef_client.facade.build_auth_token_request_xml", return_value="<auth/>"),
        patch("ksef_client.facade.sign_xades_enveloped", return_value="<signed/>"),
    ):
        op = resolve(cls.begin_auth(credentials=cred, **settings), asynchronous)
        resumed = cls.resume_auth(op.resume_state(), **settings)
        assert resolve(resumed.wait(), asynchronous).access_token == "ACCESS"
        resolve(resumed.close(), asynchronous)
        bootstrap.auth.redeem_token.side_effect = OSError("uncertain")
        with pytest.raises(OSError):
            resolve(op.wait(), asynchronous)
        with pytest.raises(KsefOperationError):
            resolve(op.wait(), asynchronous)
        bootstrap.auth.submit_xades_auth_request.return_value = None
        with pytest.raises(ValueError):
            resolve(cls.begin_auth(credentials=cred, **settings), asynchronous)
        with pytest.raises(TypeError):
            resolve(cls.begin_auth(credentials=Mock(), **settings), asynchronous)
        with pytest.raises(ValueError):
            cls.resume_auth(state(), **settings)
    store = Mock()
    certificate = Mock(certificate_pem=b"CERT")
    certificate.private_key.private_bytes.return_value = b"PRIVATE"
    store.load.return_value = certificate
    assert XadesCredentials.from_store("cert", store=store).key_pair.private_key_pem == "PRIVATE"
    from ksef_client.facade import auth_payload

    with pytest.raises(TypeError):
        auth_payload(Mock(), Mock(), "Nip", "DUMMY")
