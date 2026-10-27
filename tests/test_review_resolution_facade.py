"""Behavioral regressions from the external PR 109 review."""

from __future__ import annotations

import asyncio
import base64
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from ksef_client import (
    AsyncKsef,
    Ksef,
    KsefClientOptions,
    OperationState,
    TokenCredentials,
    XadesCredentials,
)
from ksef_client import models as m
from ksef_client.clients.security import _select_public_key_certificate
from ksef_client.facade import auth_payload
from ksef_client.operations import STATE_ENVELOPE, STATE_MAX_BYTES
from ksef_client.services.crypto import EncryptionData
from ksef_client.services.sessions import AsyncBatchSessionHandle, BatchSessionHandle
from ksef_client.services.workflows import AsyncBatchUploadHelper, AuthResult, BatchUploadHelper
from ksef_client.services.xades import XadesKeyPair
from tests.helpers import generate_ec_cert, generate_rsa_cert
from tests.test_e2e_facade import _wait_for_invoice_at_hwm
from tests.test_operations_facade import owner, state


def requests():
    return [
        m.PartUploadRequest(
            ordinal_number=i, method="PUT", url=f"https://storage.test/{i}", headers={}
        )
        for i in range(1, 4)
    ]


def test_async_upload_failure_drains_tasks_and_records_acknowledged_success():
    async def run():
        entered = 0
        ready = asyncio.Event()
        confirmed: list[int] = []
        background: list[dict] = []
        asyncio.get_running_loop().set_exception_handler(lambda loop, ctx: background.append(ctx))

        async def request(method, url, **kwargs):
            nonlocal entered
            entered += 1
            if entered == 3:
                ready.set()
            await ready.wait()
            if url.endswith("/1"):
                raise RuntimeError("first failure")
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                # Simulate a transport completing a request while cancellation arrives.
                if url.endswith("/3"):
                    raise RuntimeError("late failure") from None

        before = set(asyncio.all_tasks())
        with pytest.raises(RuntimeError, match="first failure"):
            await AsyncBatchUploadHelper(
                SimpleNamespace(request=request), parallelism=3
            ).upload_parts(
                requests(), [(i, b"x") for i in range(1, 4)], progress_callback=confirmed.append
            )
        assert confirmed == [2]
        assert set(asyncio.all_tasks()) == before
        assert background == []

    asyncio.run(run())


def test_async_upload_cancellation_joins_children_even_when_cancelled_twice():
    async def run():
        entered = asyncio.Event()
        cleanup_entered = asyncio.Event()
        cleanup_release = asyncio.Event()
        active = 0

        async def request(*args, **kwargs):
            nonlocal active
            active += 1
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleanup_entered.set()
                await cleanup_release.wait()
                active -= 1

        task = asyncio.create_task(
            AsyncBatchUploadHelper(SimpleNamespace(request=request)).upload_parts(
                requests(), [(i, b"x") for i in range(1, 4)]
            )
        )
        await entered.wait()
        task.cancel()
        await cleanup_entered.wait()
        task.cancel()
        await asyncio.sleep(0)
        cleanup_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert active == 0

    asyncio.run(run())


def test_sync_parallel_upload_records_remaining_successes_after_failure():
    barrier = threading.Barrier(3)
    confirmed: list[int] = []

    def request(method, url, **kwargs):
        barrier.wait(timeout=5)
        if url.endswith("/1"):
            raise RuntimeError("first failure")
        time.sleep(0.02)

    with pytest.raises(RuntimeError, match="first failure"):
        BatchUploadHelper(SimpleNamespace(request=request)).upload_parts(
            requests(),
            [(i, b"x") for i in range(1, 4)],
            parallelism=3,
            progress_callback=confirmed.append,
        )
    assert sorted(confirmed) == [2, 3]


def test_sync_parallel_failure_cancels_queued_work_and_records_inflight_parts():
    ready = threading.Event()
    acknowledged: list[int] = []
    confirmed: list[int] = []

    def request(method, url, **kwargs):
        ordinal = int(url.rsplit("/", 1)[1])
        if ordinal == 1:
            assert ready.wait(timeout=5)
            raise RuntimeError("failure")
        ready.set()
        time.sleep(0.05)
        acknowledged.append(ordinal)

    parts = [
        m.PartUploadRequest(
            ordinal_number=i, method="PUT", url=f"https://storage.test/{i}", headers={}
        )
        for i in range(1, 101)
    ]
    with pytest.raises(RuntimeError, match="failure"):
        BatchUploadHelper(SimpleNamespace(request=request)).upload_parts(
            parts,
            [(i, b"x") for i in range(1, 101)],
            parallelism=2,
            progress_callback=confirmed.append,
        )
    assert 0 < len(confirmed) < 99
    assert sorted(confirmed) == sorted(acknowledged)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_completed_batch_can_resume_and_close_without_archive(asynchronous):
    client = owner(asynchronous)
    handle_cls = AsyncBatchSessionHandle if asynchronous else BatchSessionHandle
    client.api.sessions.close_batch_session = AsyncMock() if asynchronous else Mock()
    handle = handle_cls(
        client.api.sessions,
        Mock(),
        "BATCH",
        m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA"),
        m.BatchFileInfo(file_size=1, file_hash=base64.b64encode(b"x" * 32).decode(), file_parts=[]),
        requests()[:1],
        EncryptionData(b"k" * 32, b"i" * 16, None),
    )
    saved = client._state(
        "batch",
        "BATCH",
        session=handle.get_state().to_dict(),
        completed_parts=[1],
        closed=False,
        close_started=False,
    )
    invalid = saved.to_dict()
    invalid["payload"]["close_started"] = "invalid"
    with pytest.raises(ValueError, match="close attempt"):
        client.resume_session(OperationState.from_dict(invalid))
    invalid["payload"].update(closed=True, close_started=False)
    with pytest.raises(ValueError, match="Closed session"):
        client.resume_session(OperationState.from_dict(invalid))
    resumed = client.resume_session(saved)
    assert resumed.handle._encrypted_parts is None
    if asynchronous:

        async def run():
            await resumed.upload_parts()
            await resumed.close()

        asyncio.run(run())
        client.api.sessions.close_batch_session.assert_awaited_once()
    else:
        resumed.upload_parts()
        resumed.close()
        client.api.sessions.close_batch_session.assert_called_once()


def test_state_cipher_roundtrip_integrity_and_random_nonce():
    original = state("export", key="SECRET", iv="IV")
    key = b"k" * 32
    first = original.to_encrypted_bytes(key)
    second = original.to_encrypted_bytes(key)
    assert first != second
    assert b"SECRET" not in first
    assert OperationState.from_encrypted_bytes(first, key) == original
    for corrupt, decryption_key in [(first[:-1] + bytes([first[-1] ^ 1]), key), (first, b"w" * 32)]:
        with pytest.raises(ValueError, match="authentication"):
            OperationState.from_encrypted_bytes(corrupt, decryption_key)
    assert OperationState.from_json(original.to_json()) == original


@pytest.mark.parametrize("key", [b"", b"x" * 16, "x" * 32])
def test_state_cipher_rejects_invalid_keys(key):
    with pytest.raises(ValueError, match="32-byte"):
        state().to_encrypted_bytes(key)
    with pytest.raises(ValueError, match="32-byte"):
        OperationState.from_encrypted_bytes(b"", key)


@pytest.mark.parametrize(
    "data",
    [b"", b"plaintext", STATE_ENVELOPE + b"x" * (STATE_MAX_BYTES + 29)],
    ids=["empty", "plaintext", "oversized"],
)
def test_state_cipher_rejects_bad_envelopes(data):
    with pytest.raises(ValueError, match="envelope"):
        OperationState.from_encrypted_bytes(data, b"k" * 32)


@pytest.mark.parametrize("payload", [{"bad": b"bytes"}, {"bad": float("nan")}])
def test_invalid_state_values_have_consistent_validation_errors(payload):
    with pytest.raises(ValueError, match="JSON"):
        state("export", **payload)


@pytest.mark.parametrize(
    "value", ["{", "x" * (STATE_MAX_BYTES + 1), 1], ids=["corrupt", "oversized", "wrong-type"]
)
def test_state_json_rejects_corrupt_and_oversized_input(value):
    with pytest.raises(ValueError):
        OperationState.from_json(value)


def test_token_policy_and_algorithm_are_forwarded():
    challenge = m.AuthenticationChallengeResponse.from_dict(
        {"challenge": "challenge", "timestampMs": 1}
    )
    policy = m.AuthorizationPolicy.from_dict({})
    credentials = TokenCredentials(
        "SECRET",
        public_key_id="EC-KEY",
        method="ec",
        ec_output_format="csharp",
        authorization_policy=policy,
    )
    with patch("ksef_client.facade.encrypt_ksef_token", return_value="ENCRYPTED") as encrypt:
        request = auth_payload(challenge, credentials, "Nip", "123", "CERT")
    assert request.authorization_policy is policy
    assert request.public_key_id == "EC-KEY"
    assert encrypt.call_args.kwargs["method"] == "ec"
    assert encrypt.call_args.kwargs["ec_output_format"] == "csharp"
    assert "SECRET" not in repr(credentials)
    with pytest.raises(ValueError, match="encryption method"):
        TokenCredentials("SECRET", method="invalid")


def test_xades_policy_and_schema_version_are_forwarded():
    challenge = m.AuthenticationChallengeResponse.from_dict({"challenge": "c", "timestampMs": 1})
    credentials = XadesCredentials(
        XadesKeyPair("CERT", "KEY"),
        authorization_policy_xml="<AuthorizationPolicy/>",
        auth_request_schema_version="2.0",
    )
    with patch("ksef_client.facade.sign_xades_enveloped", return_value="SIGNED") as sign:
        assert auth_payload(challenge, credentials, "Nip", "123") == "SIGNED"
    xml = sign.call_args.args[0]
    assert "<AuthorizationPolicy/>" in xml
    assert "http://ksef.mf.gov.pl/auth/token/2.0" in xml


def test_certificate_selection_respects_algorithm_and_key_identifier():
    now = datetime.now(timezone.utc)

    def descriptor(cert, key, date):
        return m.PublicKeyCertificate(
            certificate=cert.certificate_pem,
            certificate_id=key,
            public_key_id=key,
            usage=[m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION],
            valid_from=date.isoformat(),
            valid_to=(now + timedelta(days=1)).isoformat(),
        )

    rsa_cert = descriptor(generate_rsa_cert(), "RSA", now - timedelta(days=2))
    ec_cert = descriptor(generate_ec_cert(), "EC", now - timedelta(days=1))
    usage = m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION
    assert _select_public_key_certificate([rsa_cert, ec_cert], usage, algorithm="rsa") is rsa_cert
    assert _select_public_key_certificate([rsa_cert, ec_cert], usage, algorithm="ec") is ec_cert
    assert (
        _select_public_key_certificate([rsa_cert, ec_cert], usage, public_key_id="RSA") is rsa_cert
    )
    with pytest.raises(ValueError):
        _select_public_key_certificate([rsa_cert], usage, algorithm="invalid")
    with pytest.raises(ValueError):
        _select_public_key_certificate([rsa_cert], usage, algorithm="ec")


def test_hwm_wait_requires_the_specific_submission(monkeypatch):
    client = SimpleNamespace(
        context_key="Nip:123",
        api=SimpleNamespace(
            invoices=SimpleNamespace(
                search_invoice_metadata=Mock(
                    side_effect=[
                        [SimpleNamespace(ksef_number="OTHER")],
                        [SimpleNamespace(ksef_number="EXPECTED")],
                    ]
                )
            )
        ),
    )
    waits: list[float] = []
    monkeypatch.setattr("tests.test_e2e_facade.wait_seconds", waits.append)
    _wait_for_invoice_at_hwm(client, Mock(), "EXPECTED", poll_interval=1)
    assert waits == [1]


def test_generator_does_not_require_ruff_and_offloads_auth_helpers():
    import ast

    from tools.generate_async_facade import Convert, generate

    generated = ast.parse(generate())
    calls = [node for node in ast.walk(generated) if isinstance(node, ast.Call)]
    assert any(
        ast.unparse(node.func) == "asyncio.to_thread"
        and ast.unparse(node.args[0]) == "auth_payload"
        for node in calls
    )
    transformed = ast.fix_missing_locations(
        Convert().visit(
            ast.parse("""
def begin_auth():
    differently_named = auth_payload(a, b, c, d)
""")
        )
    )
    assert "await asyncio.to_thread(auth_payload, a, b, c, d)" in ast.unparse(transformed)
    with pytest.raises(ValueError, match="Unmapped asynchronous I/O"):
        Convert().visit(
            ast.parse("""
def newly_added_method(self):
    return self.owner.api.invoices.get_export_status("REF")
""")
        )


@pytest.mark.parametrize("asynchronous", [False, True])
def test_facade_refresh_margin_and_callback_work_through_real_token_transport(asynchronous):
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=120)).isoformat()
    result = AuthResult(
        "AUTH",
        "AUTHENTICATION",
        m.AuthenticationTokensResponse(
            access_token=m.TokenInfo("OLD", expiry),
            refresh_token=m.TokenInfo("REFRESH", "2099-01-01T00:00:00Z"),
        ),
    )
    notifications: list[str] = []
    headers: list[str] = []

    def serve(request):
        headers.append(request.headers["Authorization"])
        if request.url.path.endswith("/auth/token/refresh"):
            return httpx.Response(
                200, json={"accessToken": {"token": "NEW", "validUntil": "2099-01-01T00:00:00Z"}}
            )
        return httpx.Response(200, json={})

    options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
    if asynchronous:

        async def callback(info):
            notifications.append(info.token)

        async def run():
            client = AsyncKsef.from_auth_result(
                options,
                result,
                context_key="Nip:123",
                refresh_margin_seconds=180,
                on_refresh=callback,
            )
            await client.api.http_client._client.aclose()
            client.api.http_client._client = httpx.AsyncClient(transport=httpx.MockTransport(serve))
            async with client:
                await client.api.http_client.request("GET", "/limits/context")

        asyncio.run(run())
    else:
        with Ksef.from_auth_result(
            options,
            result,
            context_key="Nip:123",
            refresh_margin_seconds=180,
            on_refresh=lambda info: notifications.append(info.token),
        ) as client:
            client.api.http_client._client.close()
            client.api.http_client._client = httpx.Client(transport=httpx.MockTransport(serve))
            client.api.http_client.request("GET", "/limits/context")
    assert notifications == ["NEW"]
    assert headers == ["Bearer REFRESH", "Bearer NEW"]
