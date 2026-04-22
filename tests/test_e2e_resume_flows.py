from __future__ import annotations

import time
from contextlib import suppress

import pytest

from ksef_client import KsefClient, KsefClientOptions
from ksef_client import models as m
from ksef_client.services import BatchSessionWorkflow, OnlineSessionWorkflow
from ksef_client.services.sessions import BatchSessionState, OnlineSessionState
from ksef_client.utils.zip_utils import build_zip
from tests.test_e2e_token_flows import (
    FORM_CODE,
    E2EConfig,
    _authenticate_access_token,
    _build_invoice_xml,
    _ensure_e2e_enabled,
    _env_float,
    _env_int,
    _load_demo_token_config,
    _load_test_token_config,
    _poll_for_ksef_number,
    _poll_for_upo,
    _select_certificate,
    _with_rate_limit_retry,
)

pytestmark = pytest.mark.e2e


def _poll_for_session_completion(
    client: KsefClient,
    *,
    session_reference_number: str,
    access_token: str,
    require_upo_reference: bool = False,
) -> m.SessionStatusResponse:
    max_attempts = _env_int("KSEF_E2E_SESSION_MAX_ATTEMPTS", 90)
    poll_interval = _env_float("KSEF_E2E_POLL_INTERVAL_SECONDS", 2.0)

    for _ in range(max_attempts):
        status = _with_rate_limit_retry(
            lambda: client.sessions.get_session_status(
                session_reference_number,
                access_token=access_token,
            )
        )
        code = int(status.status.code)
        if code == 200 and (not require_upo_reference or _extract_upo_reference(status)):
            return status
        if code not in {100, 150}:
            raise AssertionError(f"Session processing failed with status code {code}.")
        time.sleep(poll_interval)
    raise TimeoutError("Session processing did not complete within max_attempts.")


def _extract_upo_reference(status: m.SessionStatusResponse) -> str | None:
    upo = getattr(status, "upo", None)
    if upo is None:
        return None
    pages = getattr(upo, "pages", None)
    if not pages:
        return None
    reference_number = getattr(pages[0], "reference_number", None)
    if isinstance(reference_number, str) and reference_number:
        return reference_number
    return None


def _build_batch_zip(*, seller_nip: str, environment_name: str) -> bytes:
    invoice_xml = _build_invoice_xml(seller_nip=seller_nip, environment_name=environment_name)
    return build_zip({"invoice-1.xml": invoice_xml})


def _run_online_resume_flow(config: E2EConfig) -> None:
    if config.context_type.lower() != "nip":
        raise RuntimeError("This E2E scenario requires context_type='nip'.")

    options = KsefClientOptions(base_url=config.base_url)
    access_token: str | None = None
    session_state: OnlineSessionState | None = None

    with KsefClient(options) as open_client:
        certs = _with_rate_limit_retry(lambda: open_client.security.get_public_key_certificates())
        token_cert = _select_certificate(certs, "KsefTokenEncryption")
        symmetric_cert = _select_certificate(certs, "SymmetricKeyEncryption")
        access_token = _authenticate_access_token(
            open_client,
            config=config,
            token_cert=token_cert,
        )

        session = _with_rate_limit_retry(
            lambda: OnlineSessionWorkflow(open_client.sessions).open_session(
                form_code=FORM_CODE,
                public_certificate=symmetric_cert,
                access_token=access_token,
            )
        )
        session_state = OnlineSessionState.from_json(session.get_state().to_json())

    assert access_token, "Authentication did not return access token."
    assert session_state is not None, "Online session state was not created."
    assert access_token not in session_state.to_json()

    with KsefClient(options) as resumed_client:
        resumed = OnlineSessionWorkflow(resumed_client.sessions).resume_session(
            session_state,
            access_token=access_token,
        )
        try:
            send_result = _with_rate_limit_retry(
                lambda: resumed.send_invoice(
                    _build_invoice_xml(
                        seller_nip=config.context_value,
                        environment_name=f"{config.name}-resume",
                    ),
                    access_token=access_token,
                )
            )
            invoice_reference_number = send_result.reference_number
            assert isinstance(invoice_reference_number, str) and invoice_reference_number, (
                "Missing invoice reference number after resumed send."
            )

            invoice_status = _with_rate_limit_retry(
                lambda: resumed.get_invoice_status(
                    invoice_reference_number,
                    access_token=access_token,
                )
            )
            assert int(invoice_status.status.code) in {100, 150, 200}

            ksef_number = _poll_for_ksef_number(
                resumed_client,
                resumed.session_reference_number,
                invoice_reference_number,
                access_token,
            )
            upo_bytes = _poll_for_upo(
                lambda: resumed.get_invoice_upo_by_ksef(
                    ksef_number,
                    access_token=access_token,
                )
            )
            assert upo_bytes, "Received empty invoice UPO after resumed online session."

            session_invoices = _with_rate_limit_retry(
                lambda: resumed.list_invoices(page_size=20, access_token=access_token)
            )
            assert any(
                invoice.reference_number == invoice_reference_number
                for invoice in session_invoices.invoices
            ), "Resumed online session did not list the sent invoice."
        finally:
            with suppress(Exception):
                _with_rate_limit_retry(lambda: resumed.close(access_token=access_token))


def _run_batch_resume_flow(config: E2EConfig) -> None:
    if config.context_type.lower() != "nip":
        raise RuntimeError("This E2E scenario requires context_type='nip'.")

    options = KsefClientOptions(base_url=config.base_url)
    access_token: str | None = None
    session_state: BatchSessionState | None = None
    batch_zip = _build_batch_zip(
        seller_nip=config.context_value,
        environment_name=f"{config.name}-batch-resume",
    )

    with KsefClient(options) as open_client:
        certs = _with_rate_limit_retry(lambda: open_client.security.get_public_key_certificates())
        token_cert = _select_certificate(certs, "KsefTokenEncryption")
        symmetric_cert = _select_certificate(certs, "SymmetricKeyEncryption")
        access_token = _authenticate_access_token(
            open_client,
            config=config,
            token_cert=token_cert,
        )

        session = _with_rate_limit_retry(
            lambda: BatchSessionWorkflow(
                open_client.sessions,
                open_client.http_client,
            ).open_session(
                form_code=FORM_CODE,
                zip_bytes=batch_zip,
                public_certificate=symmetric_cert,
                access_token=access_token,
            )
        )
        session_state = BatchSessionState.from_json(session.get_state().to_json())

    assert access_token, "Authentication did not return access token."
    assert session_state is not None, "Batch session state was not created."
    assert access_token not in session_state.to_json()

    with KsefClient(options) as resumed_client:
        resumed = BatchSessionWorkflow(
            resumed_client.sessions,
            resumed_client.http_client,
        ).resume_session(
            session_state,
            zip_bytes=batch_zip,
            access_token=access_token,
        )
        uploaded_ordinals: list[int] = []

        try:
            resumed.upload_parts(
                parallelism=1,
                progress_callback=uploaded_ordinals.append,
            )
            assert uploaded_ordinals, "Batch resume did not upload any parts."

            _with_rate_limit_retry(lambda: resumed.close(access_token=access_token))

            session_status = _poll_for_session_completion(
                resumed_client,
                session_reference_number=resumed.session_reference_number,
                access_token=access_token,
                require_upo_reference=True,
            )
            assert int(session_status.status.code) == 200

            upo_reference_number = _extract_upo_reference(session_status)
            assert upo_reference_number, "Batch session completion did not expose UPO reference."

            upo_bytes = _poll_for_upo(
                lambda: resumed.get_upo(
                    upo_reference_number,
                    access_token=access_token,
                )
            )
            assert upo_bytes, "Received empty batch UPO after resumed batch session."

            session_invoices = _with_rate_limit_retry(
                lambda: resumed.list_invoices(page_size=20, access_token=access_token)
            )
            failed_invoices = _with_rate_limit_retry(
                lambda: resumed.list_failed_invoices(page_size=20, access_token=access_token)
            )
            assert session_invoices.invoices or failed_invoices.invoices, (
                "Resumed batch session did not report any processed invoices."
            )
        finally:
            with suppress(Exception):
                _with_rate_limit_retry(lambda: resumed.close(access_token=access_token))


def test_e2e_test_environment_online_resume_token() -> None:
    _ensure_e2e_enabled()
    _run_online_resume_flow(_load_test_token_config())


def test_e2e_test_environment_batch_resume_token() -> None:
    _ensure_e2e_enabled()
    _run_batch_resume_flow(_load_test_token_config())


def test_e2e_demo_environment_online_resume_token() -> None:
    _ensure_e2e_enabled()
    _run_online_resume_flow(_load_demo_token_config())


def test_e2e_demo_environment_batch_resume_token() -> None:
    _ensure_e2e_enabled()
    _run_batch_resume_flow(_load_demo_token_config())
