from __future__ import annotations

import base64
import os
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key

from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client.exceptions import KsefHttpError, KsefRateLimitError
from ksef_client.services import AuthCoordinator, OnlineSessionWorkflow

pytestmark = pytest.mark.e2e

FORM_CODE = {"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"}
ENABLED_VALUES = {"1", "true", "yes"}
AUTH_MODE_TOKEN = "token"
AUTH_MODE_XADES = "xades"
T = TypeVar("T")


@dataclass(frozen=True)
class E2EConfig:
    name: str
    base_url: str
    context_type: str
    context_value: str
    subject_type: str
    auth_mode: str
    token: str | None = None
    certificate_pem: str | None = None
    private_key_pem: str | None = None
    subject_identifier_type: str | None = None


def _optional_any(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def _required_any(*names: str) -> str:
    value = _optional_any(*names)
    if value:
        return value
    raise RuntimeError(f"Missing env var: {' or '.join(names)}")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    return int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    return float(raw)


def _ensure_e2e_enabled() -> None:
    if os.getenv("KSEF_E2E", "").strip().lower() not in ENABLED_VALUES:
        pytest.skip("Set KSEF_E2E=1 to enable e2e tests.")


def _load_test_token_config() -> E2EConfig:
    return E2EConfig(
        name="test",
        base_url=_optional_any("KSEF_TEST_BASE_URL") or KsefEnvironment.TEST.value,
        context_type=_required_any("KSEF_TEST_CONTEXT_TYPE"),
        context_value=_required_any("KSEF_TEST_CONTEXT_VALUE"),
        subject_type=_optional_any("KSEF_TEST_SUBJECT_TYPE") or "Subject1",
        auth_mode=AUTH_MODE_TOKEN,
        token=_required_any("KSEF_TEST_TOKEN"),
    )


def _load_demo_token_config() -> E2EConfig:
    return E2EConfig(
        name="demo",
        base_url=_optional_any("KSEF_DEMO_BASE_URL", "KSEF_BASE_URL") or KsefEnvironment.DEMO.value,
        context_type=_required_any("KSEF_DEMO_CONTEXT_TYPE", "KSEF_CONTEXT_TYPE"),
        context_value=_required_any("KSEF_DEMO_CONTEXT_VALUE", "KSEF_CONTEXT_VALUE"),
        subject_type=_optional_any("KSEF_DEMO_SUBJECT_TYPE", "KSEF_SUBJECT_TYPE") or "Subject1",
        auth_mode=AUTH_MODE_TOKEN,
        token=_required_any("KSEF_DEMO_TOKEN", "KSEF_TOKEN"),
    )


def _select_certificate(certs: list[dict[str, Any]], usage_name: str) -> str:
    for cert in certs:
        usage = cert.get("usage") or []
        if usage_name in usage and cert.get("certificate"):
            return str(cert["certificate"])
    raise RuntimeError(f"Missing public cert usage: {usage_name}")


def _with_rate_limit_retry(call: Callable[[], T]) -> T:
    retries = _env_int("KSEF_E2E_RATE_LIMIT_RETRIES", 3)
    delay = _env_float("KSEF_E2E_RATE_LIMIT_SLEEP_SECONDS", 5.0)
    for attempt in range(retries):
        try:
            return call()
        except KsefRateLimitError:
            if attempt == retries - 1:
                raise
            time.sleep(delay)
    raise RuntimeError("Rate limit retry loop terminated unexpectedly.")


def _poll_for_ksef_number(
    client: KsefClient,
    session_reference_number: str,
    invoice_reference_number: str,
    access_token: str,
) -> str:
    max_attempts = _env_int("KSEF_E2E_INVOICE_MAX_ATTEMPTS", 90)
    poll_interval = _env_float("KSEF_E2E_POLL_INTERVAL_SECONDS", 2.0)
    for _ in range(max_attempts):
        status = _with_rate_limit_retry(
            lambda: client.sessions.get_session_invoice_status(
                session_reference_number,
                invoice_reference_number,
                access_token=access_token,
            )
        )
        code = int((status.get("status") or {}).get("code", 0))
        if code == 200:
            ksef_number = status.get("ksefNumber")
            if isinstance(ksef_number, str) and ksef_number:
                return ksef_number
            raise AssertionError("Invoice accepted but ksefNumber is missing.")
        if code not in {100, 150}:
            raise AssertionError(f"Invoice processing failed with status code {code}.")
        time.sleep(poll_interval)
    raise TimeoutError("Invoice processing did not complete within max_attempts.")


def _poll_for_upo(fetch: Callable[[], bytes]) -> bytes:
    max_attempts = _env_int("KSEF_E2E_UPO_MAX_ATTEMPTS", 45)
    poll_interval = _env_float("KSEF_E2E_POLL_INTERVAL_SECONDS", 2.0)
    transient_codes = {404, 409, 425}

    for _ in range(max_attempts):
        try:
            upo = _with_rate_limit_retry(fetch)
            if upo:
                return upo
        except KsefHttpError as error:
            if error.status_code not in transient_codes:
                raise
        time.sleep(poll_interval)
    raise TimeoutError("Invoice UPO was not available within max_attempts.")


def _extract_ksef_number(invoice: dict[str, Any]) -> str | None:
    value = invoice.get("ksefNumber")
    if isinstance(value, str) and value:
        return value
    return None


def _first_ksef_number(invoices: list[dict[str, Any]]) -> str:
    for invoice in invoices:
        ksef_number = _extract_ksef_number(invoice)
        if ksef_number:
            return ksef_number
    raise AssertionError("No invoice with ksefNumber found in metadata response.")


def _normalize_pem(raw: str) -> str:
    value = raw.strip()
    if "\\n" in value and "\n" not in value:
        value = value.replace("\\n", "\n")
    if not value.endswith("\n"):
        value += "\n"
    return value


def _decode_b64(value: str) -> bytes:
    compact = "".join(value.split())
    return base64.b64decode(compact.encode("ascii"), validate=False)


def _required_certificate_pem(
    *,
    plain_names: tuple[str, ...],
    b64_names: tuple[str, ...],
) -> str:
    plain_value = _optional_any(*plain_names)
    if plain_value:
        normalized_plain = _normalize_pem(plain_value)
        plain_bytes = normalized_plain.encode("utf-8")
        if b"BEGIN CERTIFICATE" in plain_bytes:
            return normalized_plain
        try:
            cert = x509.load_der_x509_certificate(plain_bytes)
        except ValueError:
            return normalized_plain
        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    b64_value = _optional_any(*b64_names)
    if b64_value:
        decoded = _decode_b64(b64_value)
        if b"BEGIN CERTIFICATE" in decoded:
            return _normalize_pem(decoded.decode("utf-8"))
        try:
            cert = x509.load_der_x509_certificate(decoded)
        except ValueError as exc:
            raise RuntimeError("Unable to parse XAdES certificate from provided secrets.") from exc
        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    raise RuntimeError(
        "Missing certificate value in env vars: "
        + ", ".join((*plain_names, *b64_names))
    )


def _required_private_key_pem(
    *,
    plain_names: tuple[str, ...],
    b64_names: tuple[str, ...],
    private_key_password: str | None,
    password_secret_names: tuple[str, ...],
) -> str:
    plain_value = _optional_any(*plain_names)
    if plain_value:
        key_bytes = _normalize_pem(plain_value).encode("utf-8")
    else:
        b64_value = _optional_any(*b64_names)
        if not b64_value:
            raise RuntimeError(
                "Missing PEM value in env vars: "
                + ", ".join((*plain_names, *b64_names))
            )
        decoded = _decode_b64(b64_value)
        if b"BEGIN" in decoded:
            key_bytes = _normalize_pem(decoded.decode("utf-8")).encode("utf-8")
        else:
            key_bytes = decoded

    password_bytes = None if private_key_password is None else private_key_password.encode("utf-8")
    try:
        if b"BEGIN" in key_bytes:
            key = load_pem_private_key(key_bytes, password=password_bytes)
        else:
            key = load_der_private_key(key_bytes, password=password_bytes)
    except TypeError as exc:
        raise RuntimeError(
            "Invalid private key password configuration. "
            f"If key is encrypted, set one of: {', '.join(password_secret_names)}."
        ) from exc
    except ValueError as exc:
        password_hint = (
            f"Check secret value in: {', '.join(password_secret_names)}."
            if private_key_password
            else f"If key is encrypted, set one of: {', '.join(password_secret_names)}."
        )
        raise RuntimeError(f"Unable to load XAdES private key. {password_hint}") from exc

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _load_test_xades_config() -> E2EConfig:
    key_password = _optional_any(
        "KSEF_TEST_XADES_PRIVATE_KEY_PASSWORD",
        "KSEF_XADES_PRIVATE_KEY_PASSWORD",
    )
    return E2EConfig(
        name="test",
        base_url=_optional_any("KSEF_TEST_BASE_URL") or KsefEnvironment.TEST.value,
        context_type=_required_any("KSEF_TEST_CONTEXT_TYPE"),
        context_value=_required_any("KSEF_TEST_CONTEXT_VALUE"),
        subject_type=_optional_any("KSEF_TEST_SUBJECT_TYPE") or "Subject1",
        auth_mode=AUTH_MODE_XADES,
        certificate_pem=_required_certificate_pem(
            plain_names=("KSEF_TEST_XADES_CERT_CRT", "KSEF_TEST_XADES_CERT_PEM"),
            b64_names=("KSEF_TEST_XADES_CERT_CRT_B64", "KSEF_TEST_XADES_CERT_PEM_B64"),
        ),
        private_key_pem=_required_private_key_pem(
            plain_names=("KSEF_TEST_XADES_PRIVATE_KEY_PEM",),
            b64_names=("KSEF_TEST_XADES_PRIVATE_KEY_PEM_B64",),
            private_key_password=key_password,
            password_secret_names=(
                "KSEF_TEST_XADES_PRIVATE_KEY_PASSWORD",
                "KSEF_XADES_PRIVATE_KEY_PASSWORD",
            ),
        ),
        subject_identifier_type=(
            _optional_any("KSEF_TEST_XADES_SUBJECT_IDENTIFIER_TYPE") or "certificateSubject"
        ),
    )


def _load_demo_xades_config() -> E2EConfig:
    key_password = _optional_any(
        "KSEF_DEMO_XADES_PRIVATE_KEY_PASSWORD",
        "KSEF_XADES_PRIVATE_KEY_PASSWORD",
    )
    return E2EConfig(
        name="demo",
        base_url=_optional_any("KSEF_DEMO_BASE_URL", "KSEF_BASE_URL") or KsefEnvironment.DEMO.value,
        context_type=_required_any("KSEF_DEMO_CONTEXT_TYPE", "KSEF_CONTEXT_TYPE"),
        context_value=_required_any("KSEF_DEMO_CONTEXT_VALUE", "KSEF_CONTEXT_VALUE"),
        subject_type=_optional_any("KSEF_DEMO_SUBJECT_TYPE", "KSEF_SUBJECT_TYPE") or "Subject1",
        auth_mode=AUTH_MODE_XADES,
        certificate_pem=_required_certificate_pem(
            plain_names=("KSEF_DEMO_XADES_CERT_CRT", "KSEF_DEMO_XADES_CERT_PEM"),
            b64_names=("KSEF_DEMO_XADES_CERT_CRT_B64", "KSEF_DEMO_XADES_CERT_PEM_B64"),
        ),
        private_key_pem=_required_private_key_pem(
            plain_names=("KSEF_DEMO_XADES_PRIVATE_KEY_PEM",),
            b64_names=("KSEF_DEMO_XADES_PRIVATE_KEY_PEM_B64",),
            private_key_password=key_password,
            password_secret_names=(
                "KSEF_DEMO_XADES_PRIVATE_KEY_PASSWORD",
                "KSEF_XADES_PRIVATE_KEY_PASSWORD",
            ),
        ),
        subject_identifier_type=(
            _optional_any("KSEF_DEMO_XADES_SUBJECT_IDENTIFIER_TYPE") or "certificateSubject"
        ),
    )


def _utc_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _query_invoice_metadata(
    client: KsefClient,
    *,
    access_token: str,
    subject_type: str,
) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    lookback_days = _env_int("KSEF_E2E_LOOKBACK_DAYS", 30)
    request_payload = {
        "subjectType": subject_type,
        "dateRange": {
            "dateType": "Issue",
            "from": _utc_z(now - timedelta(days=lookback_days)),
            "to": _utc_z(now + timedelta(minutes=10)),
        },
    }
    response = _with_rate_limit_retry(
        lambda: client.invoices.query_invoice_metadata(
            request_payload,
            access_token=access_token,
            page_offset=0,
            page_size=10,
            sort_order="Desc",
        )
    )
    invoices = response.get("invoices") or response.get("invoiceList") or []
    return [invoice for invoice in invoices if isinstance(invoice, dict)]


def _poll_metadata_until_contains(
    client: KsefClient,
    *,
    access_token: str,
    subject_type: str,
    expected_ksef_number: str,
) -> list[dict[str, Any]]:
    max_attempts = _env_int("KSEF_E2E_METADATA_MAX_ATTEMPTS", 45)
    poll_interval = _env_float("KSEF_E2E_POLL_INTERVAL_SECONDS", 2.0)

    for _ in range(max_attempts):
        invoices = _query_invoice_metadata(
            client,
            access_token=access_token,
            subject_type=subject_type,
        )
        if any(_extract_ksef_number(invoice) == expected_ksef_number for invoice in invoices):
            return invoices
        time.sleep(poll_interval)
    raise TimeoutError("Expected sent invoice did not appear in invoice metadata list.")


def _build_invoice_xml(*, seller_nip: str, environment_name: str) -> bytes:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issue_date = now.date().isoformat()
    period_start = now.date().replace(day=1).isoformat()
    payment_due = (now.date() + timedelta(days=14)).isoformat()
    invoice_number = (
        f"E2E/{environment_name.upper()}/{now.strftime('%Y%m%d%H%M%S')}/{uuid.uuid4().hex[:8]}"
    )

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Faktura xmlns="http://crd.gov.pl/wzor/2025/06/25/13775/"
         xmlns:etd="http://crd.gov.pl/xml/schematy/dziedzinowe/mf/2022/01/05/eD/DefinicjeTypy/"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Naglowek>
    <KodFormularza kodSystemowy="FA (3)" wersjaSchemy="1-0E">FA</KodFormularza>
    <WariantFormularza>3</WariantFormularza>
    <DataWytworzeniaFa>{_utc_z(now)}</DataWytworzeniaFa>
    <SystemInfo>pytest</SystemInfo>
  </Naglowek>
  <Podmiot1>
    <DaneIdentyfikacyjne>
      <NIP>{seller_nip}</NIP>
      <Nazwa>Automated seller</Nazwa>
    </DaneIdentyfikacyjne>
    <Adres>
      <KodKraju>PL</KodKraju>
      <AdresL1>ul. Testowa 1</AdresL1>
      <AdresL2>00-001 Warszawa</AdresL2>
    </Adres>
  </Podmiot1>
  <Podmiot2>
    <DaneIdentyfikacyjne>
      <NIP>1111111111</NIP>
      <Nazwa>Automated buyer</Nazwa>
    </DaneIdentyfikacyjne>
    <Adres>
      <KodKraju>PL</KodKraju>
      <AdresL1>ul. Odbiorcy 1</AdresL1>
      <AdresL2>00-002 Warszawa</AdresL2>
    </Adres>
    <DaneKontaktowe>
      <Email>buyer@example.com</Email>
      <Telefon>555777999</Telefon>
    </DaneKontaktowe>
    <NrKlienta>99999999</NrKlienta>
    <JST>2</JST>
    <GV>2</GV>
  </Podmiot2>
  <Fa>
    <KodWaluty>PLN</KodWaluty>
    <P_1>{issue_date}</P_1>
    <P_1M>miejscowosc</P_1M>
    <P_2>{invoice_number}</P_2>
    <OkresFa>
      <P_6_Od>{period_start}</P_6_Od>
      <P_6_Do>{payment_due}</P_6_Do>
    </OkresFa>
    <P_13_1>1.00</P_13_1>
    <P_14_1>0.23</P_14_1>
    <P_15>1.23</P_15>
    <Adnotacje>
      <P_16>2</P_16>
      <P_17>2</P_17>
      <P_18>2</P_18>
      <P_18A>2</P_18A>
      <Zwolnienie>
        <P_19N>1</P_19N>
      </Zwolnienie>
      <NoweSrodkiTransportu>
        <P_22N>1</P_22N>
      </NoweSrodkiTransportu>
      <P_23>2</P_23>
      <PMarzy>
        <P_PMarzyN>1</P_PMarzyN>
      </PMarzy>
    </Adnotacje>
    <RodzajFaktury>VAT</RodzajFaktury>
    <FaWiersz>
      <NrWierszaFa>1</NrWierszaFa>
      <P_7>Pozycja testowa</P_7>
      <P_8A>szt</P_8A>
      <P_8B>1.00</P_8B>
      <P_9A>1.00</P_9A>
      <P_11>1.00</P_11>
      <P_12>23</P_12>
    </FaWiersz>
    <Rozliczenie>
      <Obciazenia>
        <Kwota>0.00</Kwota>
        <Powod>brak</Powod>
      </Obciazenia>
      <SumaObciazen>0.00</SumaObciazen>
      <Odliczenia>
        <Kwota>0.00</Kwota>
        <Powod>brak</Powod>
      </Odliczenia>
      <SumaOdliczen>0.00</SumaOdliczen>
      <DoZaplaty>1.23</DoZaplaty>
    </Rozliczenie>
    <Platnosc>
      <TerminPlatnosci>
        <Termin>{payment_due}</Termin>
      </TerminPlatnosci>
      <FormaPlatnosci>6</FormaPlatnosci>
      <RachunekBankowy>
        <NrRB>73111111111111111111111111</NrRB>
        <NazwaBanku>Bank testowy</NazwaBanku>
        <OpisRachunku>PLN</OpisRachunku>
      </RachunekBankowy>
    </Platnosc>
  </Fa>
</Faktura>
"""
    return xml.encode("utf-8")


def _authenticate_access_token(
    client: KsefClient,
    *,
    config: E2EConfig,
    token_cert: str,
) -> str:
    coordinator = AuthCoordinator(client.auth)
    poll_interval_seconds = _env_float("KSEF_E2E_POLL_INTERVAL_SECONDS", 2.0)
    max_attempts = _env_int("KSEF_E2E_AUTH_MAX_ATTEMPTS", 90)

    if config.auth_mode == AUTH_MODE_TOKEN:
        if not config.token:
            raise RuntimeError("Missing token for token auth mode.")
        result = coordinator.authenticate_with_ksef_token(
            token=config.token,
            public_certificate=token_cert,
            context_identifier_type=config.context_type,
            context_identifier_value=config.context_value,
            max_attempts=max_attempts,
            poll_interval_seconds=poll_interval_seconds,
        )
        return result.tokens.access_token.token

    if config.auth_mode == AUTH_MODE_XADES:
        if not config.certificate_pem or not config.private_key_pem:
            raise RuntimeError("Missing certificate/private key for XAdES auth mode.")
        result = coordinator.authenticate_with_xades(
            context_identifier_type=config.context_type,
            context_identifier_value=config.context_value,
            subject_identifier_type=config.subject_identifier_type or "certificateSubject",
            certificate_pem=config.certificate_pem,
            private_key_pem=config.private_key_pem,
            max_attempts=max_attempts,
            poll_interval_seconds=poll_interval_seconds,
        )
        return result.tokens.access_token.token

    raise RuntimeError(f"Unknown auth mode: {config.auth_mode}")


def _run_full_e2e_flow(config: E2EConfig) -> None:
    if config.context_type.lower() != "nip":
        raise RuntimeError("This E2E scenario requires context_type='nip'.")

    options = KsefClientOptions(base_url=config.base_url)
    with KsefClient(options) as client:
        certs = _with_rate_limit_retry(lambda: client.security.get_public_key_certificates())
        token_cert = _select_certificate(certs, "KsefTokenEncryption")
        symmetric_cert = _select_certificate(certs, "SymmetricKeyEncryption")

        access_token = _authenticate_access_token(
            client,
            config=config,
            token_cert=token_cert,
        )
        assert access_token, "Authentication did not return access token."

        workflow = OnlineSessionWorkflow(client.sessions)
        session = workflow.open_session(
            form_code=FORM_CODE,
            public_certificate=symmetric_cert,
            access_token=access_token,
        )

        try:
            send_result = _with_rate_limit_retry(
                lambda: workflow.send_invoice(
                    session_reference_number=session.session_reference_number,
                    invoice_xml=_build_invoice_xml(
                        seller_nip=config.context_value,
                        environment_name=config.name,
                    ),
                    encryption_data=session.encryption_data,
                    access_token=access_token,
                )
            )
            invoice_reference_number = send_result.get("referenceNumber")
            assert isinstance(invoice_reference_number, str) and invoice_reference_number, (
                "Missing invoice reference number after send."
            )

            ksef_number = _poll_for_ksef_number(
                client,
                session.session_reference_number,
                invoice_reference_number,
                access_token,
            )

            upo_bytes = _poll_for_upo(
                lambda: client.sessions.get_session_invoice_upo_by_ksef(
                    session.session_reference_number,
                    ksef_number,
                    access_token=access_token,
                )
            )
            assert upo_bytes, "Received empty UPO payload."

            session_invoices = _with_rate_limit_retry(
                lambda: client.sessions.get_session_invoices(
                    session.session_reference_number,
                    access_token=access_token,
                    page_size=20,
                )
            )
            invoices_in_session = session_invoices.get("invoices") or []
            assert any(
                _extract_ksef_number(invoice) == ksef_number
                for invoice in invoices_in_session
                if isinstance(invoice, dict)
            ), "Sent invoice not found in session invoice list."

            metadata_invoices = _poll_metadata_until_contains(
                client,
                access_token=access_token,
                subject_type=config.subject_type,
                expected_ksef_number=ksef_number,
            )
            latest_ksef_number = _first_ksef_number(metadata_invoices)

            latest_invoice = _with_rate_limit_retry(
                lambda: client.invoices.get_invoice_bytes(
                    latest_ksef_number,
                    access_token=access_token,
                )
            )
            assert latest_invoice.content, "Downloaded latest invoice content is empty."
        finally:
            with suppress(Exception):
                workflow.close_session(session.session_reference_number, access_token)


def test_e2e_test_environment_full_flow_token() -> None:
    _ensure_e2e_enabled()
    _run_full_e2e_flow(_load_test_token_config())


def test_e2e_demo_environment_full_flow_token() -> None:
    _ensure_e2e_enabled()
    _run_full_e2e_flow(_load_demo_token_config())


def test_e2e_test_environment_full_flow_xades() -> None:
    _ensure_e2e_enabled()
    _run_full_e2e_flow(_load_test_xades_config())


def test_e2e_demo_environment_full_flow_xades() -> None:
    _ensure_e2e_enabled()
    _run_full_e2e_flow(_load_demo_xades_config())
