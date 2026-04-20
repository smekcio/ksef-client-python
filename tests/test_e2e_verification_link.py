from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from ksef_client.config import KsefClientOptions, KsefEnvironment
from ksef_client.services.verification_link import VerificationLinkService

pytestmark = pytest.mark.e2e

ENABLED_VALUES = {"1", "true", "yes"}
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "verification_link"
SUCCESS_SNIPPETS = (
    "Certyfikat istnieje",
    "Certyfikat jest aktywny",
    "Podpis wystawcy jest prawid",
    "Wystawca posiada uprawnienia do wystawienia faktury",
)


@dataclass(frozen=True)
class VerificationLinkE2ECase:
    name: str
    context_nip: str
    certificate_serial: str
    private_key_path: Path
    private_key_password: str | None = None
    signature_format: str = "p1363"


def _ensure_e2e_enabled() -> None:
    if os.getenv("KSEF_E2E", "").strip().lower() not in ENABLED_VALUES:
        pytest.skip("Set KSEF_E2E=1 to enable e2e tests.")


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value else default


def _load_case(name: str) -> VerificationLinkE2ECase:
    key_name = name.upper()
    defaults = {
        "RSA": VerificationLinkE2ECase(
            name="rsa",
            context_nip="7368335898",
            certificate_serial="01732D26F736E531",
            private_key_path=FIXTURES_DIR / "rsa_offline_private_key.pem",
            signature_format="p1363",
        ),
        "ECDSA": VerificationLinkE2ECase(
            name="ecdsa",
            context_nip="8096529464",
            certificate_serial="01D1732E43B9345E",
            private_key_path=FIXTURES_DIR / "ecdsa_offline_private_key.pem",
            private_key_password="ADadADad12!@adadad",
            signature_format="p1363",
        ),
    }
    base = defaults[key_name]
    return VerificationLinkE2ECase(
        name=base.name,
        context_nip=_env(f"KSEF_QR_E2E_{key_name}_NIP", base.context_nip),
        certificate_serial=_env(
            f"KSEF_QR_E2E_{key_name}_SERIAL",
            base.certificate_serial,
        ),
        private_key_path=Path(
            _env(
                f"KSEF_QR_E2E_{key_name}_KEY_PATH",
                str(base.private_key_path),
            )
        ),
        private_key_password=os.getenv(
            f"KSEF_QR_E2E_{key_name}_KEY_PASSWORD",
            base.private_key_password,
        ),
        signature_format=_env(
            f"KSEF_QR_E2E_{key_name}_SIGNATURE_FORMAT",
            base.signature_format,
        ),
    )


def _invoice_hash_base64() -> str:
    digest = hashlib.sha256(
        b'<?xml version="1.0" encoding="UTF-8"?><offlineInvoice>'
        b"<number>E2E/QR/STATIC</number></offlineInvoice>"
    ).digest()
    return base64.b64encode(digest).decode("ascii")


@pytest.mark.parametrize(
    "case",
    [_load_case("rsa"), _load_case("ecdsa")],
    ids=lambda case: case.name,
)
def test_certificate_verification_link_matches_public_ksef_qr_endpoint(
    case: VerificationLinkE2ECase,
) -> None:
    _ensure_e2e_enabled()
    assert case.private_key_path.exists(), (
        f"Missing private key fixture: {case.private_key_path}"
    )

    service = VerificationLinkService(KsefClientOptions(base_url=KsefEnvironment.TEST.value))
    private_key_pem = case.private_key_path.read_text(encoding="ascii")
    invoice_hash = _invoice_hash_base64()

    url = service.build_certificate_verification_url(
        seller_nip=case.context_nip,
        context_identifier_type="Nip",
        context_identifier_value=case.context_nip,
        certificate_serial=case.certificate_serial,
        invoice_hash=invoice_hash,
        private_key_pem=private_key_pem,
        private_key_password=case.private_key_password,
        signature_format=case.signature_format,
    )

    with httpx.Client(follow_redirects=True, timeout=20.0) as client:
        response = client.get(url)

    assert response.status_code == 200
    for snippet in SUCCESS_SNIPPETS:
        assert snippet in response.text, (
            f"Expected QR verification page to contain {snippet!r} for case {case.name}. "
            f"URL: {url}"
        )
