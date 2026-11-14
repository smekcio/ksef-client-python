from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ksef_client import KsefClientOptions, KsefEnvironment
from ksef_client._offline_invoice_state import OfflineInvoiceProgress, offline_invoice_hash
from ksef_client._offline_verification import build_offline_verification_links
from ksef_client.exceptions import KsefDocumentValidationError
from ksef_client.services.xades import XadesKeyPair
from tests.test_e2e_token_flows import _build_invoice_xml

SELLER = "5265877635"


def signer(*, expired=False, auth=False, mismatch=False):
    private = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "offline-test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(0x01F20A5D352AE590)
        .not_valid_before(now - timedelta(days=7))
        .not_valid_after(now + timedelta(days=-1 if expired else 1))
        .add_extension(
            x509.KeyUsage(auth, not auth, False, False, False, False, False, False, False),
            critical=True,
        )
        .sign(private, hashes.SHA256())
    )
    if mismatch:
        private = ec.generate_private_key(ec.SECP256R1())
    return XadesKeyPair(
        cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
    )


def links(key_pair):
    xml = _build_invoice_xml(seller_nip=SELLER, environment_name="offline-qr")
    return build_offline_verification_links(
        KsefClientOptions(base_url=KsefEnvironment.TEST.value),
        f"Nip:{SELLER}",
        OfflineInvoiceProgress(offline_invoice_hash(xml)),
        xml,
        key_pair,
    )


def test_offline_verification_uses_exact_xml_identity_and_correct_labels():
    result = links(signer())
    invoice = urlsplit(result.invoice_url)
    certificate = urlsplit(result.certificate_url)
    assert invoice.hostname == certificate.hostname == "qr-test.ksef.mf.gov.pl"
    _, _, seller, _, digest = invoice.path.split("/")
    assert seller == SELLER
    assert f"/Nip/{SELLER}/{SELLER}/01F20A5D352AE590/{digest}/" in certificate.path
    assert result.invoice_label == "OFFLINE"
    assert result.certificate_label == "CERTYFIKAT"
    assert SELLER not in repr(result)


@pytest.mark.parametrize("problem", ["expired", "auth", "mismatch"])
def test_rejects_unsuitable_offline_certificates(problem):
    with pytest.raises(KsefDocumentValidationError, match="offline certificate"):
        links(signer(**{problem: True}))
