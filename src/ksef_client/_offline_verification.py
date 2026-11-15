"""Prepare presentation links for stored FA(3) invoices, even without KSeF access."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ._offline_invoice_state import OfflineInvoiceProgress, offline_invoice_hash
from .config import KsefClientOptions
from .documents.fa3.domain import PartyIdentifierKind
from .documents.fa3.parse import FA3ParseError, parse_invoice_xml
from .exceptions import KsefDocumentValidationError
from .services.verification_link import VerificationLinkService
from .services.xades import XadesKeyPair
from .utils.certificate_serial import require_certificate_serial_number


@dataclass(frozen=True)
class OfflineVerificationLinks:
    invoice_url: str = field(repr=False)
    invoice_label: str = field(repr=False)
    certificate_url: str = field(repr=False)
    certificate_label: str = "CERTYFIKAT"


def build_offline_verification_links(
    options: KsefClientOptions,
    context_key: str,
    progress: OfflineInvoiceProgress,
    xml: bytes,
    signer: XadesKeyPair,
) -> OfflineVerificationLinks:
    """Check the key usage, validity, and key binding before generating KOD II."""
    if offline_invoice_hash(xml) != progress.invoice_hash:
        raise KsefDocumentValidationError("Offline XML does not match the recorded hash")
    serial = _validate_signer(signer)
    try:
        invoice = parse_invoice_xml(xml)
        seller = invoice.seller.identifier
        if (
            seller.kind is not PartyIdentifierKind.NIP
            or seller.value is None
            or re.fullmatch(r"[0-9]{10}", seller.value) is None
        ):
            raise ValueError
        context_type, _, context_value = context_key.partition(":")
        links = VerificationLinkService(options)
        invoice_url = links.build_invoice_verification_url(
            seller.value, invoice.issue_date, progress.invoice_hash
        )
        certificate_url = links.build_certificate_verification_url(
            seller_nip=seller.value,
            context_identifier_type=context_type,
            context_identifier_value=context_value,
            certificate_serial=serial,
            invoice_hash=progress.invoice_hash,
            signing_certificate_pem=signer.certificate_pem,
            private_key_pem=signer.private_key_pem,
        )
    except (FA3ParseError, TypeError, ValueError):
        raise KsefDocumentValidationError(
            "Invalid FA(3) or offline signing configuration"
        ) from None
    return OfflineVerificationLinks(
        invoice_url=invoice_url,
        invoice_label=progress.ksef_number or "OFFLINE",
        certificate_url=certificate_url,
    )


def _validate_signer(signer: XadesKeyPair) -> str:
    if not isinstance(signer, XadesKeyPair):
        raise TypeError("Offline signing requires a certificate and private key")
    try:
        certificate = x509.load_pem_x509_certificate(signer.certificate_pem.encode("ascii"))
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        now = datetime.now(timezone.utc)
        if (
            not usage.content_commitment
            or usage.digital_signature
            or not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc
        ):
            raise ValueError
        public_key = certificate.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < 2048:
                raise ValueError
        elif not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise ValueError
        key = serialization.load_pem_private_key(signer.private_key_pem.encode("ascii"), None)
        if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise ValueError
        if key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise ValueError
        return require_certificate_serial_number(format(certificate.serial_number, "016X"))
    except (TypeError, ValueError, x509.ExtensionNotFound):
        raise KsefDocumentValidationError(
            "Invalid, expired or mismatched offline certificate"
        ) from None
