from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class CsrResult:
    csr_base64: str
    private_key_base64: str


#: OID atrybutów DN wymaganych przez KSeF dla osoby fizycznej:
#: `2.5.4.4` (surname) i `2.5.4.42` (givenName). Dokumentacja MF
#: („certyfikaty-KSeF", rozdz. 2-3) mówi, że system zwraca komplet atrybutów DN,
#: które **muszą** zostać użyte przy budowie CSR — modyfikacja danych powoduje
#: odrzucenie wniosku (kod błędu 25003).
_SURNAME_OID = x509.ObjectIdentifier("2.5.4.4")
_GIVEN_NAME_OID = x509.ObjectIdentifier("2.5.4.42")


def _subject_value(info: dict[str, Any], *names: str) -> Any:
    """Pierwsza niepusta wartość spośród podanych nazw pól.

    Model SDK (`CertificateEnrollmentDataResponse`) używa nazw w stylu
    snake_case (`given_name`, `surname`, `organization_name`), a dokumentacja MF
    i przykłady — camelCase. Wcześniej akceptowany był wyłącznie camelCase, więc
    wołający, który przekazał dokładnie pole z modelu (`given_name`), dostawał CSR
    BEZ `givenName` i bez żadnego sygnału — a KSeF odrzuca taki wniosek (25003).
    """
    for name in names:
        value = info.get(name)
        if value:
            return value
    return None


def _build_subject(info: dict[str, Any]) -> x509.Name:
    attributes = []
    common_name = _subject_value(info, "commonName", "common_name")
    if common_name:
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    given_name = _subject_value(info, "givenName", "given_name")
    if given_name:
        attributes.append(x509.NameAttribute(_GIVEN_NAME_OID, given_name))
    surname = _subject_value(info, "surname", "lastName", "last_name")
    if surname:
        attributes.append(x509.NameAttribute(_SURNAME_OID, surname))
    organization_name = _subject_value(info, "organizationName", "organization_name")
    if organization_name:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name))
    country_name = _subject_value(info, "countryName", "country_name")
    if country_name:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country_name))
    organization_identifier = _subject_value(
        info, "organizationIdentifier", "organization_identifier"
    )
    if organization_identifier:
        attributes.append(
            x509.NameAttribute(x509.ObjectIdentifier("2.5.4.97"), organization_identifier)
        )
    serial_number = _subject_value(info, "serialNumber", "serial_number")
    if serial_number:
        attributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number))
    unique_identifier = _subject_value(info, "uniqueIdentifier", "unique_identifier")
    if unique_identifier:
        attributes.append(
            x509.NameAttribute(NameOID.X500_UNIQUE_IDENTIFIER, unique_identifier)
        )
    return x509.Name(attributes)


def generate_csr_rsa(info: dict[str, Any], key_size: int = 2048) -> CsrResult:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = _build_subject(info)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    csr_bytes = csr.public_bytes(serialization.Encoding.DER)
    key_bytes = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return CsrResult(
        csr_base64=base64.b64encode(csr_bytes).decode("ascii"),
        private_key_base64=base64.b64encode(key_bytes).decode("ascii"),
    )


def generate_csr_ec(info: dict[str, Any]) -> CsrResult:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = _build_subject(info)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    csr_bytes = csr.public_bytes(serialization.Encoding.DER)
    key_bytes = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return CsrResult(
        csr_base64=base64.b64encode(csr_bytes).decode("ascii"),
        private_key_base64=base64.b64encode(key_bytes).decode("ascii"),
    )
