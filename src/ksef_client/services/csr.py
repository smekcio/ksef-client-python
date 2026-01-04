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


def _build_subject(info: dict[str, Any]) -> x509.Name:
    attributes = []
    if info.get("commonName"):
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, info["commonName"]))
    if info.get("organizationName"):
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, info["organizationName"]))
    if info.get("countryName"):
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, info["countryName"]))
    if info.get("organizationIdentifier"):
        attributes.append(
            x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER, info["organizationIdentifier"])
        )
    if info.get("serialNumber"):
        attributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, info["serialNumber"]))
    if info.get("uniqueIdentifier"):
        attributes.append(
            x509.NameAttribute(NameOID.X500_UNIQUE_IDENTIFIER, info["uniqueIdentifier"])
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
