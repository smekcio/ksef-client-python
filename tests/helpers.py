from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Generic, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

PrivateKeyT = TypeVar(
    "PrivateKeyT",
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
)


@dataclass(frozen=True)
class GeneratedCert(Generic[PrivateKeyT]):
    private_key: PrivateKeyT
    certificate: x509.Certificate
    private_key_pem: str
    certificate_pem: str
    certificate_der_b64: str


def _self_signed_cert(
    private_key: PrivateKeyT,
) -> x509.Certificate:
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KSeF"),
        ]
    )
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )


def _serialize_private_key(
    private_key: PrivateKeyT,
) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _serialize_cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def generate_rsa_cert() -> GeneratedCert[rsa.RSAPrivateKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _self_signed_cert(private_key)
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return GeneratedCert(
        private_key=private_key,
        certificate=cert,
        private_key_pem=_serialize_private_key(private_key),
        certificate_pem=_serialize_cert_pem(cert),
        certificate_der_b64=base64.b64encode(cert_der).decode("ascii"),
    )


def generate_ec_cert() -> GeneratedCert[ec.EllipticCurvePrivateKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _self_signed_cert(private_key)
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return GeneratedCert(
        private_key=private_key,
        certificate=cert,
        private_key_pem=_serialize_private_key(private_key),
        certificate_pem=_serialize_cert_pem(cert),
        certificate_der_b64=base64.b64encode(cert_der).decode("ascii"),
    )


def generate_ed25519_key_pem() -> str:
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
