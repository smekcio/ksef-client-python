from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..config import KsefClientOptions
from ..utils.base64url import b64decode, b64url_decode, b64url_encode
from .crypto import load_private_key, sign_path_ecdsa, sign_path_rsa_pss


@dataclass(frozen=True)
class VerificationLinkService:
    options: KsefClientOptions

    def build_invoice_verification_url(
        self, nip: str, issue_date: date | datetime | str, invoice_hash: str
    ) -> str:
        if isinstance(issue_date, (date, datetime)):
            date_str = issue_date.strftime("%d-%m-%Y")
        else:
            date_str = issue_date
        hash_bytes = _decode_base64_or_url(invoice_hash)
        hash_url = b64url_encode(hash_bytes)
        base_url = self.options.resolve_qr_base_url().rstrip("/")
        return f"{base_url}/invoice/{nip}/{date_str}/{hash_url}"

    def build_certificate_verification_url(
        self,
        *,
        seller_nip: str,
        context_identifier_type: str,
        context_identifier_value: str,
        certificate_serial: str,
        invoice_hash: str,
        signing_certificate_pem: str | None = None,
        private_key_pem: str | None = None,
        signature_format: str = "p1363",
    ) -> str:
        hash_bytes = _decode_base64_or_url(invoice_hash)
        hash_url = b64url_encode(hash_bytes)
        base_url = self.options.resolve_qr_base_url().rstrip("/")
        path = "/".join(
            [
                base_url,
                "certificate",
                context_identifier_type,
                context_identifier_value,
                seller_nip,
                certificate_serial,
                hash_url,
            ]
        )
        path_to_sign = path.replace("https://", "").replace("http://", "")

        signature = _sign_path(
            path_to_sign, signing_certificate_pem, private_key_pem, signature_format
        )
        signature_url = b64url_encode(signature)
        return f"{path}/{signature_url}"


def _decode_base64_or_url(value: str) -> bytes:
    try:
        return b64decode(value)
    except Exception:
        return b64url_decode(value)


def _sign_path(
    path_to_sign: str,
    certificate_pem: str | None,
    private_key_pem: str | None,
    signature_format: str,
) -> bytes:
    if not private_key_pem:
        raise ValueError("private_key_pem is required for signing")

    private_key = load_private_key(private_key_pem)

    data = path_to_sign.encode("utf-8")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    sha = digest.finalize()

    if isinstance(private_key, rsa.RSAPrivateKey):
        return sign_path_rsa_pss(private_key, sha)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return sign_path_ecdsa(private_key, sha, format=signature_format)

    # If a certificate is provided, we can try to infer key type, but private key is required.
    if certificate_pem:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        key = cert.public_key()
        raise ValueError(f"Unsupported private key for certificate type: {type(key)}")

    raise ValueError("Unsupported private key type")
