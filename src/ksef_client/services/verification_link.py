from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..config import KsefClientOptions
from ..models import AuthenticationContextIdentifierType
from ..utils.base64url import b64decode, b64url_decode, b64url_encode
from .crypto import load_private_key, sign_path_ecdsa, sign_path_rsa_pss

#: Format daty wymagany przez qr.ksef.mf.gov.pl w segmencie linku KOD I.
_INVOICE_LINK_DATE = re.compile(r"[0-3][0-9]-[0-1][0-9]-[0-9]{4}")
#: Ten sam dzień w zapisie ISO-8601 — wygodny dla wołających, konwertujemy go.
_ISO_DATE = re.compile(r"([0-9]{4})-([0-1][0-9])-([0-3][0-9])")


def _normalize_context_identifier_type(value: str) -> str:
    """Zwraca segment ścieżki KOD II dokładnie tak, jak wymaga go kontrakt.

    ``qr.ksef.mf.gov.pl`` waliduje ten segment wobec zamkniętej listy
    (``Nip``, ``InternalId``, ``NipVatUe``, ``PeppolId``). SDK dokumentowało
    ``context_identifier_type='nip'``, a taki link był odrzucany jako
    „nieprawidłowy lub uszkodzony" — mimo że pozostałe wejścia SDK (np.
    ``services.auth``) przyjmują zapis bez rozróżniania wielkości liter.
    """
    key = value.strip().lower()
    for identifier_type in AuthenticationContextIdentifierType:
        if identifier_type.value.lower() == key:
            return identifier_type.value
    allowed = ", ".join(
        identifier_type.value for identifier_type in AuthenticationContextIdentifierType
    )
    raise ValueError(
        f"Unsupported context identifier type: {value!r}. Expected one of: {allowed}."
    )


def _normalize_invoice_link_date(issue_date: date | datetime | str) -> str:
    """Zamienia datę wystawienia na ``DD-MM-YYYY`` wymagany przez KOD I.

    Dowolny ``str`` przechodził wcześniej bez sprawdzenia: ``"2026/02/01"``
    dokładał do ścieżki dodatkowy segment (``/invoice/NIP/2026/02/01/<hash>``),
    a ``"2026-02-01"`` dawał kod odrzucany jako uszkodzony. Teraz przyjmujemy
    ``DD-MM-YYYY`` (format docelowy) oraz ISO-8601 (konwertowany), a wszystko
    inne zgłaszamy jako błąd, zanim wydrukowany zostanie błędny kod QR.
    """
    if isinstance(issue_date, (date, datetime)):
        return issue_date.strftime("%d-%m-%Y")
    text = issue_date.strip()
    if _INVOICE_LINK_DATE.fullmatch(text):
        return text
    iso_match = _ISO_DATE.fullmatch(text)
    if iso_match:
        year, month, day = iso_match.groups()
        return f"{day}-{month}-{year}"
    raise ValueError(
        f"Invalid invoice issue date: {issue_date!r}. Expected 'DD-MM-YYYY' "
        "(or ISO-8601 'YYYY-MM-DD')."
    )


@dataclass(frozen=True)
class VerificationLinkService:
    options: KsefClientOptions

    def build_invoice_verification_url(
        self, nip: str, issue_date: date | datetime | str, invoice_hash: str
    ) -> str:
        date_str = _normalize_invoice_link_date(issue_date)
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
        private_key_password: str | bytes | None = None,
        signature_format: str = "p1363",
    ) -> str:
        hash_bytes = _decode_base64_or_url(invoice_hash)
        hash_url = b64url_encode(hash_bytes)
        base_url = self.options.resolve_qr_base_url().rstrip("/")
        path = "/".join(
            [
                base_url,
                "certificate",
                _normalize_context_identifier_type(context_identifier_type),
                context_identifier_value,
                seller_nip,
                certificate_serial,
                hash_url,
            ]
        )
        path_to_sign = path.replace("https://", "").replace("http://", "")

        signature = _sign_path(
            path_to_sign,
            signing_certificate_pem,
            private_key_pem,
            signature_format,
            private_key_password=private_key_password,
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
    private_key_password: str | bytes | None = None,
) -> bytes:
    if not private_key_pem:
        raise ValueError("private_key_pem is required for signing")

    try:
        private_key = load_private_key(private_key_pem, password=private_key_password)
    except TypeError as exc:
        message = str(exc)
        if "Password was not given but private key is encrypted" in message:
            raise ValueError(
                "Unable to load the private key for verification link signing. "
                "The private key is encrypted; provide `private_key_password`."
            ) from exc
        if "Password was given but private key is not encrypted" in message:
            raise ValueError(
                "Invalid private key password configuration for verification link signing. "
                "Omit `private_key_password` for an unencrypted private key."
            ) from exc
        raise ValueError(
            "Invalid private key password configuration for verification link signing."
        ) from exc
    except ValueError as exc:
        message = str(exc).lower()
        encrypted_pem = "ENCRYPTED PRIVATE KEY" in private_key_pem or (
            "Proc-Type: 4,ENCRYPTED" in private_key_pem
        )
        if (private_key_password is not None and encrypted_pem) or any(
            text in message
            for text in (
                "incorrect password",
                "bad decrypt",
                "could not decrypt",
                "bad password read",
            )
        ):
            raise ValueError(
                "Unable to load the private key for verification link signing. "
                "`private_key_password` is incorrect."
            ) from exc
        raise ValueError(
            "Unable to load the private key for verification link signing. "
            "Unsupported private key format, encryption, or type."
        ) from exc

    data = path_to_sign.encode("utf-8")

    if isinstance(private_key, rsa.RSAPrivateKey):
        return sign_path_rsa_pss(private_key, data)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return sign_path_ecdsa(private_key, data, format=signature_format)

    # If a certificate is provided, we can try to infer key type, but private key is required.
    if certificate_pem:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        key = cert.public_key()
        raise ValueError(f"Unsupported private key for certificate type: {type(key)}")

    raise ValueError("Unsupported private key type")
