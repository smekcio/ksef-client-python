from __future__ import annotations

import os

from ksef_client.client import KsefClient
from ksef_client.config import KsefClientOptions, KsefEnvironment
from ksef_client.services import XadesKeyPair
from ksef_client.services.workflows import AuthCoordinator


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        raise SystemExit(f"Set {name} env var.")
    return value


def _env_optional(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    if value is None or value == "":
        return None
    return value


def main() -> None:
    base_url = _env("KSEF_BASE_URL", KsefEnvironment.DEMO.value)
    context_type = _env("KSEF_CONTEXT_TYPE")
    context_value = _env("KSEF_CONTEXT_VALUE")
    subject_identifier_type = _env("KSEF_SUBJECT_IDENTIFIER_TYPE", "certificateSubject")

    pkcs12_path = _env_optional("KSEF_XADES_PKCS12")
    pkcs12_password = _env_optional("KSEF_XADES_PKCS12_PASSWORD")
    certificate_path = _env_optional("KSEF_XADES_CERT_PEM")
    private_key_path = _env_optional("KSEF_XADES_KEY_PEM")
    private_key_password = _env_optional("KSEF_XADES_KEY_PASSWORD")

    try:
        if pkcs12_path:
            key_pair = XadesKeyPair.from_pkcs12_file(
                pkcs12_path=pkcs12_path,
                pkcs12_password=pkcs12_password,
            )
        else:
            if not certificate_path or not private_key_path:
                raise SystemExit(
                    "Brak konfiguracji XAdES. Wymagane jest ustawienie `KSEF_XADES_PKCS12` "
                    "albo pary `KSEF_XADES_CERT_PEM` + `KSEF_XADES_KEY_PEM`."
                )
            key_pair = XadesKeyPair.from_pem_files(
                certificate_path=certificate_path,
                private_key_path=private_key_path,
                private_key_password=private_key_password,
            )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    try:
        with KsefClient(KsefClientOptions(base_url=base_url)) as client:
            result = AuthCoordinator(client.auth).authenticate_with_xades_key_pair(
                key_pair=key_pair,
                context_identifier_type=context_type,
                context_identifier_value=context_value,
                subject_identifier_type=subject_identifier_type,
                max_attempts=90,
                poll_interval_seconds=2.0,
            )
    except RuntimeError as exc:
        if "XAdES signing requires" in str(exc):
            raise SystemExit(
                "Brak zależności dla podpisu XAdES. Wymagane jest zainstalowanie dodatku: "
                "pip install -e .[xml]"
            ) from exc
        raise

    print(f"Auth reference: {result.reference_number}")
    print(f"Access token: {result.tokens.access_token.token}")
    print(f"Refresh token: {result.tokens.refresh_token.token}")


if __name__ == "__main__":
    main()
