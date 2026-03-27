from __future__ import annotations

import os

from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client import models as m
from ksef_client.services import AuthCoordinator


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        raise SystemExit(f"Set {name} env var.")
    return value


def main() -> None:
    base_url = _env("KSEF_BASE_URL", KsefEnvironment.DEMO.value)
    token = _env("KSEF_TOKEN")
    context_type = _env("KSEF_CONTEXT_TYPE")
    context_value = _env("KSEF_CONTEXT_VALUE")

    with KsefClient(KsefClientOptions(base_url=base_url)) as client:
        token_cert_pem = client.security.get_public_key_certificate_pem(
            m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
        )
        result = AuthCoordinator(client.auth).authenticate_with_ksef_token(
            token=token,
            public_certificate=token_cert_pem,
            context_identifier_type=context_type,
            context_identifier_value=context_value,
            max_attempts=90,
            poll_interval_seconds=2.0,
        )

    print(f"Auth reference: {result.reference_number}")
    print(f"Access token: {result.access_token}")
    print(f"Refresh token: {result.refresh_token}")


if __name__ == "__main__":
    main()
