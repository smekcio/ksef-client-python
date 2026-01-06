from __future__ import annotations

import os

from ksef_client.client import KsefClient
from ksef_client.config import KsefClientOptions, KsefEnvironment
from ksef_client.services.workflows import AuthCoordinator


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
        certs = client.security.get_public_key_certificates()
        token_cert_pem = next(
            c["certificate"]
            for c in certs
            if "KsefTokenEncryption" in (c.get("usage") or [])
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
    print(f"Access token: {result.tokens.access_token.token}")
    print(f"Refresh token: {result.tokens.refresh_token.token}")


if __name__ == "__main__":
    main()

