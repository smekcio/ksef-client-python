"""Klient z automatycznym odświeżaniem tokena (bez `access_token` w metodach).

Skrypt pokazuje minimalny przepływ: uwierzytelnienie tokenem KSeF, zbudowanie
`AuthenticatedClient` z wyniku `AuthCoordinator` i jedno wywołanie API bez
przekazywania tokena.

Uruchomienie (DEMO lub TEST):

    KSEF_TOKEN=... KSEF_CONTEXT_TYPE=nip KSEF_CONTEXT_VALUE=... \\
    KSEF_BASE_URL=https://api-demo.ksef.mf.gov.pl \\
    python docs/examples/authenticated_client.py

Wymaga `KSEF_TOKEN` (token KSeF) i danych kontekstu. Skrypt tylko czyta dane.
"""

from __future__ import annotations

import os

from ksef_client import (
    AuthenticatedClient,
    KsefClient,
    KsefClientOptions,
    KsefEnvironment,
    RetryConfig,
)
from ksef_client import (
    models as m,
)
from ksef_client.services import AuthCoordinator


def _require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SystemExit(f"Brak zmiennej środowiskowej {name}")
    return value


def main() -> int:
    base_url = os.getenv("KSEF_BASE_URL", KsefEnvironment.DEMO.value)
    context_type = os.getenv("KSEF_CONTEXT_TYPE", "nip")
    context_value = _require_env("KSEF_CONTEXT_VALUE")
    token = _require_env("KSEF_TOKEN")

    options = KsefClientOptions(base_url=base_url, retry=RetryConfig())

    # 1. Uwierzytelnienie „anonimowym" klientem (endpointy auth nie wymagają tokena).
    with KsefClient(options) as anonymous:
        certificate_pem = anonymous.security.get_public_key_certificate_pem(
            m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION
        )
        auth_result = AuthCoordinator(anonymous.auth).authenticate_with_ksef_token(
            token=token,
            public_certificate=certificate_pem,
            context_identifier_type=context_type,
            context_identifier_value=context_value,
            max_attempts=90,
            poll_interval_seconds=2.0,
        )

    # 2. Klient z managerem tokenów: `access_token` nie jest już potrzebny.
    with AuthenticatedClient.from_auth_result(options, auth_result) as client:
        page = client.invoices.query_invoice_metadata_by_date_range(
            subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
            date_type=m.InvoiceQueryDateType.ISSUE,
            date_from="2026-01-01T00:00:00Z",
            date_to="2026-01-31T23:59:59Z",
            page_size=10,
        )
        print(f"Faktur na stronie: {len(page.invoices)} (hasMore={page.has_more})")
        print(f"Token wygasa: {client.token_manager.snapshot().access_token_expires_at}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
