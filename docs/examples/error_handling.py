"""Taksonomia błędów SDK — kategorie, kody KSeF i `to_dict()`.

Skrypt celowo wykonuje żądanie bez tokena: KSeF odpowie `401`, więc można zobaczyć
mapowanie na `KsefAuthenticationError` (podklasa `KsefApiError`) bez posiadania
danych uwierzytelniających.

Uruchomienie:

    KSEF_BASE_URL=https://api-demo.ksef.mf.gov.pl \\
    python docs/examples/error_handling.py
"""

from __future__ import annotations

import os

from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client.exceptions import KsefApiError, KsefError, KsefRateLimitError


def main() -> int:
    options = KsefClientOptions(
        base_url=os.getenv("KSEF_BASE_URL", KsefEnvironment.DEMO.value),
    )

    with KsefClient(options) as client:
        try:
            client.auth.get_active_sessions()
        except KsefRateLimitError as exc:
            print(f"429: retry_after={exc.retry_after}")
            print(f"to_dict: {exc.to_dict()}")
        except KsefApiError as exc:
            print(f"API: {exc.code.value} (HTTP {exc.status_code})")
            print(f"kody KSeF: {exc.exception_codes}")
            print(f"znane kody: {[member.name for member in exc.known_exception_codes]}")
            print(f"szczegóły: {exc.details}")
            print(f"trace_id: {exc.trace_id}")
            print(f"to_dict: {exc.to_dict()}")
        except KsefError as exc:
            # np. KsefTransportError, gdy środowisko jest nieosiągalne
            print(f"SDK: {exc.code.value}: {exc.message}")
            print(f"to_dict: {exc.to_dict()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
