"""Retry HTTP w SDK — konfiguracja i wyliczanie opóźnień bez sieci.

Skrypt pokazuje, jak działa `RetryConfig`: które statusy/metody są ponawiane,
jak wygląda backoff i jak `Retry-After` wpływa na opóźnienie. Nie wymaga
dostępu do KSeF ani tokena.

Uruchomienie:

    python docs/examples/retry_config.py
"""

from __future__ import annotations

from ksef_client import KsefClientOptions, RetryConfig
from ksef_client.retry import compute_retry_delay_seconds, should_retry_request


def main() -> int:
    config = RetryConfig(
        max_retries=3,
        base_delay_ms=250,
        jitter_ratio=0.2,
        retryable_post_paths=frozenset({"/invoices/query/metadata"}),
    )
    options = KsefClientOptions(base_url="https://api-demo.ksef.mf.gov.pl", retry=config)
    print(f"Retry włączony: {options.retry is not None}")

    # Co wolno ponowić?
    for method, path, status in [
        ("GET", "/invoices/query/metadata", 503),
        ("POST", "/invoices/query/metadata", 503),
        ("POST", "/sessions/online", 503),
        ("GET", "/x", 400),
    ]:
        decision = should_retry_request(method, path, status, config)
        print(f"{method:5} {path:28} status={status} -> retry={decision}")

    # Ile czekać przed kolejnymi próbami? (random_value=0.5 wyłącza losowość)
    for attempt in range(1, 4):
        delay = compute_retry_delay_seconds(attempt, config, random_value=0.5)
        print(f"próba {attempt}: backoff {delay * 1000:.0f} ms")

    # Serwer może zażądać własnego czasu — ma pierwszeństwo (z sufitem 300 s).
    for retry_after in ("30", "999999"):
        delay = compute_retry_delay_seconds(1, config, retry_after=retry_after)
        print(f"Retry-After: {retry_after:>6} -> czekaj {delay:.0f} s")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
