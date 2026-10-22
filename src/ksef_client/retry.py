"""Retry HTTP dla SDK KSeF — konfiguracja, opóźnienia i kwalifikacja żądań.

Moduł jest niezależny od warstwy HTTP (nie importuje ``http.py``), żeby dało się
go użyć w testach, w CLI i w konfiguracji bez cyklu importów. Stałe kontraktu
(``MAX_RETRY_AFTER_SECONDS``, ``RETRYABLE_STATUS_CODES``) mieszkają tutaj, a
:mod:`ksef_client.http` re-eksportuje je dla zgodności z istniejącymi importerami.

Retry jest **opt-in**: dopóki :class:`~ksef_client.config.KsefClientOptions` nie
ma ustawionego ``retry``, warstwa HTTP zachowuje się dokładnie tak jak wcześniej
(jedno żądanie, wyjątek przy błędzie). Włączenie to jedna linia:

```python
from ksef_client import KsefClientOptions, RetryConfig

options = KsefClientOptions(base_url="https://api-demo.ksef.mf.gov.pl", retry=RetryConfig())
```

Domyślna allowlista metod (``GET``/``PUT``/``DELETE``) jest celowo konserwatywna:
``POST`` bywa nieidempotentny (wysyłka faktury, redeem tokena), więc ponowienie
wymaga jawnego dodania ścieżki do ``retryable_post_paths``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

#: Górne ograniczenie ``Retry-After`` (sekundy).
#:
#: Serwer może zażądać pauzy o dowolnej długości (także ``Retry-After: 86400``),
#: a SDK czekałby wtedy dobę — proces wisiałby bez żadnego sygnału dla wołającego.
#: Wartość powyżej limitu jest traktowana jako „odczekaj maksimum", a nie
#: ignorowana, bo dalsze żądania i tak nie mają sensu.
MAX_RETRY_AFTER_SECONDS = 300

#: Statusy, których ponowienie ma sens — te same, które ponawia CLI
#: (``cli.policies.retry.should_retry``). Tylko dla nich warstwa HTTP czyta
#: ``Retry-After`` i tylko one kwalifikują się do pętli retry.
RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 502, 503, 504})

#: Twardy sufit opóźnienia jednej ponownej próby (24 h, w milisekundach).
#:
#: ``max_delay_ms=None`` wyłącza **własny** sufit konfiguracji, ale nie ten
#: bezpieczeństwa: bez niego backoff wykładniczy przy dużym ``max_retries``
#: dochodziłby do wartości, których ``time.sleep``/``asyncio.sleep`` nie przyjmą
#: (``OverflowError``), zamiast po prostu czekać.
MAX_RETRY_DELAY_MS = 86_400_000


@dataclass(frozen=True)
class RetryConfig:
    """Konfiguracja automatycznego ponawiania żądań HTTP.

    Args:
        max_retries: Ile razy ponowić po nieudanej próbie (``0`` = jedno żądanie,
            bez ponowień).
        base_delay_ms: Bazowe opóźnienie pierwszej ponownej próby (milisekundy).
        jitter_ratio: Losowy rozrzut opóźnienia w zakresie ``±jitter_ratio``
            (``0.2`` = ±20%), żeby równolegli klienci nie uderzali w serwer
            w tej samej chwili.
        max_delay_ms: Sufit wyliczonego backoffu (milisekundy); ``None`` wyłącza
            własny sufit konfiguracji, ale nadal obowiązuje twardy sufit
            bezpieczeństwa ``MAX_RETRY_DELAY_MS`` (24 h). Nie dotyczy
            ``Retry-After`` — wartość podana przez serwer ma pierwszeństwo
            (z sufitem ``MAX_RETRY_AFTER_SECONDS``).
        retryable_methods: Metody, które wolno ponawiać. Wartości są normalizowane
            do wielkich liter.
        retryable_post_paths: Ścieżki ``POST`` (dokładne, względne, np.
            ``"/invoices/query/metadata"``), które wolno ponawiać. Puste domyślnie:
            wysyłka faktury i redeem tokena nie mogą zostać powtórzone przez pomyłkę.

    Raises:
        ValueError: Gdy któraś wartość jest poza dozwolonym zakresem.
    """

    max_retries: int = 3
    base_delay_ms: int = 250
    jitter_ratio: float = 0.2
    max_delay_ms: int | None = 30_000
    retryable_methods: frozenset[str] = frozenset({"GET", "PUT", "DELETE"})
    retryable_post_paths: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if self.max_retries > 100:
            raise ValueError("max_retries must be <= 100")
        if self.base_delay_ms <= 0:
            raise ValueError("base_delay_ms must be > 0")
        if not (0 <= self.jitter_ratio <= 1):
            raise ValueError("jitter_ratio must be in range [0, 1]")
        if self.max_delay_ms is not None and self.max_delay_ms < self.base_delay_ms:
            raise ValueError("max_delay_ms must be >= base_delay_ms")
        if self.max_delay_ms is not None and self.max_delay_ms > MAX_RETRY_DELAY_MS:
            raise ValueError(f"max_delay_ms must be <= {MAX_RETRY_DELAY_MS} (24 h)")
        methods = frozenset(str(method).strip().upper() for method in self.retryable_methods)
        if "" in methods:
            raise ValueError("retryable_methods cannot contain an empty method name")
        # `frozen=True`: normalizację ustawiamy przez `object.__setattr__`, bo
        # `__post_init__` nie może przypisać do pola normalnie.
        object.__setattr__(self, "retryable_methods", methods)


def parse_retry_after_seconds(value: str | None) -> float | None:
    """Zamienia nagłówek ``Retry-After`` na sekundy (albo ``None``).

    Obsługuje obie formy z RFC 7231: liczbę sekund i datę HTTP. Wynik jest
    przycięty do ``0..MAX_RETRY_AFTER_SECONDS`` — wartość od serwera nie może
    usypiać procesu na dni.

    Funkcja jest wspólna z CLI (``cli.policies.retry.parse_retry_after``), żeby
    obie ścieżki czekały dokładnie tyle samo.
    """
    if value is None:
        return None
    text = value.strip()
    if text == "":
        return None

    if text.isdigit():
        return min(max(0.0, float(text)), float(MAX_RETRY_AFTER_SECONDS))

    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    delta_seconds = (parsed.astimezone(timezone.utc) - now).total_seconds()
    return min(max(0.0, delta_seconds), float(MAX_RETRY_AFTER_SECONDS))


def compute_retry_delay_seconds(
    attempt: int,
    config: RetryConfig,
    *,
    retry_after: str | None = None,
    random_value: float = 0.5,
) -> float:
    """Opóźnienie przed kolejną próbą (sekundy).

    ``Retry-After`` wygrywa z backoffem: serwer wie lepiej, ile kazać czekać.
    W przeciwnym razie opóźnienie rośnie wykładniczo (``base * 2**(attempt-1)``)
    z losowym rozrzutem ``±jitter_ratio`` i sufitem ``max_delay_ms``.

    Args:
        attempt: Numer próby, która właśnie się nie udała (``1`` = pierwsza).
        config: Konfiguracja retry.
        retry_after: Surowa wartość nagłówka ``Retry-After`` (jeśli była).
        random_value: Liczba z ``[0, 1]`` do wyznaczenia jittera; w testach
            podajemy ją wprost, żeby wynik był deterministyczny.

    Raises:
        ValueError: Gdy ``attempt`` lub ``random_value`` są poza zakresem.
    """
    if attempt <= 0:
        raise ValueError("attempt must be > 0")
    if not (0 <= random_value <= 1):
        raise ValueError("random_value must be in range [0, 1]")

    retry_after_seconds = parse_retry_after_seconds(retry_after)
    if retry_after_seconds is not None:
        return retry_after_seconds

    # Wykładnik ograniczamy, żeby `2 ** attempt` nie przepełnił `float`
    # przy dużym `max_retries` (wcześniej: OverflowError zamiast opóźnienia).
    exponent = min(attempt - 1, 63)
    base = float(config.base_delay_ms) * (2 ** exponent)
    jitter_factor = 1 + ((random_value * 2 - 1) * config.jitter_ratio)
    effective_ms = max(0.0, base * jitter_factor)
    cap_ms = (
        float(config.max_delay_ms)
        if config.max_delay_ms is not None
        else float(MAX_RETRY_DELAY_MS)
    )
    effective_ms = min(effective_ms, cap_ms, float(MAX_RETRY_DELAY_MS))
    return effective_ms / 1000.0


def should_retry_request(
    method: str,
    path: str,
    status_code: int,
    config: RetryConfig,
) -> bool:
    """Czy po tej odpowiedzi wolno ponowić **to** żądanie.

    Ponowienie wymaga jednocześnie:

    * statusu z ``RETRYABLE_STATUS_CODES`` (429/502/503/504),
    * metody z allowlisty (``GET``/``PUT``/``DELETE``) albo ``POST`` na ścieżce
      jawnie dopuszczonej w ``retryable_post_paths``.

    Args:
        method: Metoda HTTP żądania.
        path: Ścieżka przekazana do warstwy HTTP (względna, bez query). Ścieżki
            absolutne (pre-signed URL) nie pasują do allowlisty ``POST`` — tam
            i tak nie ma bezpiecznych przypadków.
        status_code: Status odpowiedzi.
        config: Konfiguracja retry.

    Returns:
        ``True``, gdy żądanie kwalifikuje się do ponowienia.
    """
    if status_code not in RETRYABLE_STATUS_CODES:
        return False

    normalized_method = method.strip().upper()
    if normalized_method == "POST":
        # POST tylko po jawnej ścieżce — nawet jeśli ktoś doda "POST" do
        # `retryable_methods`, nieidempotentna wysyłka nie może być ponawiana.
        return path in config.retryable_post_paths
    return normalized_method in config.retryable_methods


__all__ = [
    "MAX_RETRY_AFTER_SECONDS",
    "MAX_RETRY_DELAY_MS",
    "RETRYABLE_STATUS_CODES",
    "RetryConfig",
    "compute_retry_delay_seconds",
    "parse_retry_after_seconds",
    "should_retry_request",
]
