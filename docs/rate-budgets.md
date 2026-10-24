# Wspólne budżety limitów API

`RateLimitBudget` planuje dopuszczenie żądania na podstawie ruchomych okien
1 sekundy, 1 minuty i 1 godziny. Jedna instancja może być współdzielona przez
wiele klientów synchronicznych, wątki i klientów async. Oczekiwanie async nie
blokuje pętli zdarzeń. Bez konfiguracji budżetu klienci zachowują swoje domyślne
działanie; budżet i retry HTTP są niezależnymi ustawieniami.

## Konfiguracja

Najpierw pobierz aktualne limity uwierzytelnionego kontekstu. Nie zakładaj,
że TEST, DEMO i PROD mają takie same wartości.

```python
from dataclasses import replace
from ksef_client import RateLimitBudget, RateLimitPolicy

policy = RateLimitPolicy.from_effective_limits(client.rate_limits.get_rate_limits())
budget = RateLimitBudget(policy)
limited_options = replace(
    options,
    rate_limit_budget=budget,
    rate_limit_context_key="Nip:5265877635",
    rate_limit_egress_key="office",
)
```

Utwórz klientów sync i async z tym samym `budget`. `rate_limit_context_key`
opisuje kontekst użyty do uwierzytelnienia; SDK nie wyprowadza go z tokena i nie
sprawdza nim uprawnień. `rate_limit_egress_key` to stabilna etykieta wyjściowego
adresu IP lub proxy. SDK nie ustala publicznego adresu IP. Domyślna etykieta
`default` zachowawczo współdzieli budżet dla klientów korzystających z tej instancji.

Globalne i anonimowe liczniki są wspólne dla środowiska i wyjściowego IP,
a pozostałe także dla kontekstu. Aliasy URL tego samego origin współdzielą
liczniki; poświadczenia, query i identyfikatory dokumentów nie są kluczami budżetu.
Endpointy `other` mają osobne liczniki według metody i szablonu ścieżki.
Nieznane endpointy API używają zachowawczego wspólnego `other`.
Pobrania z adresów storage i wywołania Latarni nie zużywają budżetu API KSeF.
Publiczne endpointy API, w tym certyfikaty i uwierzytelnienie, są rozliczane.

Politykę można też zbudować jawnie:

```python
from ksef_client import RateLimitPolicy, RateLimitValues

policy = RateLimitPolicy({
    "global": RateLimitValues(per_second=5, per_minute=60, per_hour=500),
    "invoice_metadata": RateLimitValues(per_second=1, per_minute=5, per_hour=10),
})
```

To przykładowe wartości aplikacyjne, nie limity KSeF. Brak polityki dla użytej
grupy endpointów powoduje błąd przed wysłaniem żądania. Pominięcie `global` oznacza
świadomie niepełną politykę lokalną; odpowiedź `/rate-limits` zawiera tę grupę.
`None` i `-1` oznaczają brak limitu danego okna. Polityka jest niezmiennym snapshotem.
Zmianę limitów i wymianę instancji należy skoordynować z aktywnym ruchem aplikacji.

## Termin i anulowanie oczekiwania

```python
from ksef_client import CancellationToken, request_control

cancel = CancellationToken()  # inny wątek może wywołać cancel.cancel()
with request_control(timeout_seconds=30, cancellation=cancel):
    page = search.page(cursor=saved_cursor)
```

Ten sam kontekst działa wokół `await search.page(...)`. Obsługuje też absolutny
`deadline` zegara monotonicznego. Zagnieżdżone konteksty mogą skrócić termin rodzica,
zachowują też jego sygnał anulowania. Kontekst propaguje się do zadań asyncio,
ale nowe wątki wymagają własnego kontekstu lub jawnego `RequestControl`.

`KsefRateLimitWaitTimeout` oznacza przekroczenie terminu, a
`KsefRequestCancelledError` — anulowanie. Oczekiwanie na budżet i retry jest
przerywalne; anulowanie nie cofa żądania już wysłanego do KSeF. Synchronicznego
wywołania sieciowego w toku nie da się przerwać tokenem. Pozostały czas ogranicza
timeout HTTP, ale timeouty transportu nie są gwarancją ścisłego czasu całej operacji.
Natywne anulowanie zadania asyncio pozostaje obsługiwane.

Każde fizyczne wysłanie, w tym retry i ponowienie po 401, otrzymuje osobne
dopuszczenie. Token jest przygotowywany poza rezerwacją; jeśli wygaśnie podczas
oczekiwania, niewykorzystane dopuszczenie zostaje zwolnione, token odświeżony,
a żądanie ponownie dopuszczone. Błąd transportu po rozpoczęciu wysyłki zachowawczo
zużywa limit. Automatyczne przekierowania są niedozwolone przy aktywnym budżecie.

HTTP 429 aktualizuje współdzielony cooldown z pełnego `Retry-After`. Budżet sam
nie ponawia wysyłki faktury ani nie zmienia allowlisty `RetryConfig`. Długi cooldown
nadal podlega terminowi i anulowaniu, zamiast nieprzerywalnego uśpienia wątku.

## Granice współdzielenia i pamięci

Budżet działa w jednym procesie. Nie koordynuje innych procesów, hostów ani
aplikacji używających tego samego konta/IP. W takich wdrożeniach aplikacja musi
uzgodnić wspólny ruch lub zastosować zachowawcze limity lokalne. Nie ma gwarancji
kolejności FIFO oczekujących żądań.

`max_scopes`, `max_buckets` i `max_history` ograniczają pamięć. Historia liczy
znaczniki czasu we wszystkich oknach i grupach. SDK usuwa tylko wygasłe liczniki;
nie porzuca aktywnych danych, żeby zrobić miejsce. Brak miejsca powoduje
`KsefRateLimitCapacityError` i nie dopuszcza kolejnego żądania.

Zaawansowane bezpośrednie użycie `budget.acquire()` / `await budget.acquire_async()`
zwraca `RateLimitAdmission`. `commit()` zatwierdza wysłanie, a `cancel()` zwalnia
niewykorzystane dopuszczenie. Operacje są idempotentne; zatwierdzonego wysłania
nie można zwolnić. Klienci HTTP zarządzają tym cyklem automatycznie.
