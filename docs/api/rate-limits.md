# Rate limits (`client.rate_limits`)

## `get_rate_limits(access_token)`

Endpoint: `GET /rate-limits`

Zwraca bieżące limity wywołań API. Obsługa 429: [Błędy i retry](../errors.md).

Wartości `perSecond` / `perMinute` / `perHour` odpowiadają limitom **żądań na sekundę,
minutę i godzinę** (`req/s`, `req/min`, `req/h`) — nie na dobę.

## Czytelny dostęp do grup limitów

Odpowiedź API jest płaskim modelem z 17 grupami. Moduł `ksef_client.services`
udostępnia warstwę semantyczną:

```python
from ksef_client.services import RateLimitGroup, get_rate_limit, iter_rate_limits

limits = client.rate_limits.get_rate_limits(access_token)

for info in iter_rate_limits(limits):
    print(info.group.value, info.per_second, info.per_minute, info.per_hour, info.is_active)

online_close = get_rate_limit(limits, RateLimitGroup.ONLINE_SESSION_CLOSE)
```

### Grupy limitów (KSeF API 2.8.0+)

| Grupa | Uwagi |
| --- | --- |
| `anonymous` | Operacje anonimowe. Obowiązywały wcześniej, ale API zwraca je od 2.8.0. |
| `onlineSession` / `batchSession` | Otwieranie sesji. |
| `onlineSessionClose` / `batchSessionClose` | **Nowe w 2.8.0.** Zamykanie sesji ma osobne, wyższe limity niż otwieranie: interaktywna `20/60/240`, wsadowa `20/40/120`. |
| `global` | **Zarezerwowane.** Przyszłe globalne limity per adres IP — mechanizm jest obecnie wyłączony i nie wpływa na integracje. |
| `collectiveIdentifier` | Identyfikatory zbiorcze; od 2.7.1 limit `20/120/240`. |
| pozostałe | `invoiceSend`, `invoiceStatus`, `invoiceMetadata`, `invoiceExport`, `invoiceExportStatus`, `invoiceDownload`, `sessionList`, `sessionInvoiceList`, `sessionMisc`, `other`. |

`RateLimitInfo.is_active` zwraca `False` dla grup zarezerwowanych (obecnie `global`),
żeby nie budować na nich logiki ponawiania.

> Limity zawsze odczytuj z `GET /rate-limits` — wartości domyślne w kontrakcie OpenAPI
> mogą się różnić od efektywnych dla Twojego kontekstu.
