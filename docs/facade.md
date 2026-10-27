# Fasada aplikacyjna i operacje KSeF

`Ksef` i `AsyncKsef` upraszczają logowanie, sesje i długotrwałe operacje.
Pełne dotychczasowe SDK pozostaje dostępne przez `client.api`; jego sygnatury
i typy wyników nie zmieniają się. Fasada wymaga Pythona 3.10+ i nie importuje CLI.

[Pierwszy przykład od instalacji do numeru KSeF](getting-started.md#zalecany-start-ksef)
działa bez profilu. Poniższe przykłady używają profilu `firma` albo już połączonego
klienta `client` wewnątrz jego bloku `with`.

| Zadanie | Punkt wejścia |
| --- | --- |
| Logowanie tokenem lub XAdES | `Ksef.connect(credentials=..., ...)` |
| Wysyłka XML i wynik faktury | `client.online_session()`, `session.send_invoice(xml).wait()` |
| Wysyłka archiwum | `client.batch_session(archive)`, `session.upload_parts()` |
| Pobranie XML faktury | `client.invoices.download(ksef_number)` |
| Eksport na dysk | `client.exports.start(filters).download_to(destination, work_dir=work)` |
| Wznowienie | `client.resume_operation(state)` lub `client.resume_session(state, ...)` |
| Pozostałe endpointy SDK | `client.api` |

## Połączenie

Profil `firma` utwórz przez [SDK](profiles.md) albo CLI:

```bash
ksef init --non-interactive --name firma --env TEST --context-type nip --context-value <NIP> --set-active
```

Komenda wymaga dodatku `cli`; sam klient Python go nie potrzebuje.
Token w `KSEF_TOKEN` musi dotyczyć tego samego środowiska i kontekstu co profil.

```python
import os
from ksef_client import Ksef, TokenCredentials

with Ksef.connect(
    profile="firma",
    credentials=TokenCredentials(os.environ["KSEF_TOKEN"]),
) as client:
    print(client.api.limits.get_context_limits())
```

Profil dostarcza środowisko i kontekst, a aplikacja dostarcza poświadczenia.
Alternatywnie przekaż `options=KsefClientOptions(...)`, `context_type="nip"`
i `context_value=...`; nie łącz ich z profilem. Połączenie automatycznie dobiera
publiczny certyfikat KSeF i odświeża access token. Nie zapisuje tokenów na dysku.
Wyjście z kontekstu zamyka transporty, bez unieważniania tokenów w KSeF.

XAdES wymaga dodatku `xml`. Użyj `XadesCredentials(XadesKeyPair(...))`,
`XadesKeyPair.from_pem_files(...)`, `XadesKeyPair.from_pkcs12_file(...)` albo
`XadesCredentials.from_store("certyfikat", password=...)`. Magazyn certyfikatów
jest niezależny od CLI i keyringa. Hasła i klucze nigdy nie trafiają do `repr`.

`TokenCredentials` przyjmuje także `public_key_id`, własny `public_certificate`,
`method="rsa"` lub `"ec"`, `ec_output_format="java"` lub `"csharp"` oraz
typowane `authorization_policy`. Automatyczny wybór certyfikatu uwzględnia algorytm
i wskazany identyfikator klucza, więc nowszy certyfikat EC nie zastępuje klucza RSA.
`XadesCredentials` obsługuje `authorization_policy_xml` i `auth_request_schema_version`.
`connect()` oraz `from_auth_result()` przyjmują `refresh_margin_seconds` i `on_refresh`;
w async callback może być zwykłą funkcją lub funkcją asynchroniczną.
`online_session()`, `batch_session()` i `exports.start()` pozwalają jawnie przekazać
`public_certificate` i `public_key_id` dla szyfrowania klucza sesji.

## Sesja online i wynik faktury

```python
with client.online_session() as session:
    operation = session.send_invoice(xml_bytes)
    invoice = operation.wait(timeout=120)

session.wait(timeout=120)
upo = session.upo().wait(timeout=120)
xml = client.invoices.download(invoice.ksef_number)
```

Domyślny formularz to FA(3); można podać `form_code=`. Wynikiem `send_invoice()`
jest uchwyt, a wynikiem jego `wait()` jest `SessionInvoiceStatusResponse`.
Zakończenie `with` zamyka sesję bez oczekiwania na przetworzenie. Przy błędzie
również podejmuje próbę zamknięcia, zachowując pierwotny wyjątek.
`session.wait()` nie ukrywa odrzuconych faktur, nawet jeśli sesja ma status 200.
UPO ma osobny uchwyt, bo może stać się dostępne później; wynik opisuje wszystkie strony.

`upo.pages` zawiera informacje o stronach, a nie ich XML. Aby zapisać dokumenty,
po uzyskaniu `upo` użyj klienta API w tym samym połączeniu:

```python
from pathlib import Path

reference = session.resume_state().reference_number
for index, page in enumerate(upo.pages, start=1):
    content = client.api.sessions.get_session_upo(reference, page.reference_number)
    Path(f"upo-{index}.xml").write_bytes(content)
```

## Batch i wznowienie

```python
with client.batch_session(archive_bytes) as session:
    session.upload_parts()
session.wait()
```

Kontekst batch zamyka sesję tylko po potwierdzeniu uploadu wszystkich części.
Przy błędzie lub niepełnym uploadzie sesja pozostaje do wznowienia.
`session.resume_state()` zapisuje także potwierdzone części. Aplikacja jawnie
utrwala ten poufny stan i oryginalne archiwum; po restarcie:

```python
resumed = client.resume_session(state, archive_bytes=archive_bytes)
with resumed:
    resumed.upload_parts()  # pomija potwierdzone części
resumed.wait()
```

Jeżeli upload wszystkich części już się zakończył, samo `client.resume_session(state)`
wystarcza do zamknięcia sesji, odczytu jej statusu lub pobrania UPO. Archiwum jest
wymagane wyłącznie do wysłania brakujących części. Równoległy upload odbiera wyniki
wszystkich zadań przed zwróceniem błędu; potwierdzone sukcesy pozostają w stanie.

Niepewnego wyniku zamknięcia SDK nie ponawia automatycznie. Odtworzony uchwyt
pozwala sprawdzić status i oczekiwać na wynik. Decyzję o ewentualnym ponowieniu
zmiany stanu podejmuje aplikacja po uzgodnieniu stanu z KSeF.

## Wspólny kontrakt operacji

Każdy uchwyt udostępnia `get_status()`, `wait(timeout=120, poll_interval=2)`
i `resume_state()`. Pierwszy status odczytuje natychmiast, później odpytuje
w podanym interwale. Termin jest monotoniczny i obejmuje retry oraz oczekiwanie
na budżet API; zagnieżdżony `request_control()` może go skrócić lub anulować.

`KsefOperationTimeout` zawiera `state` i `last_status`. Timeout przerywa lokalne
oczekiwanie, nie anuluje operacji w KSeF. `KsefOperationError` zachowuje wynik
odrzucenia; nieznany kod statusu nie jest traktowany jako sukces.
Powtórne `wait()` na zakończonym uchwycie zwraca zapamiętany wynik.

Przykład dłuższego oczekiwania po lokalnym timeoutcie, bez ponownej wysyłki faktury:

```python
from ksef_client import KsefOperationTimeout

try:
    invoice = operation.wait(timeout=120)
except KsefOperationTimeout as exc:
    resumed = client.resume_operation(exc.state)
    invoice = resumed.wait(timeout=300)
```

Tutaj `operation` jest wynikiem `session.send_invoice(...)`. Po restarcie aplikacji
zaloguj się ponownie i odtwórz uchwyt z wcześniej zapisanego stanu w tym samym kontekście.
Stan eksportu wznawia transfer, stan faktury wznawia sprawdzanie jej wyniku;
`resume_session()` odtwarza sesję do dalszej pracy.

Fasada zawęża przekazaną konfigurację retry do GET/HEAD/OPTIONS, idempotentnych
uploadów PUT i jawnie dozwolonego
odczytu `/invoices/query/metadata`. Nie przejmuje szerokiej polityki ponawiania
POST/DELETE z SDK. Oryginalne opcje pozostają niezmienione.

`client.resume_operation(state)` odtwarza oczekiwanie na fakturę, sesję,
eksport, uprawnienia lub certyfikat. Stan wiąże się z kontekstem i środowiskiem,
ale nie zastępuje autoryzacji. `OperationState.from_dict(...)` wczytuje wersję 1.
Stany są prywatnymi danymi aplikacji: nie są podpisane ani zaszyfrowane.
`to_dict()`/`to_json()` to jawny eksport, który może zawierać token uwierzytelniania,
klucze AES i podpisane URL-e. Nie loguj ani nie udostępniaj tych danych.

Do utrwalania plikowego użyj uwierzytelnionego szyfrowania stanu zamiast jawnego JSON:

```python
from ksef_client import OperationState

# state_key: 32 losowe bajty z magazynu sekretów aplikacji, przechowywane osobno.
encrypted = operation.resume_state().to_encrypted_bytes(state_key)
restored = OperationState.from_encrypted_bytes(encrypted, state_key)
resumed = client.resume_operation(restored)
```

Format szyfrowany używa AES-256-GCM, losowego nonce oraz uwierzytelnionej wersji
koperty. Zmieniony szyfrogram, błędny klucz i nieznana wersja są odrzucane.
`from_json()` ogranicza rozmiar wejścia przed parsowaniem. Wersja schematu stanu to 1;
nieznane wersje wymagają jawnej migracji przez aplikację i nie są automatycznie odtwarzane.

Logowanie ma również uchwyt: `Ksef.begin_auth(...)` / `Ksef.resume_auth(state, ...)`.
Użyj go jako kontekstu, aby zamknąć transport. `wait()` zwraca `AuthResult`;
`Ksef.from_auth_result(options, result, context_key="Nip:...")` tworzy fasadę.
Po utracie odpowiedzi na jednorazową wymianę tokena SDK zgłasza niepewny wynik,
zamiast ponawiać wymianę.

## Uprawnienia i certyfikaty

`client.permissions.grant_person(request).wait()` oraz pozostałe metody
`grant_*`, `revoke_authorization()` i `revoke_common_permission()` zwracają
`PermissionsOperationStatusResponse`. Przyjmują te same typowane requesty co SDK.

`client.certificates.send_enrollment(request).wait()` zwraca
`CertificateEnrollmentStatusResponse`. Odczyt, pobranie i odwołanie certyfikatu
pozostają zwykłymi wywołaniami. Oczekiwanie nie oznacza, że aplikacja automatycznie
zapisze certyfikat lub prywatny klucz.

## Eksport na dysk

Wewnątrz połączenia `with ... as client` wybierz zakres i stronę transakcji.
Ten przykład eksportuje faktury sprzedażowe z podanego okresu:

```python
from ksef_client import models as m

filters = m.InvoiceQueryFilters(
    subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
    date_range=m.InvoiceQueryDateRange(
        date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
        from_="2026-01-01T00:00:00Z",
        to="2026-02-01T00:00:00Z",
        restrict_to_permanent_storage_hwm_date=True,
    ),
)
operation = client.exports.start(filters)
# Aplikacja jawnie zapisuje operation.resume_state() w swoim magazynie sekretów.
result = operation.download_to("output/export-1", work_dir="work/export-1", timeout=600)
print(result.files)
# result.metadata_path wskazuje surowy _metadata.json, bez ładowania go do RAM.
```

`wait()` eksportu czeka tylko na gotową paczkę. `download_to()` obejmuje jednym
terminem oczekiwanie i pobieranie; domyślnie jest to **600 sekund**.
Cel musi być nowym katalogiem, oddzielnym od
`work_dir`. Wynik pojawia się dopiero po pełnej walidacji; istniejący katalog nie
jest nadpisywany. `work_dir` jest przeznaczony dla jednego eksportu i jednego
aktywnego procesu; blokada jest zwalniana również po zakończeniu procesu.

`work_dir` przechowuje zaszyfrowane części i manifest umożliwiający wznowienie.
Odszyfrowane archiwum powstaje wyłącznie w prywatnym katalogu tymczasowym i jest
usuwane po sukcesie lub błędzie. Katalog wynikowy zawiera jawne faktury, zgodnie
z żądaniem pobrania. Na POSIX istniejący `work_dir` musi mieć uprawnienia `0700`;
na Windows aplikacja powinna wskazać katalog z prywatnymi ACL. Symlinki w przodkach
(np. systemowy `/tmp`) są rozwiązywane; końcowy plik lub katalog będący dowiązaniem
albo punktem ponownej analizy jest odrzucany.
Pliki robocze muszą być zwykłymi plikami z jednym dowiązaniem: FIFO, urządzenia
i twarde dowiązania są odrzucane przed odczytem lub zapisem.

Transfer ma osobne limity dyskowe: domyślnie **64 MiB na odszyfrowaną część**
i **1 GiB na całe archiwum**, z uwzględnieniem dopełnienia CBC dla zaszyfrowanych części.
Rozmiary i ich sumy są sprawdzane przed żądaniami storage, a odczyty nie mogą
przekroczyć rozmiaru zadeklarowanego przez API. Politykę można jawnie zmienić:

```python
from ksef_client import ExportLimits

result = operation.download_to(
    "output/export-2", work_dir="work/export-2",
    limits=ExportLimits(max_part_bytes=64 * 1024**2, max_archive_bytes=1024**3),
)
```

Przed publikacją paczka musi zawierać `_metadata.json` i wyłącznie oczekiwane XML-e.
Stan nowego eksportu zachowuje `only_metadata`, więc liczba XML-i jest porównywana
z liczbą faktur z API albo musi wynosić zero dla eksportu samych metadanych.
Starsze stany wersji 1 bez tego pola nadal można wznowić; dla nich sprawdzane są
obecność metadanych, dozwolone pliki oraz limit 10 000 faktur.

Uszkodzony checkpoint lub archiwum i błędy plikowe podczas transferu zgłaszają
`KsefExportTransferError` z oryginalnym wyjątkiem w `__cause__`.
Timeout zachowuje osobny typ `KsefOperationTimeout`; błędne argumenty wywołania
pozostają `ValueError` lub `TypeError`.

Transfer używa buforów 1 MiB. Pobieranie wznawia zaszyfrowaną część przez
Range/If-Range z silnym ETag. Brak wsparcia, zmieniony ETag lub niepoprawna
odpowiedź powodują ponowne pobranie tej części; ukończone części są zachowane.
Po restarcie lokalne pliki są ponownie hashowane. Wygasły podpisany URL jest
odświeżany przez status tego samego eksportu, bez tworzenia nowej operacji.

SDK sprawdza rozmiary, hashe z API i dostępny nagłówek storage, oddzielnie
odszyfrowuje części i rozpakowuje ZIP/TarGz na dysku. Nie materializuje paczki
ani metadanych w RAM. Zachowuje limity archiwów: 10 001 plików, 500 MB na plik,
2 GB łącznie i stosunek dekompresji do 200. Odrzuca dowiązania i niebezpieczne nazwy.
ZIP obsługuje metody Stored i Deflate; BZIP2/LZMA są odrzucane przed dekompresją.
Przed utworzeniem obiektów wpisów ZIP sprawdza rzeczywistą liczbę nagłówków katalogu
centralnego (do 10 001, wliczając katalogi), jego rozmiar (do 16 MiB) i zgodność
z licznikiem końca archiwum. Obsługuje także ZIP64 i archiwa z prefiksem.
Odczyt tych rekordów nie korzysta z prywatnego parsera `zipfile`; archiwa wielodyskowe
i rozszerzone rekordy końcowe ZIP64 są odrzucane przed utworzeniem `ZipFile`.
TarGz ogranicza również nagłówki rozszerzone (1 MiB na nagłówek, 16 MiB łącznie),
liczbę nagłówków i katalogów oraz rozmiar strumienia po dekompresji.
Termin transferu jest sprawdzany po każdym odczycie sieciowym, przed złożeniem
bufora zapisu 1 MiB. Timeout pobierania zawiera stan wznowienia i ostatni status.

Manifest postępu w `work_dir` nie zawiera tokenów, kluczy ani URL-i. Zawiera
techniczne identyfikatory i hashe, więc również należy go chronić. Klucze
eksportu są wyłącznie w poufnym `resume_state()`, którego utrwalenie należy do aplikacji.
Po restarcie zaloguj się ponownie, odtwórz uchwyt przez `resume_operation()`
i użyj tego samego `work_dir` oraz nowego lub jeszcze nieutworzonego celu.

`result.package` zachowuje `isTruncated`, HWM i daty kontynuacji. Ukończenie
transferu oznacza pobranie jednej paczki, nie całego zbioru faktur. Fasada nie
uruchamia kolejnych eksportów ani synchronizacji przyrostowej automatycznie.

## Async

```python
import asyncio
import os
from pathlib import Path

from ksef_client import AsyncKsef, TokenCredentials

async def main():
    xml = await asyncio.to_thread(Path("invoice.xml").read_bytes)
    client = await AsyncKsef.connect(
        profile="firma",
        credentials=TokenCredentials(os.environ["KSEF_TOKEN"]),
    )
    async with client:
        session = await client.online_session()
        async with session:
            operation = await session.send_invoice(xml)
            invoice = await operation.wait()
        await session.wait()
        print(invoice.ksef_number)

asyncio.run(main())
```

Metody wykonujące HTTP wymagają `await`. Tworzenie uchwytów z lokalnego stanu,
`resume_state()` i `session.upo()` pozostają synchroniczne. Transfer eksportu
wykorzystuje osobny worker z własnym transportem; nie blokuje pętli asyncio.
Anulowanie sygnalizuje zatrzymanie i czeka na zamknięcie workera, zanim odda kontrolę.
Trwający synchroniczny odczyt sieciowy podlega skonfigurowanemu timeoutowi HTTP;
sam sygnał anulowania go nie przerywa.

Uruchamialne przykłady: [sync](examples/facade_sync.py) i [async](examples/facade_async.py).
Pomiar pamięci: `PYTHONPATH=src python tools/benchmark_streaming_export.py --directory .build/export-rss`.
