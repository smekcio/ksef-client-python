# Fasada aplikacyjna i operacje KSeF

`Ksef` i `AsyncKsef` upraszczają logowanie, sesje i długotrwałe operacje.
Pełne dotychczasowe SDK pozostaje dostępne przez `client.api`; jego sygnatury
i typy wyników nie zmieniają się. Fasada wymaga Pythona 3.10+ i nie importuje CLI.

## Połączenie

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

Fasada zawęża przekazaną konfigurację retry do GET/HEAD/OPTIONS i jawnie dozwolonego
odczytu `/invoices/query/metadata`. Nie przejmuje szerokiej polityki ponawiania
POST/DELETE z SDK. Oryginalne opcje pozostają niezmienione.

`client.resume_operation(state)` odtwarza oczekiwanie na fakturę, sesję,
eksport, uprawnienia lub certyfikat. Stan wiąże się z kontekstem i środowiskiem,
ale nie zastępuje autoryzacji. `OperationState.from_dict(...)` wczytuje wersję 1.
Stany są prywatnymi danymi aplikacji: nie są podpisane ani zaszyfrowane.
`to_dict()`/`to_json()` to jawny eksport, który może zawierać token uwierzytelniania,
klucze AES i podpisane URL-e. Nie loguj ani nie udostępniaj tych danych.

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

```python
operation = client.exports.start(filters)
# Aplikacja jawnie zapisuje operation.resume_state() w swoim magazynie sekretów.
result = operation.download_to("output/export-1", work_dir="work/export-1", timeout=600)
print(result.files)
# result.metadata_path wskazuje surowy _metadata.json, bez ładowania go do RAM.
```

`wait()` eksportu czeka tylko na gotową paczkę. `download_to()` obejmuje jednym
terminem oczekiwanie i pobieranie. Cel musi być nowym katalogiem, oddzielnym od
`work_dir`. Wynik pojawia się dopiero po pełnej walidacji; istniejący katalog nie
jest nadpisywany. `work_dir` jest przeznaczony dla jednego eksportu i jednego
aktywnego procesu; blokada jest zwalniana również po zakończeniu procesu.

Transfer używa buforów 1 MiB. Pobieranie wznawia zaszyfrowaną część przez
Range/If-Range z silnym ETag. Brak wsparcia, zmieniony ETag lub niepoprawna
odpowiedź powodują ponowne pobranie tej części; ukończone części są zachowane.
Po restarcie lokalne pliki są ponownie hashowane. Wygasły podpisany URL jest
odświeżany przez status tego samego eksportu, bez tworzenia nowej operacji.

SDK sprawdza rozmiary, hashe z API i dostępny nagłówek storage, oddzielnie
odszyfrowuje części i rozpakowuje ZIP/TarGz na dysku. Nie materializuje paczki
ani metadanych w RAM. Zachowuje limity archiwów: 10 001 plików, 500 MB na plik,
2 GB łącznie i stosunek dekompresji do 200. Odrzuca dowiązania i niebezpieczne nazwy.

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
client = await AsyncKsef.connect(profile="firma", credentials=credentials)
async with client:
    session = await client.online_session()
    async with session:
        invoice = await (await session.send_invoice(xml_bytes)).wait()
    await session.wait()
```

Metody wykonujące HTTP wymagają `await`. Tworzenie uchwytów z lokalnego stanu,
`resume_state()` i `session.upo()` pozostają synchroniczne. Transfer eksportu
wykorzystuje osobny worker z własnym transportem; nie blokuje pętli asyncio.
Anulowanie sygnalizuje zatrzymanie i czeka na zamknięcie workera, zanim odda kontrolę.
Trwający synchroniczny odczyt sieciowy podlega skonfigurowanemu timeoutowi HTTP;
sam sygnał anulowania go nie przerywa.

Uruchamialne przykłady: [sync](examples/facade_sync.py) i [async](examples/facade_async.py).
Pomiar pamięci: `PYTHONPATH=src python tools/benchmark_streaming_export.py --directory .build/export-rss`.
