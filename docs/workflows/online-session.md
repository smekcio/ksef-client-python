# Workflow: sesja interaktywna (online)

Scenariusz obejmuje: otwarcie sesji, serializację lekkiego stanu JSON, wznowienie po restarcie procesu,
wysyłkę jednej lub wielu faktur, sprawdzanie statusów, zamknięcie sesji oraz pobranie UPO.

Rekomendowane podejście:
- `OnlineSessionWorkflow.open_session()` do otwarcia sesji,
- `OnlineSessionHandle` do dalszych operacji na sesji,
- `OnlineSessionWorkflow.resume_session()` do wznowienia z `OnlineSessionState`.

## Przykład (sync, z resume)

```python
import time

from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment, models as m
from ksef_client.services import AuthCoordinator, OnlineSessionState, OnlineSessionWorkflow

KSEF_TOKEN = "<TOKEN_KSEF>"
CONTEXT_TYPE = "nip"
CONTEXT_VALUE = "5265877635"
INVOICE_XML = b"""<Invoice>...</Invoice>"""

FORM_CODE = m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")

# Proces 1: auth + open + zapis lekkiego stanu JSON
with KsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
    token_cert = client.security.get_public_key_certificate_pem(
        m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
    )
    sym_cert = client.security.get_public_key_certificate_pem(
        m.PublicKeyCertificateUsage.SYMMETRICKEYENCRYPTION,
    )

    access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
        token=KSEF_TOKEN,
        public_certificate=token_cert,
        context_identifier_type=CONTEXT_TYPE,
        context_identifier_value=CONTEXT_VALUE,
        max_attempts=90,
        poll_interval_seconds=2.0,
    ).access_token

    workflow = OnlineSessionWorkflow(client.sessions)
    session = workflow.open_session(
        form_code=FORM_CODE,
        public_certificate=sym_cert,
        access_token=access_token,
        upo_v43=False,
    )
    state_json = session.get_state().to_json()

# Proces 2: nowy klient + resume z JSON
state = OnlineSessionState.from_json(state_json)

with KsefClient(
    KsefClientOptions(base_url=KsefEnvironment.DEMO.value),
    access_token=access_token,
) as client:
    workflow = OnlineSessionWorkflow(client.sessions)
    session = workflow.resume_session(state)

    send = session.send_invoice(INVOICE_XML)
    invoice_reference = send.reference_number

    for _ in range(60):
        status = session.get_invoice_status(invoice_reference)
        code = int(status.status.code)
        if code == 200:
            break
        if code not in {100, 150}:
            raise RuntimeError(status.to_dict())
        time.sleep(2)

    session.close()

print("OK")
```

## Kontrakt stanu SDK

`OnlineSessionState` serializuje wyłącznie dane potrzebne do wznowienia sesji:
- `schema_version`
- `kind="online"`
- `reference_number`
- `form_code`
- `valid_until`
- `symmetric_key_base64`
- `iv_base64`
- `upo_v43`

Nie są serializowane:
- `access_token`
- XML faktur
- wynik wysyłki / `invoice_reference`

Oznacza to, że po wznowieniu musisz nadal mieć ważny token dostępu:
- przekazany jawnie do `resume_session(..., access_token=...)`, albo
- ustawiony na kliencie: `KsefClient(..., access_token=...)`.

## Publiczne API handle'a

`OnlineSessionHandle` udostępnia:
- `reference_number`
- `session_reference_number` jako alias kompatybilności
- `valid_until`
- `form_code`
- `encryption_data`
- `get_state()`
- `send_invoice()`
- `get_status()`
- `list_invoices()`
- `list_failed_invoices()`
- `get_invoice_status()`
- `get_invoice_upo_by_ref()`
- `get_invoice_upo_by_ksef()`
- `get_upo()`
- `close()`

Zgodność wsteczna:
- `OnlineSessionResult` pozostaje aliasem do `OnlineSessionHandle`,
- kod używający `session_reference_number` i `encryption_data` nadal działa.

## Uwagi

- `encryption_data` z `open_session()` musi być użyte dla wszystkich faktur wysyłanych w ramach tej sesji; dlatego jest odtwarzane również przy `resume_session()`.
- `resume_session()` odtwarza tylko stan sesji i materiał kryptograficzny. Statusy faktur wysłanych wcześniej trzeba śledzić osobno przez `invoice_reference`.
- Dla `FA_RR (1)` w wersji `1-1E` przekazuj `formCode.value="FA_RR"`.
- Status przetwarzania jest udostępniany asynchronicznie; sprawdzanie statusu odbywa się przez polling.
- Pobranie UPO:
  - dla faktury: `get_invoice_upo_by_ref()` / `get_invoice_upo_by_ksef()`
  - dla sesji: `get_upo()`
- `upo_v43=True` dodaje nagłówek `X-KSeF-Feature: upo-v4-3` przy otwieraniu sesji.
- `AsyncOnlineSessionWorkflow` i `AsyncOnlineSessionHandle` oferują lustrzane API asynchroniczne.

## Trwała wysyłka online

W terminalu `ksef send online --local-id ID --state-dir KATALOG --invoice PLIK` zapisuje wysyłkę pod własnym ID. [Wznowienie i indywidualne UPO w CLI](cli-operations.md#wysyłka-online-po-własnym-id)

Do automatycznej wysyłki z możliwością wznowienia zapisz oryginalny XML
pod stałym identyfikatorem swojej aplikacji. Wybierz prywatny katalog dla
SQLite i przechowuj losowy klucz 32-bajtowy oddzielnie, w magazynie sekretów.

```python
from ksef_client.online_invoices import OnlineInvoiceStatus, SQLiteOnlineInvoiceStore

# client to uwierzytelniony klient Ksef. Klucz i identyfikator pochodzą z aplikacji.
with SQLiteOnlineInvoiceStore.open("private/online.db", key=archive_key) as store:
    invoices = client.invoices.online(store, namespace="company")
    current = invoices.enqueue("FV-123", invoice_xml_bytes)

    # Jeden krok. Kolejny cykl harmonogramu wykonuje advance na tym samym ID.
    current = invoices.advance("FV-123", timeout=60)
    if current.status is OnlineInvoiceStatus.COMPLETE:
        upo_xml = invoices.read_upo("FV-123")
        print(current.ksef_number)
```

Po instalacji `pip install "ksef-client[pdf]"` możesz zapisać pakiet dokumentów z tej samej kolejki.

```python
with SQLiteOnlineInvoiceStore.open("private/online.db", key=archive_key) as store:
    invoices = client.invoices.online(store, namespace="company")
    bundle = invoices.bundle("FV-123")
    bundle.save("private/FV-123.zip")
    print(bundle.invoice.ksef_number, bundle.upo_status)
```

`OnlineInvoiceQueue.bundle()` działa lokalnie, także bez zalogowanego klienta. W `AsyncKsef` pobierz migawkę przez `await invoices.bundle("FV-123")`. Zapis PDF i ZIP wykonaj przez `await asyncio.to_thread(bundle.save, path)`. Oryginalne bajty są w `bundle.xml` i opcjonalnym `bundle.upo`. Zapis używa nowej ścieżki w istniejącym katalogu. [Format pakietu i statusy UPO](cli-operations.md#lokalny-pakiet-faktury-i-upo)

Ta sama kombinacja bazy, klucza, środowiska, kontekstu i namespace po restarcie
odczytuje zapisany stan. Ponowne zgłoszenie tego samego ID z tymi samymi bajtami
zwraca bieżący stan. Ten sam identyfikator z innym XML lub zgłoszenie identycznego
XML pod innym ID w tym samym zakresie powoduje konflikt. Próby, XML, klucze sesji
i UPO są zapisywane w lokalnym szyfrowanym archiwum. ID jest indeksowane przez
HMAC, w bazie widoczne są skróty XML i metadane potrzebne do transakcji.

Po timeoutcie wysyłki odczytaj status przed kolejnym krokiem. Stan
SUBMISSION_UNKNOWN oznacza, że SDK sprawdzi zapisaną sesję i dokładny skrót XML,
dopóki wynik nie będzie znany. Sam brak pozycji w chwilowej odpowiedzi z KSeF
nie upoważnia do wysłania faktury ponownie. Jawne retry_if_unsubmitted wymaga
zamkniętej sesji z potwierdzoną liczbą zero faktur i pełnego, pustego odczytu listy.
Po potwierdzonym anulowaniu przetwarzania przez KSeF (kod 550) użyj retry_cancelled,
aby ponownie zakolejkować oryginalny dokument. Odrzucenie i duplikat mają odrębne
stany. Dla zaakceptowanej faktury SDK zamyka sesję i pobiera indywidualne UPO 4.2
lub 4.3 z limitem 1 MiB. Przed zapisaniem potwierdzenia sprawdza numer sesji, numer
KSeF i skrót oryginalnego XML. Weryfikację podpisu XAdES ministerstwa wykonaj osobno,
jeśli jest potrzebna w Twoim procesie.

Jeśli po otwarciu sesji zabraknie odpowiedzi, rezerwacja otwarcia musi wygasnąć.
Sesja bez zapisanego numeru nie zostanie użyta do wysyłki. KSeF może zachować
taką pustą sesję do jej wygaśnięcia. Procesy synchronizują się przy użyciu tej
samej bazy, a timeout pojedynczego kroku nie cofa żądania już przekazanego
do KSeF. Ustawiaj harmonogram zgodnie z Retry-After.

Transport używany przez klienta musi odpowiadać środowisku kolejki oraz mieć
wyłączone automatyczne przekierowania i powtórzenia żądań POST sesji online.
Kolejka używa zarządzanej autoryzacji i hosta z adresu API. Gdy POST sesji
zwróci 401, klient może odświeżyć token i zwraca błąd tego żądania.
Kolejny krok korzysta z odświeżonego tokena. Domyślny mechanizm odświeżania
wymaga tego samego transportu, którego używa kolejka. Przy zmianie klienta
wznów pracę kolejki z klientem, do którego jest dołączony menedżer tokenów.

Po odtworzeniu kopii sprzed próby wysłania najpierw uzgodnij stan z KSeF.
Starsza kopia może nie zawierać informacji o fakturach zapisanych już w KSeF.
W AsyncKsef użyj AsyncSQLiteOnlineInvoiceStore i await dla metod kolejki.

[Oficjalna dokumentacja statusu faktury i UPO](https://github.com/CIRFMF/ksef-api/blob/main/faktury/sesje/sesja-sprawdzenie-stanu-i-pobranie-upo.md)

## Trwała wysyłka offline

`client.invoices.offline(...)` wiąże lokalną kolejkę z uwierzytelnionym
środowiskiem i kontekstem. Klucz 32-bajtowy dostarcza aplikacja z własnego
magazynu sekretów. Używaj prywatnego katalogu i osobnego połączenia dla
każdego workera. Przy restarcie użyj tej samej bazy, klucza i namespace.

```python
from ksef_client.offline_invoices import (
    OfflineInvoiceQueue,
    OfflineInvoiceStatus,
    SQLiteOfflineInvoiceStore,
)

# Wystawienie i podpisanie linku może odbyć się przy niedostępnym KSeF.
with SQLiteOfflineInvoiceStore.open("private/offline.db", key=archive_key) as store:
    queue = OfflineInvoiceQueue(
        store, options=options, context_type="Nip", context_value=company_nip,
        namespace="company",
    )
    entry = queue.enqueue(invoice_xml_bytes, due_at=application_due_at)
    invoice_hash = entry.progress.invoice_hash
    links = queue.verification_links(invoice_hash, offline_signing_key_pair)

# Po odzyskaniu połączenia, wewnątrz kontekstu zalogowanego klienta.
with SQLiteOfflineInvoiceStore.open("private/offline.db", key=archive_key) as store:
    outbox = client.invoices.offline(store, namespace="company")
    # Jeden krok workera. Kolejne kroki wykonuje harmonogram aplikacji.
    entry = outbox.advance(invoice_hash)
    if entry.progress.status is OfflineInvoiceStatus.COMPLETE:
        upo_xml = outbox.read_upo(invoice_hash)
```

Termin jest znacznikiem UTC wyliczonym przez aplikację na podstawie trybu
offline i obowiązujących komunikatów KSeF. Wybór zapisuje parametr `mode`
(`OfflineInvoiceMode.OFFLINE24`, `UNAVAILABLE` albo `EMERGENCY`). `pending()` zwraca ograniczoną
stronę aktywnych dokumentów w kolejności terminów. Do kolejnej strony przekaż
ostatnią parę `(due_at, invoice_hash)` jako `after`. Gdy aplikacja otrzyma aktualizację terminu,
wywołaj `reschedule(invoice_hash, due_at=..., expected_revision=entry.revision)`.
W razie konfliktu odczytaj bieżący wpis przed ponowieniem aktualizacji. Każde `advance()`
wykonuje jeden krok. Wywołuj je ponownie z harmonogramu aplikacji, uwzględniając
`Retry-After` i zachowując czas na przetworzenie kolejnych dokumentów.

W razie utraty odpowiedzi na POST stan `submission_unknown` pozostaje na dysku.
Worker sprawdza zapisany numer sesji i dokładny skrót dokumentu. Pusta lista
faktur nie wystarcza do ponownej wysyłki. `retry_if_unsubmitted()` może
zamknąć otwartą sesję i zwolnić wpis dopiero po tym, jak KSeF potwierdzi
anulowanie sesji, liczbę zero faktur i pustą pełną listę dokumentów.
Po stanie `accepted` kolejne wywołania `advance()` zamykają sesję,
czekają na jej przetworzenie i zapisują indywidualne UPO. Harmonogram wywołuje
`advance()` do stanu `complete`, po którym `read_upo(invoice_hash)` odczytuje
lokalny dokument. Dokument zwrócony przez KSeF jako duplikat ma stan `duplicate`. Odrębnym przypadkiem jest kod 550, czyli potwierdzone
anulowanie przetwarzania przez KSeF. Stan `retryable` pozostaje w kolejce.
Po odczekaniu okresu wybranego przez aplikację wywołaj `retry_cancelled(invoice_hash)`.
SDK zachowa szyfrowany zapis poprzedniej próby i kolejny cykl użyje oryginalnego XML-a.
Podczas otwierania sesji worker ma czasową rezerwację wpisu.
Jeśli proces przerwie pracę przed zapisaniem referencji, inny worker może
przejąć wpis po wygaśnięciu rezerwacji.

Korektę techniczną dodaj jako nowy XML z argumentem
`correction_of=original_invoice_hash`, po zapisaniu odrzucenia oryginału.
Jeśli próba korekty została jednoznacznie odrzucona, wskaż ten sam oryginał
w następnej korekcie. Weryfikacja, że poprawka zachowuje treść faktury, należy do aplikacji.
Kody QR pochodzą z oryginalnych bajtów FA(3). SDK sprawdza użycie klucza,
ważność oraz zgodność klucza z certyfikatem offline. Stan odwołania i uprawnienia
wystawcy zależą od rejestru KSeF.

W `AsyncKsef` użyj `AsyncSQLiteOfflineInvoiceStore` i `await` dla operacji
kolejki. Oryginalne XML, UPO i stan sesji są szyfrowane lokalnie. Kopia
sprzed wysłania dokumentu nie zawiera informacji o tej próbie, więc po
odtworzeniu takiej kopii sprawdź stan KSeF przed ponownym uruchomieniem workerów.

[Tryby offline](https://github.com/CIRFMF/ksef-api/blob/ce3670e/tryby-offline.md)
· [Kody QR](https://github.com/CIRFMF/ksef-api/blob/ce3670e/kody-qr.md)
· [Korekta techniczna](https://github.com/CIRFMF/ksef-api/blob/ce3670e/offline/korekta-techniczna.md)

### Weryfikacja z KSeF TEST

Z ustawionymi `KSEF_E2E=1`, `KSEF_TEST_TOKEN`, `KSEF_TEST_CONTEXT_TYPE=Nip` i
`KSEF_TEST_CONTEXT_VALUE` uruchom:

```shell
python -m pytest -q tests/test_e2e_offline_queue.py
```

Test zapisuje fakturę w kolejce przed uwierzytelnieniem, wznawia pracę z zapisaną
sesją, przesyła oryginalny XML do KSeF TEST i weryfikuje zapisane UPO.
