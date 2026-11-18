# Workflow: sesja wsadowa (batch)

Scenariusz obejmuje: przygotowanie ZIP albo TarGz z wieloma XML, podział na części <=100MB, szyfrowanie,
otwarcie sesji wsadowej, serializację lekkiego stanu JSON, wznowienie po restarcie procesu,
wysyłkę brakujących partów na pre-signed URL oraz zamknięcie sesji.

Rekomendowane podejście:
- `BatchSessionWorkflow.open_session()` do otwarcia sesji,
- `BatchSessionHandle.upload_parts()` do wysyłki partów,
- `BatchSessionWorkflow.resume_session()` do wznowienia z `BatchSessionState`,
- `BatchSessionWorkflow.open_upload_and_close()` jako one-shot convenience API bez resume.

## Przykład (sync, z resume)

```python
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment, models as m
from ksef_client.services import AuthCoordinator, BatchSessionState, BatchSessionWorkflow
from ksef_client.utils import build_tar_gz, build_zip

KSEF_TOKEN = "<TOKEN_KSEF>"
CONTEXT_TYPE = "nip"
CONTEXT_VALUE = "5265877635"

FORM_CODE = m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")

zip_bytes = build_zip(
    {
        "invoice1.xml": b"""<Invoice>...</Invoice>""",
        "invoice2.xml": b"""<Invoice>...</Invoice>""",
    }
)

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

    workflow = BatchSessionWorkflow(client.sessions, client.http_client)
    session = workflow.open_session(
        form_code=FORM_CODE,
        zip_bytes=zip_bytes,
        public_certificate=sym_cert,
        access_token=access_token,
        offline_mode=None,
        upo_v43=False,
    )
    state_json = session.get_state().to_json()

    # KSeF API 2.6.0 dopuszcza także TarGz jako alternatywny format archiwum.
    tar_gz_bytes = build_tar_gz({"invoice1.xml": b"""<Invoice>...</Invoice>"""})
    session_targz = workflow.open_session(
        form_code=FORM_CODE,
        archive_bytes=tar_gz_bytes,
        compression_type=m.CompressionType.TARGZ,
        public_certificate=sym_cert,
        access_token=access_token,
    )

# Proces 2: nowy klient + resume z JSON i tym samym ZIP-em
state = BatchSessionState.from_json(state_json)

with KsefClient(
    KsefClientOptions(base_url=KsefEnvironment.DEMO.value),
    access_token=access_token,
) as client:
    workflow = BatchSessionWorkflow(client.sessions, client.http_client)
    session = workflow.resume_session(state, zip_bytes=zip_bytes)
    session.upload_parts(parallelism=4)
    session.close()

print(session.reference_number)
```

## Kontrakt stanu SDK

`BatchSessionState` serializuje wyłącznie dane potrzebne do wznowienia sesji i odtworzenia uploadu:
- `schema_version`
- `kind="batch"`
- `reference_number`
- `form_code`
- `batch_file`
- `part_upload_requests`
- `symmetric_key_base64`
- `iv_base64`
- `upo_v43`
- `offline_mode`

Nie są serializowane:
- `access_token`
- ZIP wsadowy
- XML faktur
- ścieżka do pliku / katalogu źródłowego
- lista już wysłanych ordinals

To rozróżnienie jest celowe:
- stan SDK pozostaje lekki i przenośny,
- pełny checkpoint operacyjny dla batch resume wymaga dodatkowego zapisania źródła payloadu i
  listy `uploaded_ordinals`; robi to CLI pod `ksef session ...`.

## Publiczne API handle'a

`BatchSessionHandle` udostępnia:
- `reference_number`
- `session_reference_number` jako alias kompatybilności
- `form_code`
- `batch_file`
- `part_upload_requests`
- `encryption_data`
- `get_state()`
- `upload_parts()`
- `get_status()`
- `list_invoices()`
- `list_failed_invoices()`
- `get_upo()`
- `invoice_outcomes(manifest)`
- `close()`

## Wynik każdej faktury w paczce

W terminalu wynik dla każdego pliku wyświetla `ksef session batch report --id ID`. [Raport paczki w CLI](cli-operations.md#raport-faktur-z-paczki)

Przygotuj archiwum wraz z manifestem. Manifest zapisuje nazwy plików i SHA-256
oryginalnych dokumentów oraz rozmiar i SHA-256 archiwum. Można go odtworzyć z
`manifest.to_dict()` przez `BatchInvoiceManifest.from_dict(...)`. Przechowuj go
obok stanu sesji w magazynie aplikacji. Przy tworzeniu nowej paczki nazwy plików mają limit 128 znaków
z kontraktu KSeF i mogą zawierać dane firmowe.

```python
from ksef_client.batch_outcomes import BatchInvoiceManifest, prepare_invoice_batch

prepared = prepare_invoice_batch({"first.xml": first_xml, "second.xml": second_xml})
manifest_data = prepared.manifest.to_dict()

with client.batch_session(
    prepared.archive_bytes, compression_type=prepared.compression_type
) as session:
    session.upload_parts(parallelism=4)
    # Zapisuj też checkpoint uploadu zgodnie z opisem wyżej.
    session.close()
    state = session.resume_state()

# Po restarcie użyj uwierzytelnionego klienta dla tego samego kontekstu.
resumed = client.resume_session(state)
manifest = BatchInvoiceManifest.from_dict(manifest_data)
report = resumed.invoice_outcomes(manifest)

for entry in report.invoices:
    print(entry.invoice.file_name, entry.disposition.value, entry.status_code, entry.ksef_number)
```

Raport działa na uchwytach `BatchSessionHandle` i `AsyncBatchSessionHandle` oraz
na sesji wsadowej z fasady `Ksef` lub `AsyncKsef`. Dla fasady asynchronicznej
użyj `await session.invoice_outcomes(manifest)`. Po wznowieniu odczyt raportu
wymaga stanu sesji i manifestu, bez załączania archiwum do klienta. Zachowane
archiwum nadal jest potrzebne do wznowienia transferu.
Własny adapter sesji musi udostępniać `validated` z metodami
`get_session_status` i `get_session_invoices`, które sprawdzają odpowiedzi KSeF.

Wyniki są zwracane w kolejności manifestu.
`accepted` oznacza status 200 i prawidłowy numer KSeF, `rejected` potwierdzone
odrzucenie, `duplicate` duplikat, `cancelled` potwierdzone anulowanie faktury
przez KSeF (550), a `unresolved` brak jednoznacznego wyniku. Dla sesji w toku
wywołaj metodę ponownie po uzyskaniu statusu 200 lub 445. W przypadku
mieszanych wyników możesz odczytać raport także wtedy, gdy `Session.wait()`
zgłosi odrzucenie części faktur.

SDK wiąże odpowiedzi z dokumentami po SHA-256 XML. Jeżeli KSeF podaje nazwę pliku,
musi ona wskazywać ten sam dokument. Wynik bez nazwy wymaga jednego dopasowania
skrótu w manifeście. Niekompletny raport, niespójność liczników, konflikt
identyfikatorów, numer porządkowy spoza zakresu paczki albo przerwana
paginacja wyłączają obie listy kandydatów. Pusty token kończy paginację.
Błędy HTTP są przekazywane do wywołującego. `page_size` i `max_pages`
ograniczają liczbę odczytów jednego raportu.

- `report.correction_candidates` udostępnia pozycje do sprawdzenia i poprawy
  po błędzie weryfikacji pliku (430) lub semantyki faktury (450). Błędy sesji,
  uprawnień, obsługi załączników i odszyfrowania pozostają widoczne jako
  `rejected` z kodem błędu i wymagają wyjaśnienia przyczyny przed ponowieniem.
- `report.retry_candidates` udostępnia pozycje, których anulowanie KSeF
  potwierdził kodem 550. Listy pomijają dokumenty o skrócie współdzielonym
  z innym dokumentem tej paczki.

Raport niczego nie wysyła. Jeżeli zdecydujesz się ponowić wysyłkę, przygotuj
nową paczkę z wybranych dokumentów. Zachowaj wyniki poprzedniej sesji, razem
z jej referencją i numerami KSeF.

[Korelacja wyników w dokumentacji KSeF](https://github.com/CIRFMF/ksef-api/blob/main/sesja-wsadowa.md)

## Resume i walidacja źródła batch

`resume_session(state, zip_bytes=...)` odtwarza zaszyfrowane party z podanego ZIP-a i porównuje
odtworzone `BatchFileInfo` z danymi zapisanymi w `BatchSessionState`.
Przy TarGz użyj `resume_session(state, archive_bytes=..., compression_type=m.CompressionType.TARGZ)`.

Jeśli ZIP różni się od oryginału, workflow przerywa działanie błędem i nie próbuje uploadu.

To oznacza, że po restarcie procesu musisz zachować:
- ten sam ZIP/TarGz wejściowy, albo
- ten sam katalog źródłowy, z którego ponownie zbudujesz identyczny ZIP.

## Upload częściowy i checkpointing

`BatchUploadHelper.upload_parts()` oraz `BatchSessionHandle.upload_parts()` obsługują:
- `skip_ordinals`
- `progress_callback`

To pozwala budować własny checkpointing wokół SDK, np. zapisywać numer partu po każdym sukcesie
i po wznowieniu wywołać:

```python
session.upload_parts(skip_ordinals={1, 2, 3}, parallelism=4)
```

CLI wykorzystuje dokładnie ten mechanizm i zapisuje `uploaded_ordinals` w lokalnym checkpointcie.

## Uwagi

- Wysyłka partów odbywa się na pre-signed URL: bez Bearer tokena.
- Limit czasu wysyłki w sesji wsadowej wynosi liczba partów x 20 minut na każdy part.
- Podział ZIP musi nastąpić przed szyfrowaniem; biblioteka wykonuje to w `encrypt_batch_parts()`.
- Korelacja statusów z plikami źródłowymi jest możliwa przez zapisanie hashy SHA-256 faktur i
  mapowanie ich na identyfikatory w procesie weryfikacji (`invoiceHash`).
- `AsyncBatchSessionWorkflow` i `AsyncBatchSessionHandle` oferują lustrzane API asynchroniczne.
