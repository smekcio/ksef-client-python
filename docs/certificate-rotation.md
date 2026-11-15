# Rotacja certyfikatu uwierzytelniającego XAdES

`ProfileCertificates` zarządza wyborem certyfikatu uwierzytelniającego
dla procesu przetwarzającego faktury. Aktywacja sprawdza ważność X.509,
zgodność klucza z certyfikatem i możliwość uzyskania tokena w KSeF dla
wskazanego profilu. Przy akceptacji może też wykonać wskazane przez
aplikację sprawdzenie uprawnień. Następnie atomowo zapisuje wybór
w lokalnym SQLite.

W przypadku certyfikatu wystawianego przez KSeF użyj typu `Authentication`.
Certyfikat `Offline` jest przeznaczony do QR II.
[Kontrakt certyfikatów CIRF](https://github.com/CIRFMF/ksef-api/blob/main/certyfikaty-KSeF.md)

## Wymiana certyfikatu

1. Dodaj nowy certyfikat i klucz pod nową nazwą w
   [FileCertificateStore](certificate-store.md). W produkcji użyj
   `FileCertificateStore(require_password=True)` i pobierz hasło z magazynu
   sekretów. Wpisy poprzedniej wersji zostaw na czas pracy uruchomionych z nią
   procesów.
2. Odczytaj bieżący wybór przez `status()`. Przekaż do `activate()` jego
   generację lub wartość `0` przy pierwszej konfiguracji. Jeżeli inna
   aktywacja zakończy się wcześniej, operacja z nieaktualną generacją zgłosi
   konflikt. Jeśli KSeF odrzuci logowanie lub sprawdzenie uprawnień,
   pozostanie poprzedni wybór.
3. Worker wywołuje `connect()` na początku cyklu i kończy cykl na tym samym
   kliencie. Kolejne cykle odczytują nowy wybór. Przed wycofaniem starego
   certyfikatu doprowadź rozpoczęte zadania do stanu, który można wznowić
   w kolejnym cyklu z tymi samymi uprawnieniami.
4. W razie potrzeby ponownie aktywuj poprzednią, wciąż ważną wersję,
   używając aktualnej generacji. Gdy zakończysz okres obserwacji,
   unieważnij poprzedni certyfikat zgodnie z procedurą wystawcy.

```python
from ksef_client.certificate_rotation import ProfileCertificates
from ksef_client.certificates import FileCertificateStore
from ksef_client.profiles import ProfileStore

profile = ProfileStore.default().get("firma-a")
store = FileCertificateStore(require_password=True)
certificates = ProfileCertificates("private/xades-selection.db", profile, store=store)

# Kod operatora. cert_password pochodzi z magazynu sekretów.
active = certificates.status().selection
selection = certificates.activate(
    "firma-a-2027",
    password=cert_password,
    expected_generation=active.generation if active else 0,
)

# Kod jednego cyklu workera. read_password pobiera hasło po nazwie wpisu.
with certificates.connect(password_for=read_password) as client:
    process_pending_invoices(client)
```

Przy uwierzytelnianiu na odcisk certyfikatu przekaż do `activate()`
wartość `subject_identifier_type="certificateFingerprint"` i upewnij się,
że nowy odcisk dostał uprawnienia w KSeF. Opcjonalny argument
`verify` przyjmuje funkcję z klientem powiązanym z nowym certyfikatem.
Użyj jej na przykład do wykonania odczytu wymaganego później przez worker.
[Uwierzytelnianie XAdES](https://github.com/CIRFMF/ksef-api/blob/main/uwierzytelnianie.md)

Monitoruj `status(warn_before=timedelta(days=30))` dla każdego profilu.
Wynik zawiera stan, aktywny odcisk i okres ważności. Odczyt jest lokalny
i odbywa się bez odszyfrowania klucza oraz bez żądania do KSeF.
Wystawca i KSeF nadal odpowiadają za status unieważnienia i uprawnienia.
Baza wyboru i magazyn kluczy powinny być dostępne wyłącznie dla operatora
i procesów KSeF. Zmieniony adres API, nazwa profilu albo kontekst tworzą
osobne powiązanie.
