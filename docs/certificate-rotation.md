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
3. Worker otwiera `session()` na początku cyklu i kończy cykl na tym samym
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
with certificates.session(password_for=read_password) as client:
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

`session()` kończy sesję uwierzytelniania po zakończeniu cyklu, również
przy błędzie. Granice cyklu ustal zgodnie z obciążeniem i limitami
uwierzytelniania KSeF, np. przetwarzaj grupę pozycji w jednym cyklu.

[Przykład workera z kolejką offline](examples/xades_offline_worker.py)
udostępnia polecenia `status`, `activate` i `run`. Każde uruchomienie
`run` wykonuje ograniczoną liczbę kroków na zaległych fakturach. Działa na
istniejącym `SQLiteOfflineInvoiceStore`, do którego aplikacja zapisuje faktury
z przestrzenią nazw równą nazwie profilu. W przykładzie proces otrzymuje hasła
w `KSEF_XADES_KEY_PASSWORDS` jako obiekt JSON mapujący nazwy certyfikatów na
ich hasła i osobny klucz kolejki w `KSEF_OFFLINE_STATE_KEY` jako Base64.
Dostarczaj je przez konfigurację sekretów używaną przez nadzorcę procesu.

Przy wymianie certyfikatu dla aktywnej kolejki zachowaj tożsamość podmiotu
uwierzytelniającego i jego uprawnienia w KSeF. Jeśli równocześnie przenosisz
integrację na inny podmiot, sprawdź przed aktywacją dostęp do rozpoczętych
sesji i uprawnienia wymagane do ich dokończenia. Samo zalogowanie w tym
samym kontekście potwierdza dostęp do kontekstu. Przykładowe
`activate --queue <plik>` dodatkowo sprawdza odczyt statusu sesji
zapisanych w kolejce. [Uprawnienia KSeF](https://github.com/CIRFMF/ksef-api/blob/main/uprawnienia.md)

Profil może wymagać weryfikacji łańcucha i zgodności podpisu XAdES.
Przekaż `verify_certificate_chain=True` i `enforce_xades_compliance=True`
do `ProfileCertificates`. Wartości obowiązują przy sprawdzaniu kandydata
i przy otwieraniu sesji workera. Użyj tych samych ustawień u operatora
i w workerze. Zmiana polityki wymaga zweryfikowania i aktywacji certyfikatu
w konfiguracji z nową polityką.

Stan `policy_mismatch` oznacza, że worker ma inne ustawienia niż ostatnia
aktywacja. Do czasu ujednolicenia konfiguracji nie zaloguje się certyfikatem
dla tego profilu. Gdy baza z wersji przed wydaniem ma kilka wyborów dla
tego samego profilu, stan `reactivation_required` wymaga jawnej aktywacji
zweryfikowanego certyfikatu z `expected_generation=0`. Udana aktywacja
usuwa stare wskazania tego profilu z bazy wyboru.

Przykładowe `run` podaje błędy poszczególnych pozycji w `failures` i zwraca
`next_cursor`. Do następnego uruchomienia przekaż pola kursora przez
`--after-due-at` i `--after-hash`. Gdy `next_cursor` jest pusty, zacznij
kolejną rundę od początku. Nowe pozycje mogą otworzyć sesję i wysłać
fakturę w tym samym cyklu.
