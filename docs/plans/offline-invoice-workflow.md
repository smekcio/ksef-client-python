# Trwały przepływ faktur offline

Aplikacja jawnie wybiera tryb offline oraz przekazuje oryginalny XML i termin wysyłki. SDK używa istniejących mechanizmów FA(3), QR, certyfikatów i sesji interaktywnej. Przechowuje stan potrzebny do bezpiecznego podjęcia pracy po restarcie, z tym samym publicznym kontraktem sync i async.

## Przebieg

- Zapis lokalny utrwala oryginalne bajty, SHA-256, tryb, termin oraz tożsamość środowiska i kontekstu. Wystawienie poza KSeF zwraca dane do KOD I i KOD II. Przed podpisaniem należy sprawdzić typ i ważność certyfikatu offline oraz zgodność jego klucza. Klucz podpisujący otrzymuje się od aplikacji.
- Worker zapisuje referencję nowej sesji przed wysłaniem faktury. Przed POST utrwala dowód rozpoczęcia próby. Po utracie odpowiedzi sprawdza tę samą sesję i wyszukuje dokument po hash. Niepewny wynik pozostaje jawny, dopóki nie ma rozstrzygającego dowodu. Ten stan nie prowadzi automatycznie do ponownej wysyłki.
- Po przyjęciu worker zapisuje numer KSeF, finalizuje sesję i pobiera UPO. Każdy z tych kroków można wznowić z zapisanych referencji. Porażka pobrania UPO zachowuje numer KSeF i pozwala ponowić wyłącznie odczyt.
- Korekta techniczna jest odrębnym dokumentem związanym z odrzuconym oryginałem. Korzysta z jego skrótu jako hashOfCorrectedInvoice i ustawia offlineMode. Wydanie korekty wymaga jawnej decyzji aplikacji i nowego XML.
- Lokalna baza koordynuje workerów przez transakcje i warunkowe przejścia stanu. Po utracie dzierżawy starszy wykonawca nie nadpisuje późniejszych ustaleń. Raporty pokazują stany, terminy i dozwolone kody bez kluczy, XML ani poufnych parametrów operacji.

## Odbiór

Odtworzyć restart przed POST, utratę odpowiedzi po przyjęciu przesyłki, konkurencję workerów, odrzucenie z korektą i restart między otrzymaniem numeru a pobraniem UPO. Sprawdzić odmowę niewłaściwego lub wygasłego certyfikatu oraz rozdzielenie środowisk i kontekstów.

Źródła: [tryby offline](https://github.com/CIRFMF/ksef-api/blob/ce3670e/tryby-offline.md) i [korekta techniczna](https://github.com/CIRFMF/ksef-api/blob/ce3670e/offline/korekta-techniczna.md).
