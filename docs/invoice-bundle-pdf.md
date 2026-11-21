# Podgląd PDF faktur FA(3) i UPO

Generator MF jest dostępny w wersji rozwojowej repozytorium. Do czasu kolejnego wydania
zainstaluj SDK z lokalnej kopii przez `pip install -e ".[cli]"` i zapewnij Node.js 22 lub nowszy.
Nowe polecenia `invoice render` i `upo render` korzystają domyślnie z MF.
API Pythona `render_invoice_pdf(xml)` i `bundle.save(path)` domyślnie korzysta z ReportLab.

## Podgląd lokalny ReportLab

Pakiet wysyłki zawiera oryginalny XML i czytelny PDF do podglądu dokumentu. Zainstaluj `pip install "ksef-client[cli,pdf]"`, aby utworzyć pakiet w CLI. Sam moduł Pythona wymaga `pip install "ksef-client[pdf]"`.

```python
from pathlib import Path

from ksef_client.invoice_pdf import render_invoice_pdf

xml = Path("faktura.xml").read_bytes()
Path("faktura.pdf").write_bytes(render_invoice_pdf(xml))
```

Opcjonalny argument `ksef_number` służy do pokazania numeru nadanego przez KSeF. Eksport pakietu podstawia numer z zapisanego stanu wysyłki. Oryginałem pozostaje dołączony XML. PDF służy do odczytu zawartości i nie poświadcza przyjęcia faktury ani jej zgodności ze schemą. Potwierdzenie pochodzi z UPO.

Pierwsza część PDF pokazuje numer, datę wystawienia, dostępne nazwy stron i należność z walutą. Dalej widoczne są pola dokumentu w kolejności XML, również pozycje, płatności, odwołania do faktur korygowanych i dane załączników. Pola zrozumiałe dla użytkownika mają polskie etykiety. Pozostałe zachowują nazwy ze schemy. Wartości kwot i stawek pochodzą z pliku źródłowego. Generator zgłasza błąd przy powtórzonych polach podsumowania i przy treści mieszanej, której nie może wiernie pokazać.

Wizualizacja powstaje lokalnie, również bez sesji KSeF. Generator osadza font z polskimi znakami. Znaki spoza repertuaru fontu przedstawia kodem Unicode w nawiasach kwadratowych. Układ służy do podglądu danych i nie stanowi wzoru wizualizacji MF do przekazywania faktur poza KSeF. Funkcja obsługuje przestrzeń nazw FA(3), odrzuca DTD i ogranicza koszt przetwarzania do 20 MiB XML, 100 000 elementów i atrybutów łącznie, 64 poziomów, 65 536 znaków w pojedynczym polu i 500 stron. Przekroczenie limitu zgłasza błąd przed zwróceniem PDF.

## Oficjalny generator MF

Pakiet zawiera generator CIRFMF 1.1.48. Renderowanie MF wymaga lokalnego Node.js 22 lub nowszego.
CLI instalujesz przez `pip install "ksef-client[cli]"`. Samo SDK zawiera moduł JavaScript i fonty.
Proces renderujący otrzymuje oryginalny XML oraz metadane wizualizacji. Klucz certyfikatu obsługuje Python.

```python
import os
from pathlib import Path

from ksef_client import KsefClientOptions, KsefEnvironment
from ksef_client.invoice_pdf import InvoicePdfContext, render_invoice_pdf, render_upo_pdf
from ksef_client.services.xades import XadesKeyPair

xml = Path("faktura.xml").read_bytes()
options = KsefClientOptions(base_url=KsefEnvironment.TEST.value)
Path("podglad.pdf").write_bytes(render_invoice_pdf(xml, renderer="mf"))

# Dla faktury z przydzielonym numerem KSeF.
accepted = InvoicePdfContext.accepted(options, os.environ["KSEF_NUMBER"])
Path("faktura.pdf").write_bytes(render_invoice_pdf(xml, renderer="mf", context=accepted))

# Dla faktury offline przed nadaniem numeru. Użyj jej oryginalnego XML.
signer = XadesKeyPair.from_pem_files(
    certificate_path="certyfikat-offline.pem",
    private_key_path="klucz-offline.pem",
    private_key_password=os.environ.get("KSEF_PDF_KEY_PASSWORD"),
)
offline = InvoicePdfContext.offline(options, "Nip", os.environ["KSEF_NIP"], signer)
Path("offline.pdf").write_bytes(render_invoice_pdf(xml, renderer="mf", context=offline))
Path("upo.pdf").write_bytes(render_upo_pdf(Path("upo.xml").read_bytes()))
```

Kontekst `InvoicePdfContext.accepted(...)` generuje jeden QR z numerem KSeF. Dotyczy to
również faktury wystawionej offline po nadaniu jej numeru. Kontekst `InvoicePdfContext.offline(...)`
generuje przed nadaniem numeru dwa QR z podpisami OFFLINE i CERTYFIKAT.
Wywołanie z samym `xml` tworzy podgląd. Argument `ksef_number` bez kontekstu dodaje numer do treści PDF. Linki korzystają ze skrótu oryginalnych bajtów XML i wybranego
środowiska. UPO 4.2 i 4.3 można renderować indywidualnie lub jako część zbiorczego poświadczenia.
Renderowanie UPO zachowuje wszystkie dokumenty dostarczonej części. Budżet UPO wynosi 32 MiB XML,
300 000 elementów i atrybutów oraz 10 000 faktur. Proces MF ma limit 120 sekund i 64 MiB wyjściowego PDF.
Faktury mają limit 20 MiB XML i 100 000 elementów i atrybutów.

```bash
ksef invoice render faktura.xml --out podglad.pdf
ksef invoice render faktura.xml --ksef-number NUMER --env TEST --out faktura.pdf
ksef --profile firma invoice render faktura.xml --offline --cert-pem cert.pem --key-pem key.pem --out offline.pdf
ksef upo render upo.xml --out upo.pdf
ksef online bundle --id FV-123 --state-dir ./private --pdf-renderer mf --out FV-123-mf.zip
```

Hasło klucza PEM lub PKCS#12 podaj przez `KSEF_PDF_KEY_PASSWORD` albo `--key-password`.
Dla PKCS#12 użyj `--pkcs12-path`. Renderowanie lokalnych plików działa bez sesji KSeF.
Tryb offline korzysta z kontekstu zapisanego profilu.

Eksport MF tworzy manifest v2 z wersją i commitem generatora oraz SHA-256 plików.
Jeżeli dostępne jest indywidualne UPO, ZIP zawiera również `upo.pdf`. Błąd generatora przerywa
zapis ZIP. Bezpośrednio tworzona `OnlineInvoiceQueue` powinna dostać `options=options`, aby
zbudować QR przyjętej faktury w środowisku zgodnym z kolejką. Dla asynchronicznej fasady
zapis wykonaj przez `await asyncio.to_thread(bundle.save, path, pdf_renderer="mf")`.

## Aktualizacja generatora

Źródłem wersji jest `src/ksef_client/_mf_pdf/upstream.json`. Ustaw nowy tag, pełny commit i wersję,
a następnie uruchom `python tools/build_mf_pdf.py` narzędziami Node/npm zapisanymi w manifeście.
`python tools/build_mf_pdf.py --check` sprawdza zgodność z odbudowanym modułem. Przy aktualizacji
przejrzyj licencje generatora, zależności i fontów oraz porównaj wzorcowe PDF-y i odczyt QR.

Workflow MF PDF integration sprawdza renderowanie na Windows i Linux oraz odtwarzalność modułu.
Codzienny monitoring o 06:15 UTC tworzy issue dla każdego stabilnego wydania nowszego od przypiętej
wersji. Ręczne uruchomienie domyślnie korzysta z `dry_run`. Zamknięte zgłoszenia są uwzględniane
przy wykrywaniu duplikatów. Workflow `Watch MF PDF generator releases` możesz uruchomić
ręcznie w GitHub Actions z `dry_run=true`, aby zobaczyć planowane zgłoszenia.
Wydania przedpremierowe są pomijane. Błąd GitHuba kończy przebieg błędem, a kolejne uruchomienie
wznawia zgłaszanie brakujących wersji.

## Błędy i zapis plików

Błędny XML i sprzeczne numery weryfikacyjne zgłaszają `KsefDocumentValidationError`.
Błąd procesu, przekroczenie czasu lub rozmiaru PDF zgłasza `KsefRenderingError`.
Generator MF wymaga działającego polecenia `node` w `PATH`.
CLI kończy się kodem 2 przy błędnych danych, 6 przy błędzie generatora lub brakujących zależnościach
i 8 przy błędzie odczytu lub zapisu. Plik docelowy musi być nowy, a katalog docelowy musi istnieć.

Dla wybranego `renderer="mf"` błąd przerywa operację. W ZIP MF obecność UPO oznacza zarówno
oryginalny `upo.xml`, jak i jego wizualizację `upo.pdf`. Status `pending` lub `unavailable`
opisuje brak źródłowego UPO. Szczegóły opisuje [format pakietu](workflows/cli-operations.md#lokalny-pakiet-faktury-i-upo).
