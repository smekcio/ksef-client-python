# ZIP/TarGz i podział partów (`ksef_client.utils.zip_utils`)

## `MAX_BATCH_PART_SIZE_BYTES`

Stała: `100_000_000` (100 MB dziesiętnie) – limit KSeF dla części paczki wsadowej
**przed** zaszyfrowaniem („Maksymalny dozwolony rozmiar części przed zaszyfrowaniem
to 100MB"). Wcześniejsza wartość `100 * 1024 * 1024` (100 MiB) pozwalała wysłać część
o ~4,9% większą niż dozwolona — KSeF odrzucał ją komunikatem
„Rozmiar części 1 przekroczył dozwolony rozmiar 100MB".

## `build_zip(files: dict[str, bytes]) -> bytes`

Buduje ZIP w pamięci. Nazwy wpisów są sanityzowane tak samo jak w `build_tar_gz`:
ścieżka absolutna, segment `..` albo nazwa powtarzająca się po normalizacji kończą się
`ValueError` (wcześniej powstawało archiwum, którego własny czytnik SDK nie przyjmował).
Przykład:

```python
from ksef_client.utils import build_zip

zip_bytes = build_zip({
    "invoice1.xml": invoice_xml_1,
    "invoice2.xml": invoice_xml_2,
})
```

## `build_tar_gz(files: dict[str, bytes]) -> bytes`

Buduje deterministyczne archiwum TarGz w pamięci. Może być użyte jako alternatywny format
paczki wsadowej oraz do testów eksportu KSeF API 2.6.0.

```python
from ksef_client.utils import build_tar_gz

tar_gz_bytes = build_tar_gz({
    "invoice1.xml": invoice_xml_1,
    "invoice2.xml": invoice_xml_2,
})
```

## `split_bytes(data: bytes, max_part_size=MAX_BATCH_PART_SIZE_BYTES) -> list[bytes]`

Dzieli bajty na części o maksymalnym rozmiarze. Wykorzystywane w przygotowaniu paczek wsadowych.

## `unzip_bytes(data: bytes, ...) -> dict[str, bytes]`

Alias do `unzip_bytes_safe()` z sensownymi limitami.

## `unzip_bytes_safe(data: bytes, ...) -> dict[str, bytes]`

Bezpieczne rozpakowanie ZIP z limitami:
- liczba plików
- maksymalny rozmiar pojedynczego pliku
- maksymalny rozmiar sumaryczny
- opcjonalny limit współczynnika kompresji (ochrona przed zip bomb)

Każdy wpis jest czytany po swoim wpisie w archiwum (nie „po nazwie"), a powtórzona
nazwa kończy się `ValueError` — wcześniej archiwum z trzema wpisami `faktura.xml`
zwracało tylko treść ostatniego, gubiąc pozostałe faktury bez żadnego komunikatu.

W przypadku paczek eksportu z KSeF zalecane jest użycie `unzip_bytes_safe()`.

## `untar_gz_bytes(data: bytes, ...) -> dict[str, bytes]`

Alias do `untar_gz_bytes_safe()` z sensownymi limitami.

## `untar_gz_bytes_safe(data: bytes, ...) -> dict[str, bytes]`

Bezpieczne rozpakowanie TarGz z limitami analogicznymi do ZIP. Funkcja odrzuca ścieżki
absolutne, segmenty `..`, wpisy z separatorem dysku oraz linki symboliczne/twarde.
