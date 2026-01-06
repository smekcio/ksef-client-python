# ZIP i podział partów (`ksef_client.utils.zip_utils`)

## `MAX_BATCH_PART_SIZE_BYTES`

Stała: 100MB – limit wynikający z KSeF (paczka wsadowa jest dzielona na takie części przed szyfrowaniem).

## `build_zip(files: dict[str, bytes]) -> bytes`

Buduje ZIP w pamięci. Przykład:

```python
from ksef_client.utils import build_zip

zip_bytes = build_zip({
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

W przypadku paczek eksportu z KSeF zalecane jest użycie `unzip_bytes_safe()`.
