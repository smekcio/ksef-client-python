# QR PNG (`ksef_client.services.qr`)

Te funkcje generują obraz PNG z gotowego URL (np. z `VerificationLinkService`).

Wymaga dodatku:

```bash
pip install -e .[qr]
```

## `generate_qr_png(payload_url, box_size=10, border=4) -> bytes`

Zwraca bajty PNG. Wynik może zostać zapisany do pliku lub osadzony w PDF.

## `resize_png(png_bytes, width, height) -> bytes`

Proste skalowanie PNG.

## `add_label_to_qr(png_bytes, label, font_size=14) -> bytes`

Dodaje podpis pod QR (np. numer faktury). Funkcja jest przydatna przy generowaniu wydruków.
