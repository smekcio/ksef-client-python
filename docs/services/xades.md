# XAdES (`ksef_client.services.xades`)

## `XadesKeyPair`

`XadesKeyPair` porządkuje pracę z certyfikatem i kluczem prywatnym w sposób zbliżony do podejścia znanego z implementacji C#/.NET i Java (kontener klucza lub para plików). Klasa dostarcza metody wczytania materiału klucza oraz przygotowuje klucz prywatny w postaci niezaszyfrowanego PKCS#8 (PEM) do użycia przez podpis XAdES.

### `XadesKeyPair.from_pkcs12_file(pkcs12_path, pkcs12_password) -> XadesKeyPair`

Wczytuje certyfikat i klucz prywatny z kontenera PKCS#12 (`.pfx` / `.p12`).

### `XadesKeyPair.from_pkcs12_bytes(pkcs12_bytes, pkcs12_password) -> XadesKeyPair`

Wariant dla danych w pamięci (np. sekret z magazynu, zasób pobrany przez HTTP). Parametr `pkcs12_password` jest opcjonalny i zależy od sposobu zabezpieczenia pliku.

### `XadesKeyPair.from_pem_files(certificate_path, private_key_path, private_key_password=None) -> XadesKeyPair`

Wczytuje certyfikat z pliku PEM albo DER (`.crt`) oraz klucz prywatny w PEM/DER (w tym klucz zaszyfrowany hasłem).

Przykład użycia w workflow uwierzytelnienia:

```python
from ksef_client.services import XadesKeyPair
from ksef_client.services.workflows import AuthCoordinator

key_pair = XadesKeyPair.from_pkcs12_file(
    pkcs12_path="cert.pfx",
    pkcs12_password="haslo",
)

result = AuthCoordinator(client.auth).authenticate_with_xades_key_pair(
    key_pair=key_pair,
    context_identifier_type="nip",
    context_identifier_value="7831906994",
    subject_identifier_type="certificateSubject",
    max_attempts=90,
    poll_interval_seconds=2.0,
)
```

## `sign_xades_enveloped(xml_string, certificate_pem, private_key_pem) -> str`

Podpisuje XML w formacie XAdES (enveloped signature), zgodnie z wymaganiami KSeF.

Wymaga zainstalowanych dodatków:

```bash
pip install -e .[xml]
```

Uwagi:
- funkcja dobiera algorytm podpisu na podstawie typu klucza w certyfikacie (RSA/ECDSA)
- to nie jest „detached signature” – podpis jest w dokumencie
- w przypadku braku `xmlsec`/`lxml` zgłaszany jest `RuntimeError`
