# Numer KSeF (`ksef_client.utils.ksef_number`)

Walidator jest przydatny, gdy `ksefNumber` pochodzi ze źródła zewnętrznego (np. UI, import).

## `validate_ksef_number(ksef_number) -> ValidationResult`

Zwraca:
- `is_valid: bool`
- `message: str` (np. `invalid format`, `checksum mismatch (...)`, `ok`)

Obsługuje formaty:
- 35-znakowy „kanoniczny”
- 36-znakowy z dodatkowym myślnikiem w części technicznej (biblioteka normalizuje format)

Walidacja sprawdza:
- dopasowanie do wzorca
- długość
- checksum CRC8

## `is_valid_ksef_number(ksef_number) -> bool`

Skrót do `validate_ksef_number(...).is_valid`.
