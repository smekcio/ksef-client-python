# Numer seryjny certyfikatu (`ksef_client.utils.certificate_serial`)

Walidator zgodny z OpenAPI: `^[0-9A-F]{16}$`.

## `validate_certificate_serial_number(value) -> ValidationResult`

## `is_valid_certificate_serial_number(value) -> bool`

## `require_certificate_serial_number(value) -> str`

Zwraca wartość albo rzuca `ValueError`. Używane przez `client.testdata.update_certificate`.
