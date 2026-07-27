# Identyfikator zbiorczy (`ksef_client.utils.collective_identifier`)

Walidator formatu IZ (`NIP-IZYYYYMM-HEX12-CRC8`), zgodny z dokumentacją KSeF API 2.7.0.

## `validate_collective_identifier_number(value) -> ValidationResult`

Sprawdza wzorzec, długość 35 znaków oraz checksum CRC-8 (ten sam algorytm co dla numeru KSeF).

## `is_valid_collective_identifier_number(value) -> bool`

## `require_collective_identifier_number(value) -> str`

Zwraca wartość albo rzuca `ValueError`. Używane przez `client.collective_identifiers.list_invoices`.
