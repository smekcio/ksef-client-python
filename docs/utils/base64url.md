# Base64 / Base64Url (`ksef_client.utils.base64url`)

W API KSeF występują zarówno pola kodowane w Base64, jak i w Base64Url. Funkcje w module porządkują kodowanie i dekodowanie oraz ujednolicają format.

## `b64encode(data: bytes) -> str`

Klasyczny Base64 (z paddingiem).

## `b64decode(data: str | bytes) -> bytes`

Klasyczny Base64.

## `b64url_encode(data: bytes) -> str`

Base64Url bez paddingu (bez znaków `=`) – format używany m.in. w QR.

## `b64url_decode(data: str) -> bytes`

Dekoduje Base64Url (uzupełnia padding).
