from __future__ import annotations

import base64


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str | bytes) -> bytes:
    """Dekoduje **standardowy** base64 i wymaga poprawnego alfabetu.

    ``validate=True`` jest tu istotne: bez niego ``base64.b64decode`` po cichu
    *odrzuca* znaki spoza alfabetu standardowego (``-``, ``_``, ``!``) i zwraca
    krótszy — albo pusty — wynik zamiast zgłosić błąd. Wywołujący opierają na
    tym wyjątku fallback na base64url (patrz
    ``services.verification_link._decode_base64_or_url``), więc cicha degradacja
    prowadziła do porównań na przekręconym hashu.
    """
    if isinstance(data, str):
        data = data.encode("ascii")
    return base64.b64decode(data, validate=True)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """Dekoduje base64url **ściśle** (bez cichego odrzucania znaków).

    ``base64.urlsafe_b64decode`` *odrzuca* znaki spoza alfabetu (``!``, ``=``
    w środku, znaki sterujące) i zwraca krótszy — albo pusty — wynik zamiast
    zgłosić błąd. Dla hasha faktury kończyło się to linkiem z niepełnym
    segmentem, a nie czytelnym błędem, dlatego dekodujemy z ``validate=True``
    (własne ``altchars`` dają alfabet base64url).
    """
    padding = "=" * ((4 - len(data) % 4) % 4)
    try:
        return base64.b64decode((data + padding).encode("ascii"), altchars=b"-_", validate=True)
    except ValueError as exc:
        # `binascii.Error` i `UnicodeEncodeError` są podklasami `ValueError`.
        raise ValueError(f"Invalid base64url value: {data!r}") from exc
