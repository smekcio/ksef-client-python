"""Profile i magazyn certyfikatów bez CLI.

Skrypt jest **tylko do odczytu** — nie tworzy profili ani nie zapisuje
certyfikatów, więc można go bezpiecznie uruchomić na własnej konfiguracji.

Uruchomienie:

    python docs/examples/profiles_sdk.py
"""

from __future__ import annotations

from ksef_client import KsefClientOptions
from ksef_client.certificates import FileCertificateStore
from ksef_client.profiles import ProfileStore


def main() -> int:
    store = ProfileStore.default()
    print(f"Plik profili: {store.path}")

    profiles = store.list()
    if not profiles:
        print("Brak profili. Utwórz pierwszy przez `ksef init` albo ProfileStore.create(...).")
    for profile in profiles:
        marker = "*" if profile.name == store.active_name() else " "
        print(
            f"{marker} {profile.name:20} env={profile.env or '-':5} "
            f"base_url={profile.base_url} context={profile.context_type}:{profile.context_value}"
        )

    active = store.active()
    if active is not None:
        options = KsefClientOptions.from_profile(active)
        print(f"Aktywny profil -> base_url={options.base_url}")

    certificate_store = FileCertificateStore.default()
    print(f"Katalog certyfikatów: {certificate_store.directory}")
    records = certificate_store.list()
    if not records:
        print("Brak certyfikatów w magazynie SDK.")
    for record in records:
        print(
            f"  {record.name}: subject={record.subject} "
            f"ważny do {record.not_valid_after.date()} "
            f"sha256={record.fingerprint_sha256[:16]}…"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
