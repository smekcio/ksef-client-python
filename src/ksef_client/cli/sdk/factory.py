from __future__ import annotations

from ksef_client import KsefClient, KsefClientOptions


def create_client(base_url: str, access_token: str | None = None) -> KsefClient:
    return KsefClient(KsefClientOptions(base_url=base_url), access_token=access_token)
