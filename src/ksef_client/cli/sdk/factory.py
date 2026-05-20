from __future__ import annotations

from collections.abc import Callable

from ksef_client import KsefClient, KsefClientOptions


def create_client(
    base_url: str,
    access_token: str | None = None,
    base_lighthouse_url: str | None = None,
    system_warning_handler: Callable[[str], None] | None = None,
) -> KsefClient:
    return KsefClient(
        KsefClientOptions(
            base_url=base_url,
            base_lighthouse_url=base_lighthouse_url,
            custom_headers={"X-Error-Format": "problem-details"},
            system_warning_handler=system_warning_handler,
        ),
        access_token=access_token,
    )
