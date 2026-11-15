from __future__ import annotations

import hashlib
import json

from ksef_client.config import KsefClientOptions
from ksef_client.operations import environment_key
from ksef_client.services.auth import _normalize_context_identifier_type


def login_scope(base_url: str, kind: str, context: str) -> str:
    """Bind durable workflows to the environment and context actually authenticated."""
    return _digest(
        login_endpoint(base_url),
        _normalize_context_identifier_type(kind).value,
        context,
    )


def login_endpoint(base_url: str) -> str:
    return environment_key(KsefClientOptions(base_url).normalized_base_url())


def token_pair_digest(access_token: str, refresh_token: str) -> str:
    return _digest(access_token, refresh_token)


def _digest(*values: str) -> str:
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()
