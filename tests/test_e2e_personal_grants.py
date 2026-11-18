"""Read the authenticated identity's personal permissions in the KSeF TEST environment."""

import pytest

from ksef_client import Ksef, KsefClientOptions, RetryConfig, TokenCredentials
from tests.test_e2e_token_flows import _ensure_e2e_enabled, _load_test_token_config

pytestmark = pytest.mark.e2e


def test_e2e_test_environment_personal_grants():
    _ensure_e2e_enabled()
    config = _load_test_token_config()
    assert config.token, "TEST token is required"
    options = KsefClientOptions(
        base_url=config.base_url,
        retry=RetryConfig(
            max_retries=5, retryable_post_paths=frozenset({"/permissions/query/personal/grants"})
        ),
    )
    with Ksef.connect(
        options=options,
        credentials=TokenCredentials(config.token),
        context_type=config.context_type,
        context_value=config.context_value,
        timeout=360,
    ) as client:
        # A complete empty list is valid. Keep the identity's grants out of test output.
        has_more = client.permissions.list_personal_grants().has_more
        assert has_more is False
