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
        # The check reads all pages once. The TEST identity can have any level of access.
        status = client.permissions.check_operation("download-purchases").status
        assert status in {"grant_found", "grant_not_found", "indeterminate"}
