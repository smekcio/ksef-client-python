"""Live TEST coverage for KSeF 2.10 token management and authentication."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from ksef_client import Ksef, KsefClientOptions, KsefEnvironment, TokenCredentials, XadesCredentials
from ksef_client import models as m
from ksef_client.exceptions import KsefApiError, KsefExceptionCode
from ksef_client.request_control import request_control, wait_seconds
from ksef_client.services import XadesKeyPair
from tests.test_e2e_token_flows import (
    _ensure_e2e_enabled,
    _load_test_xades_config,
    _with_rate_limit_retry,
)

pytestmark = pytest.mark.e2e
Status = m.TokenStatusRev2Code


def _wait_for_status(tokens, reference, expected: Status):
    with request_control(timeout_seconds=180):
        while True:
            token = _with_rate_limit_retry(lambda: tokens.get_token_status_rev2(reference))
            if token.status.code == expected:
                return token
            assert token.status.code in {Status.PENDING, Status.AWAITINGAPPROVAL, Status.REVOKING}
            wait_seconds(2)


@contextmanager
def _session(options, config, credentials):
    with Ksef.connect(
        options=options,
        context_type=config.context_type,
        context_value=config.context_value,
        credentials=credentials,
        timeout=180,
    ) as client:
        try:
            yield client.api
        finally:
            _with_rate_limit_retry(client.api.auth.revoke_current_session)


def _revoke(tokens, reference):
    try:
        _with_rate_limit_retry(lambda: tokens.revoke_token(reference))
    except KsefApiError as error:
        if KsefExceptionCode.TOKEN_STATUS_BLOCKS_OPERATION not in error.exception_codes:
            raise
        # A token whose approval expired may already be terminal.
        token = tokens.get_token_status_rev2(reference)
        assert token.status.code in {Status.APPROVALEXPIRED, Status.EXPIRED, Status.REVOKED}


def test_e2e_test_environment_rev2_token_lifecycle():
    _ensure_e2e_enabled()
    config = _load_test_xades_config()
    options = KsefClientOptions(base_url=config.base_url, auth_status_rev2=True)
    assert options.normalized_base_url() == f"{KsefEnvironment.TEST.value}/v2"
    assert config.context_type.casefold() == "nip"
    assert config.certificate_pem and config.private_key_pem
    assert config.subject_identifier_type
    credentials = XadesCredentials(
        XadesKeyPair(config.certificate_pem, config.private_key_pem),
        subject_identifier_type=config.subject_identifier_type,
        auth_request_schema_version=config.auth_request_schema_version,
    )
    prefix = f"sdk-e2e-rev2-{uuid4().hex}"
    now = datetime.now(timezone.utc)
    parent_end = (now + timedelta(days=1)).replace(microsecond=0)
    child_start = (now + timedelta(hours=1)).replace(microsecond=0)

    with ExitStack() as stack:
        owner = stack.enter_context(_session(options, config, credentials))
        assert any(
            item.is_current
            and item.authentication_method_info.category.code
            == m.AuthenticationMethodCategoryRev2Code.XADESSIGNATURE
            for item in owner.auth.get_active_sessions_rev2().items
        )
        limits = owner.limits.get_context_limits()
        assert limits.tokens is not None and limits.tokens.max_tokens > 0

        def generate(api, suffix, permissions, *, valid_from=None, valid_to=None):
            result = _with_rate_limit_retry(
                lambda: api.tokens.generate_token_rev2(
                    m.GenerateTokenRequestRev2(
                        description=f"{prefix}-{suffix}",
                        permissions=permissions,
                        valid_from=valid_from.isoformat() if valid_from else None,
                        valid_to=valid_to.isoformat() if valid_to else None,
                    )
                )
            )
            stack.callback(_revoke, owner.tokens, result.reference_number)
            return result

        parent = generate(
            owner,
            "parent",
            [m.TokenPermissionType.CREDENTIALSMANAGE, m.TokenPermissionType.INVOICEREAD],
            valid_to=parent_end,
        )
        parent_status = _wait_for_status(owner.tokens, parent.reference_number, Status.ACTIVE)
        assert datetime.fromisoformat(parent_status.valid_to.replace("Z", "+00:00")) == parent_end
        child_permissions = [m.TokenPermissionType.INVOICEREAD]
        with _session(options, config, TokenCredentials(parent.token)) as delegated:
            approval = generate(
                delegated,
                "approval",
                child_permissions,
                valid_from=child_start,
            )
            expiry = generate(delegated, "expiry", child_permissions)

        for child in (approval, expiry):
            _wait_for_status(owner.tokens, child.reference_number, Status.AWAITINGAPPROVAL)

        waiting = owner.tokens.list_tokens_rev2(
            description=prefix, statuses=[m.TokenStatusFilterRev2.AWAITINGAPPROVAL]
        )
        assert {token.reference_number for token in waiting.tokens} == {
            approval.reference_number,
            expiry.reference_number,
        }
        owner.tokens.approve_token(approval.reference_number)
        approved = _wait_for_status(owner.tokens, approval.reference_number, Status.NOTYETACTIVE)
        assert datetime.fromisoformat(approved.valid_from.replace("Z", "+00:00")) == child_start

        owner.testdata.expire_token_approval(expiry.reference_number)
        _wait_for_status(owner.tokens, expiry.reference_number, Status.APPROVALEXPIRED)

        # The same DELETE endpoint revokes tokens of either revision.
        owner.tokens.revoke_token(approval.reference_number)
        _wait_for_status(owner.tokens, approval.reference_number, Status.REVOKED)
