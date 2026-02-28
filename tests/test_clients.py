import unittest
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import httpx

from ksef_client.clients.auth import AsyncAuthClient, AuthClient
from ksef_client.clients.certificates import AsyncCertificatesClient, CertificatesClient
from ksef_client.clients.invoices import (
    AsyncInvoicesClient,
    InvoicesClient,
    _normalize_datetime_without_offset,
    _normalize_invoice_date_range_payload,
)
from ksef_client.clients.lighthouse import AsyncLighthouseClient, LighthouseClient
from ksef_client.clients.limits import AsyncLimitsClient, LimitsClient
from ksef_client.clients.peppol import AsyncPeppolClient, PeppolClient
from ksef_client.clients.permissions import AsyncPermissionsClient, PermissionsClient, _page_params
from ksef_client.clients.rate_limits import AsyncRateLimitsClient, RateLimitsClient
from ksef_client.clients.security import AsyncSecurityClient, SecurityClient
from ksef_client.clients.sessions import AsyncSessionsClient, SessionsClient
from ksef_client.clients.testdata import AsyncTestDataClient, TestDataClient
from ksef_client.clients.tokens import AsyncTokensClient, TokensClient
from ksef_client.http import HttpResponse


class DummyHttp:
    def __init__(self, response: HttpResponse) -> None:
        self._response = response

    def request(self, *args: Any, **kwargs: Any) -> HttpResponse:
        return self._response


class DummyAsyncHttp:
    def __init__(self, response: HttpResponse) -> None:
        self._response = response

    async def request(self, *args: Any, **kwargs: Any) -> HttpResponse:
        return self._response


class ClientsTests(unittest.TestCase):
    def setUp(self):
        self.response = HttpResponse(200, httpx.Headers({"x-ms-meta-hash": "hash"}), b"<xml/>")
        self.http = DummyHttp(self.response)

    def test_auth_client(self):
        client = AuthClient(self.http)
        with (
            patch.object(client, "_request_json", Mock(return_value={"ok": True})),
            patch.object(
                client,
                "_request_bytes",
                Mock(side_effect=[b'{"status": "ok"}', b""]),
            ) as request_bytes_mock,
        ):
            client.get_active_sessions(
                page_size=10, continuation_token="cont", access_token="token"
            )
            client.revoke_current_session("token")
            client.revoke_session("ref", "token")
            client.get_challenge()
            result = client.submit_xades_auth_request(
                "<xml/>",
                verify_certificate_chain=True,
                enforce_xades_compliance=True,
            )
            self.assertEqual(
                request_bytes_mock.call_args_list[0].kwargs["headers"].get("X-KSeF-Feature"),
                "enforce-xades-compliance",
            )
            self.assertEqual(result["status"], "ok")
            self.assertIsNone(client.submit_xades_auth_request("<xml/>"))
            client.submit_ksef_token_auth({"a": 1})
            client.get_auth_status("ref", "auth")
            client.redeem_token("auth")
            client.refresh_access_token("refresh")

    def test_auth_client_get_active_sessions_without_optional_filters(self):
        client = AuthClient(self.http)
        with patch.object(
            client, "_request_json", Mock(return_value={"ok": True})
        ) as request_json_mock:
            client.get_active_sessions(continuation_token="", access_token="token")
            self.assertIsNone(request_json_mock.call_args.kwargs["headers"])
            self.assertIsNone(request_json_mock.call_args.kwargs["params"])

    def test_sessions_client(self):
        client = SessionsClient(self.http)
        with (
            patch.object(client, "_request_json", Mock(return_value={"referenceNumber": "ref"})),
            patch.object(client, "_request_bytes", Mock(return_value=b"upo")),
        ):
            client.get_sessions(
                session_type="online",
                page_size=1,
                continuation_token="cont",
                reference_number="ref",
                date_created_from="2024-01-01",
                date_created_to="2024-01-02",
                date_closed_from="2024-01-03",
                date_closed_to="2024-01-04",
                date_modified_from="2024-01-05",
                date_modified_to="2024-01-06",
                statuses=["OK"],
                access_token="token",
            )
            client.open_online_session({"a": 1}, access_token="token", upo_v43=True)
            client.close_online_session("ref", "token")
            client.send_online_invoice("ref", {"a": 1}, access_token="token")
            client.open_batch_session({"a": 1}, access_token="token", upo_v43=True)
            client.close_batch_session("ref", "token")
            client.get_session_status("ref", "token")
            client.get_session_invoices(
                "ref", page_size=1, continuation_token="cont", access_token="token"
            )
            client.get_session_failed_invoices(
                "ref", page_size=1, continuation_token="cont", access_token="token"
            )
            client.get_session_invoice_status("ref", "inv", access_token="token")
            client.get_session_invoice_upo_by_ref("ref", "inv", access_token="token")
            client.get_session_invoice_upo_by_ksef("ref", "ksef", access_token="token")
            client.get_session_upo("ref", "upo", access_token="token")

    def test_sessions_client_without_optional_filters(self):
        client = SessionsClient(self.http)
        with patch.object(
            client, "_request_json", Mock(return_value={"ok": True})
        ) as request_json_mock:
            client.get_sessions(
                session_type="online",
                continuation_token="",
                reference_number="",
                date_created_from="",
                date_created_to="",
                date_closed_from="",
                date_closed_to="",
                date_modified_from="",
                date_modified_to="",
                statuses=[],
                access_token="token",
            )
            self.assertEqual(
                request_json_mock.call_args.kwargs["params"], {"sessionType": "online"}
            )
            self.assertIsNone(request_json_mock.call_args.kwargs["headers"])

    def test_sessions_client_without_upo_feature_and_pagination(self):
        client = SessionsClient(self.http)
        with patch.object(
            client, "_request_json", Mock(return_value={"ok": True})
        ) as request_json_mock:
            client.open_online_session({"a": 1}, access_token="token")
            client.open_batch_session({"a": 1}, access_token="token")
            client.get_session_invoices("ref", continuation_token="", access_token="token")
            client.get_session_failed_invoices("ref", continuation_token="", access_token="token")

            self.assertIsNone(request_json_mock.call_args_list[0].kwargs["headers"])
            self.assertIsNone(request_json_mock.call_args_list[1].kwargs["headers"])
            self.assertIsNone(request_json_mock.call_args_list[2].kwargs["headers"])
            self.assertIsNone(request_json_mock.call_args_list[2].kwargs["params"])
            self.assertIsNone(request_json_mock.call_args_list[3].kwargs["headers"])
            self.assertIsNone(request_json_mock.call_args_list[3].kwargs["params"])

    def test_invoices_client(self):
        client = InvoicesClient(self.http)
        query_payload = {
            "subjectType": "Subject1",
            "dateRange": {
                "dateType": "Issue",
                "from": "2025-01-02T10:15:00",
                "to": "2025-01-02T11:15:00",
            },
        }
        export_payload = {
            "encryption": {"encryptedSymmetricKey": "abc", "initializationVector": "def"},
            "filters": {
                "subjectType": "Subject1",
                "dateRange": {
                    "dateType": "Issue",
                    "from": "2025-07-02T10:15:00",
                    "to": "2025-07-02T11:15:00",
                },
            },
        }
        with (
            patch.object(client, "_request_raw", Mock(return_value=self.response)),
            patch.object(
                client, "_request_json", Mock(return_value={"ok": True})
            ) as request_json_mock,
            patch.object(client, "_request_bytes", Mock(return_value=b"bytes")),
        ):
            invoice = client.get_invoice("ksef", access_token="token")
            self.assertEqual(invoice.sha256_base64, "hash")
            invoice_bytes = client.get_invoice_bytes("ksef", access_token="token")
            self.assertEqual(invoice_bytes.sha256_base64, "hash")
            client.query_invoice_metadata(
                query_payload,
                access_token="token",
                page_offset=0,
                page_size=10,
                sort_order="asc",
            )
            client.export_invoices(export_payload, access_token="token")
            client.get_export_status("ref", access_token="token")
            client.download_export_part("https://example.com")
            client.download_package_part("https://example.com")
            with_hash = client.download_export_part_with_hash("https://example.com")
            self.assertEqual(with_hash.sha256_base64, "hash")
            self.assertEqual(
                request_json_mock.call_args_list[0].kwargs["json"]["dateRange"]["from"],
                "2025-01-02T10:15:00+01:00",
            )
            self.assertEqual(
                request_json_mock.call_args_list[0].kwargs["json"]["dateRange"]["to"],
                "2025-01-02T11:15:00+01:00",
            )
            self.assertEqual(
                request_json_mock.call_args_list[1].kwargs["json"]["filters"]["dateRange"]["from"],
                "2025-07-02T10:15:00+02:00",
            )
            self.assertEqual(
                request_json_mock.call_args_list[1].kwargs["json"]["filters"]["dateRange"]["to"],
                "2025-07-02T11:15:00+02:00",
            )

    def test_invoices_client_query_metadata_without_optional_params(self):
        client = InvoicesClient(self.http)
        with patch.object(
            client, "_request_json", Mock(return_value={"ok": True})
        ) as request_json_mock:
            client.query_invoice_metadata({"subjectType": "Subject1"}, access_token="token")
            self.assertIsNone(request_json_mock.call_args.kwargs["params"])

    def test_normalize_invoice_date_range_payload_passthrough_branches(self):
        payload = {
            "dateRange": {"from": 1, "to": None},
            "filters": {"dateRange": "invalid"},
        }
        normalized = _normalize_invoice_date_range_payload(payload)
        self.assertEqual(normalized["dateRange"]["from"], 1)
        self.assertIsNone(normalized["dateRange"]["to"])

    def test_normalize_datetime_without_offset_passthrough_branches(self):
        self.assertEqual(_normalize_datetime_without_offset("2025-01-02"), "2025-01-02")

        invalid_value = "not-a-dateT10:15:00"
        self.assertEqual(_normalize_datetime_without_offset(invalid_value), invalid_value)

        tz_aware_short_offset = "2025-01-02T10:15:00+01"
        self.assertEqual(
            _normalize_datetime_without_offset(tz_aware_short_offset), tz_aware_short_offset
        )

    def test_permissions_client(self):
        client = PermissionsClient(self.http)
        with patch.object(client, "_request_json", Mock(return_value={"ok": True})):
            payload = {"a": 1}
            client.check_attachment_permission_status("token")
            client.grant_authorization(payload, access_token="token")
            client.revoke_authorization("perm", access_token="token")
            client.revoke_common_permission("perm", access_token="token")
            client.grant_entity(payload, access_token="token")
            client.grant_eu_entity(payload, access_token="token")
            client.grant_eu_entity_admin(payload, access_token="token")
            client.grant_indirect(payload, access_token="token")
            client.grant_person(payload, access_token="token")
            client.grant_subunit(payload, access_token="token")
            client.get_operation_status("ref", access_token="token")
            client.query_authorizations_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            client.query_entities_roles(page_offset=0, page_size=10, access_token="token")
            client.query_eu_entities_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            client.query_personal_grants(payload, page_offset=0, page_size=10, access_token="token")
            client.query_persons_grants(payload, page_offset=0, page_size=10, access_token="token")
            client.query_subordinate_entities_roles(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            client.query_subunits_grants(payload, page_offset=0, page_size=10, access_token="token")

    def test_permissions_page_params_without_values(self):
        self.assertEqual(_page_params(None, None), {})

    def test_certificates_client(self):
        client = CertificatesClient(self.http)
        with patch.object(client, "_request_json", Mock(return_value={"ok": True})):
            payload = {"a": 1}
            client.get_limits("token")
            client.get_enrollment_data("token")
            client.send_enrollment(payload, access_token="token")
            client.get_enrollment_status("ref", access_token="token")
            client.query_certificates(
                payload,
                page_size=10,
                page_offset=0,
                access_token="token",
            )
            client.retrieve_certificate(payload, access_token="token")
            client.revoke_certificate("serial", payload, access_token="token")

    def test_certificates_client_query_without_pagination(self):
        client = CertificatesClient(self.http)
        with patch.object(
            client, "_request_json", Mock(return_value={"ok": True})
        ) as request_json_mock:
            client.query_certificates({"a": 1}, access_token="token")
            self.assertIsNone(request_json_mock.call_args.kwargs["params"])

    def test_tokens_client(self):
        client = TokensClient(self.http)
        with patch.object(client, "_request_json", Mock(return_value={"ok": True})):
            client.generate_token({"a": 1}, access_token="token")
            client.list_tokens(
                access_token="token",
                statuses=["active"],
                description="desc",
                author_identifier="id",
                author_identifier_type="nip",
                page_size=10,
                continuation_token="cont",
            )
            client.get_token_status("ref", access_token="token")
            client.revoke_token("ref", access_token="token")

    def test_tokens_client_list_tokens_without_optional_filters(self):
        client = TokensClient(self.http)
        with patch.object(
            client, "_request_json", Mock(return_value={"ok": True})
        ) as request_json_mock:
            client.list_tokens(
                access_token="token",
                statuses=[],
                description="",
                author_identifier="",
                author_identifier_type="",
                continuation_token="",
            )
            self.assertIsNone(request_json_mock.call_args.kwargs["params"])
            self.assertIsNone(request_json_mock.call_args.kwargs["headers"])

    def test_limits_clients(self):
        client = LimitsClient(self.http)
        with patch.object(client, "_request_json", Mock(return_value={"ok": True})):
            client.get_context_limits("token")
            client.get_subject_limits("token")

        rate_client = RateLimitsClient(self.http)
        with patch.object(rate_client, "_request_json", Mock(return_value={"ok": True})):
            rate_client.get_rate_limits("token")

        security_client = SecurityClient(self.http)
        with patch.object(security_client, "_request_json", Mock(return_value={"ok": True})):
            security_client.get_public_key_certificates()

    def test_testdata_client(self):
        client = TestDataClient(self.http)
        with patch.object(client, "_request_json", Mock(return_value={"ok": True})):
            payload = {"a": 1}
            client.create_subject(payload)
            client.remove_subject(payload)
            client.create_person(payload)
            client.remove_person(payload)
            client.grant_permissions(payload)
            client.revoke_permissions(payload)
            client.enable_attachment(payload)
            client.disable_attachment(payload)
            client.block_context_authentication(payload)
            client.unblock_context_authentication(payload)
            client.change_session_limits(payload, access_token="token")
            client.reset_session_limits(access_token="token")
            client.change_certificate_limits(payload, access_token="token")
            client.reset_certificate_limits(access_token="token")
            client.set_rate_limits(payload, access_token="token")
            client.reset_rate_limits(access_token="token")
            client.restore_production_rate_limits(access_token="token")

    def test_peppol_client(self):
        client = PeppolClient(self.http)
        with patch.object(client, "_request_json", Mock(return_value={"ok": True})):
            client.list_providers(page_offset=0, page_size=10)

    def test_peppol_client_without_pagination(self):
        client = PeppolClient(self.http)
        with patch.object(
            client, "_request_json", Mock(return_value={"ok": True})
        ) as request_json_mock:
            client.list_providers()
            self.assertIsNone(request_json_mock.call_args.kwargs["params"])

    def test_lighthouse_client(self):
        client = LighthouseClient(self.http, "https://api-latarnia-test.ksef.mf.gov.pl")
        with patch.object(
            client,
            "_request_json",
            Mock(
                side_effect=[
                    {
                        "status": "AVAILABLE",
                        "messages": [],
                    },
                    [],
                ]
            ),
        ) as request_json_mock:
            status = client.get_status()
            messages = client.get_messages()
            self.assertEqual(status.status.value, "AVAILABLE")
            self.assertEqual(messages, [])
            self.assertEqual(
                request_json_mock.call_args_list[0].args[1],
                "https://api-latarnia-test.ksef.mf.gov.pl/status",
            )
            self.assertEqual(
                request_json_mock.call_args_list[1].args[1],
                "https://api-latarnia-test.ksef.mf.gov.pl/messages",
            )

    def test_lighthouse_client_handles_invalid_payload_and_missing_base_url(self):
        client = LighthouseClient(self.http, "https://api-latarnia-test.ksef.mf.gov.pl")
        with patch.object(client, "_request_json", Mock(side_effect=[None, {"unexpected": True}])):
            status = client.get_status()
            messages = client.get_messages()
            self.assertEqual(status.status.value, "AVAILABLE")
            self.assertEqual(messages, [])

        missing_base_client = LighthouseClient(self.http, "")
        with self.assertRaises(ValueError):
            missing_base_client.get_status()


class AsyncClientsTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_clients(self):
        response = HttpResponse(200, httpx.Headers({"x-ms-meta-hash": "hash"}), b"<xml/>")
        http = DummyAsyncHttp(response)

        auth = AsyncAuthClient(http)
        with (
            patch.object(auth, "_request_json", AsyncMock(return_value={"ok": True})),
            patch.object(
                auth,
                "_request_bytes",
                AsyncMock(side_effect=[b'{"status": "ok"}', b""]),
            ) as request_bytes_mock,
        ):
            await auth.get_active_sessions(
                page_size=10,
                continuation_token="cont",
                access_token="token",
            )
            await auth.revoke_current_session("token")
            await auth.revoke_session("ref", "token")
            await auth.get_challenge()
            result = await auth.submit_xades_auth_request(
                "<xml/>",
                verify_certificate_chain=True,
                enforce_xades_compliance=True,
            )
            self.assertEqual(
                request_bytes_mock.call_args_list[0].kwargs["headers"].get("X-KSeF-Feature"),
                "enforce-xades-compliance",
            )
            self.assertEqual(result["status"], "ok")
            self.assertIsNone(
                await auth.submit_xades_auth_request(
                    "<xml/>",
                    verify_certificate_chain=None,
                )
            )
            await auth.submit_ksef_token_auth({"a": 1})
            await auth.get_auth_status("ref", "auth")
            await auth.redeem_token("auth")
            await auth.refresh_access_token("refresh")

        sessions = AsyncSessionsClient(http)
        with (
            patch.object(
                sessions, "_request_json", AsyncMock(return_value={"referenceNumber": "ref"})
            ),
            patch.object(sessions, "_request_bytes", AsyncMock(return_value=b"upo")),
        ):
            await sessions.get_sessions(
                session_type="online",
                page_size=1,
                continuation_token="cont",
                reference_number="ref",
                date_created_from="2024-01-01",
                date_created_to="2024-01-02",
                date_closed_from="2024-01-03",
                date_closed_to="2024-01-04",
                date_modified_from="2024-01-05",
                date_modified_to="2024-01-06",
                statuses=["OK"],
                access_token="token",
            )
            await sessions.open_online_session(
                {"a": 1},
                access_token="token",
                upo_v43=True,
            )
            await sessions.close_online_session("ref", "token")
            await sessions.send_online_invoice("ref", {"a": 1}, access_token="token")
            await sessions.open_batch_session(
                {"a": 1},
                access_token="token",
                upo_v43=True,
            )
            await sessions.close_batch_session("ref", "token")
            await sessions.get_session_status("ref", "token")
            await sessions.get_session_invoices(
                "ref",
                page_size=1,
                continuation_token="cont",
                access_token="token",
            )
            await sessions.get_session_failed_invoices(
                "ref",
                page_size=1,
                continuation_token="cont",
                access_token="token",
            )
            await sessions.get_session_invoice_status("ref", "inv", access_token="token")
            await sessions.get_session_invoice_upo_by_ref("ref", "inv", access_token="token")
            await sessions.get_session_invoice_upo_by_ksef("ref", "ksef", access_token="token")
            await sessions.get_session_upo("ref", "upo", access_token="token")

        invoices = AsyncInvoicesClient(http)
        query_payload = {
            "subjectType": "Subject1",
            "dateRange": {
                "dateType": "Issue",
                "from": "2025-01-02T10:15:00",
                "to": "2025-01-02T11:15:00",
            },
        }
        export_payload = {
            "encryption": {"encryptedSymmetricKey": "abc", "initializationVector": "def"},
            "filters": {
                "subjectType": "Subject1",
                "dateRange": {
                    "dateType": "Issue",
                    "from": "2025-07-02T10:15:00",
                    "to": "2025-07-02T11:15:00",
                },
            },
        }
        with (
            patch.object(invoices, "_request_raw", AsyncMock(return_value=response)),
            patch.object(
                invoices, "_request_json", AsyncMock(return_value={"ok": True})
            ) as request_json_mock,
            patch.object(invoices, "_request_bytes", AsyncMock(return_value=b"bytes")),
        ):
            await invoices.get_invoice("ksef", access_token="token")
            await invoices.get_invoice_bytes("ksef", access_token="token")
            await invoices.query_invoice_metadata(
                query_payload,
                access_token="token",
                page_offset=0,
                page_size=10,
                sort_order="asc",
            )
            await invoices.export_invoices(export_payload, access_token="token")
            await invoices.get_export_status("ref", access_token="token")
            await invoices.download_export_part("https://example.com")
            await invoices.download_package_part("https://example.com")
            await invoices.download_export_part_with_hash("https://example.com")
            self.assertEqual(
                request_json_mock.call_args_list[0].kwargs["json"]["dateRange"]["from"],
                "2025-01-02T10:15:00+01:00",
            )
            self.assertEqual(
                request_json_mock.call_args_list[1].kwargs["json"]["filters"]["dateRange"]["from"],
                "2025-07-02T10:15:00+02:00",
            )

        permissions = AsyncPermissionsClient(http)
        with patch.object(permissions, "_request_json", AsyncMock(return_value={"ok": True})):
            payload = {"a": 1}
            await permissions.check_attachment_permission_status("token")
            await permissions.grant_authorization(payload, access_token="token")
            await permissions.revoke_authorization("perm", access_token="token")
            await permissions.revoke_common_permission("perm", access_token="token")
            await permissions.grant_entity(payload, access_token="token")
            await permissions.grant_eu_entity(payload, access_token="token")
            await permissions.grant_eu_entity_admin(payload, access_token="token")
            await permissions.grant_indirect(payload, access_token="token")
            await permissions.grant_person(payload, access_token="token")
            await permissions.grant_subunit(payload, access_token="token")
            await permissions.get_operation_status("ref", access_token="token")
            await permissions.query_authorizations_grants(
                payload,
                page_offset=0,
                page_size=10,
                access_token="token",
            )
            await permissions.query_entities_roles(
                page_offset=0,
                page_size=10,
                access_token="token",
            )
            await permissions.query_eu_entities_grants(
                payload,
                page_offset=0,
                page_size=10,
                access_token="token",
            )
            await permissions.query_personal_grants(
                payload,
                page_offset=0,
                page_size=10,
                access_token="token",
            )
            await permissions.query_persons_grants(
                payload,
                page_offset=0,
                page_size=10,
                access_token="token",
            )
            await permissions.query_subordinate_entities_roles(
                payload,
                page_offset=0,
                page_size=10,
                access_token="token",
            )
            await permissions.query_subunits_grants(
                payload,
                page_offset=0,
                page_size=10,
                access_token="token",
            )

        certificates = AsyncCertificatesClient(http)
        with patch.object(certificates, "_request_json", AsyncMock(return_value={"ok": True})):
            await certificates.get_limits("token")
            await certificates.get_enrollment_data("token")
            await certificates.send_enrollment(payload, access_token="token")
            await certificates.get_enrollment_status("ref", access_token="token")
            await certificates.query_certificates(
                payload,
                page_size=10,
                page_offset=0,
                access_token="token",
            )
            await certificates.retrieve_certificate(payload, access_token="token")
            await certificates.revoke_certificate("serial", payload, access_token="token")

        tokens = AsyncTokensClient(http)
        with patch.object(tokens, "_request_json", AsyncMock(return_value={"ok": True})):
            await tokens.generate_token(payload, access_token="token")
            await tokens.list_tokens(
                access_token="token",
                statuses=["active"],
                description="desc",
                author_identifier="id",
                author_identifier_type="nip",
                page_size=10,
                continuation_token="cont",
            )
            await tokens.get_token_status("ref", access_token="token")
            await tokens.revoke_token("ref", access_token="token")

    async def test_async_tokens_client_list_tokens_without_optional_filters(self):
        response = HttpResponse(200, httpx.Headers({}), b"{}")
        http = DummyAsyncHttp(response)
        payload = {"a": 1}
        tokens = AsyncTokensClient(http)
        with patch.object(
            tokens, "_request_json", AsyncMock(return_value={"ok": True})
        ) as request_json_mock:
            await tokens.list_tokens(
                access_token="token",
                statuses=[],
                description="",
                author_identifier="",
                author_identifier_type="",
                continuation_token="",
            )
            self.assertIsNone(request_json_mock.call_args.kwargs["params"])
            self.assertIsNone(request_json_mock.call_args.kwargs["headers"])

        limits = AsyncLimitsClient(http)
        with patch.object(limits, "_request_json", AsyncMock(return_value={"ok": True})):
            await limits.get_context_limits("token")
            await limits.get_subject_limits("token")

        rate_limits = AsyncRateLimitsClient(http)
        with patch.object(rate_limits, "_request_json", AsyncMock(return_value={"ok": True})):
            await rate_limits.get_rate_limits("token")

        security = AsyncSecurityClient(http)
        with patch.object(security, "_request_json", AsyncMock(return_value={"ok": True})):
            await security.get_public_key_certificates()

        testdata = AsyncTestDataClient(http)
        with patch.object(testdata, "_request_json", AsyncMock(return_value={"ok": True})):
            await testdata.create_subject(payload)
            await testdata.remove_subject(payload)
            await testdata.create_person(payload)
            await testdata.remove_person(payload)
            await testdata.grant_permissions(payload)
            await testdata.revoke_permissions(payload)
            await testdata.enable_attachment(payload)
            await testdata.disable_attachment(payload)
            await testdata.block_context_authentication(payload)
            await testdata.unblock_context_authentication(payload)
            await testdata.change_session_limits(payload, access_token="token")
            await testdata.reset_session_limits(access_token="token")
            await testdata.change_certificate_limits(payload, access_token="token")
            await testdata.reset_certificate_limits(access_token="token")
            await testdata.set_rate_limits(payload, access_token="token")
            await testdata.reset_rate_limits(access_token="token")
            await testdata.restore_production_rate_limits(access_token="token")

        peppol = AsyncPeppolClient(http)
        with patch.object(peppol, "_request_json", AsyncMock(return_value={"ok": True})):
            await peppol.list_providers(page_offset=0, page_size=10)

    async def test_async_peppol_client_without_pagination(self):
        response = HttpResponse(200, httpx.Headers({}), b"{}")
        http = DummyAsyncHttp(response)
        peppol = AsyncPeppolClient(http)
        with patch.object(
            peppol, "_request_json", AsyncMock(return_value={"ok": True})
        ) as request_json_mock:
            await peppol.list_providers()
            self.assertIsNone(request_json_mock.call_args.kwargs["params"])

    async def test_async_auth_client_get_active_sessions_without_optional_filters(self):
        response = HttpResponse(200, httpx.Headers({}), b"{}")
        http = DummyAsyncHttp(response)
        auth = AsyncAuthClient(http)
        with patch.object(
            auth, "_request_json", AsyncMock(return_value={"ok": True})
        ) as request_json_mock:
            await auth.get_active_sessions(continuation_token="", access_token="token")
            self.assertIsNone(request_json_mock.call_args.kwargs["headers"])
            self.assertIsNone(request_json_mock.call_args.kwargs["params"])

    async def test_async_certificates_client_query_without_pagination(self):
        response = HttpResponse(200, httpx.Headers({}), b"{}")
        http = DummyAsyncHttp(response)
        certificates = AsyncCertificatesClient(http)
        with patch.object(
            certificates, "_request_json", AsyncMock(return_value={"ok": True})
        ) as request_json_mock:
            await certificates.query_certificates({"a": 1}, access_token="token")
            self.assertIsNone(request_json_mock.call_args.kwargs["params"])

    async def test_async_invoices_client_query_metadata_without_optional_params(self):
        response = HttpResponse(200, httpx.Headers({}), b"{}")
        http = DummyAsyncHttp(response)
        invoices = AsyncInvoicesClient(http)
        with patch.object(
            invoices, "_request_json", AsyncMock(return_value={"ok": True})
        ) as request_json_mock:
            await invoices.query_invoice_metadata({"subjectType": "Subject1"}, access_token="token")
            self.assertIsNone(request_json_mock.call_args.kwargs["params"])

    async def test_async_sessions_client_without_optional_filters(self):
        response = HttpResponse(200, httpx.Headers({}), b"{}")
        http = DummyAsyncHttp(response)
        sessions = AsyncSessionsClient(http)
        with patch.object(
            sessions, "_request_json", AsyncMock(return_value={"ok": True})
        ) as request_json_mock:
            await sessions.get_sessions(
                session_type="online",
                continuation_token="",
                reference_number="",
                date_created_from="",
                date_created_to="",
                date_closed_from="",
                date_closed_to="",
                date_modified_from="",
                date_modified_to="",
                statuses=[],
                access_token="token",
            )
            self.assertEqual(
                request_json_mock.call_args.kwargs["params"], {"sessionType": "online"}
            )
            self.assertIsNone(request_json_mock.call_args.kwargs["headers"])

    async def test_async_sessions_client_without_upo_feature_and_pagination(self):
        response = HttpResponse(200, httpx.Headers({}), b"{}")
        http = DummyAsyncHttp(response)
        sessions = AsyncSessionsClient(http)
        with patch.object(
            sessions, "_request_json", AsyncMock(return_value={"ok": True})
        ) as request_json_mock:
            await sessions.open_online_session({"a": 1}, access_token="token")
            await sessions.open_batch_session({"a": 1}, access_token="token")
            await sessions.get_session_invoices("ref", continuation_token="", access_token="token")
            await sessions.get_session_failed_invoices(
                "ref", continuation_token="", access_token="token"
            )

            self.assertIsNone(request_json_mock.call_args_list[0].kwargs["headers"])
            self.assertIsNone(request_json_mock.call_args_list[1].kwargs["headers"])
            self.assertIsNone(request_json_mock.call_args_list[2].kwargs["headers"])
            self.assertIsNone(request_json_mock.call_args_list[2].kwargs["params"])
            self.assertIsNone(request_json_mock.call_args_list[3].kwargs["headers"])
            self.assertIsNone(request_json_mock.call_args_list[3].kwargs["params"])

        lighthouse = AsyncLighthouseClient(http, "https://api-latarnia-test.ksef.mf.gov.pl")
        with patch.object(
            lighthouse,
            "_request_json",
            AsyncMock(side_effect=[{"status": "AVAILABLE", "messages": []}, []]),
        ) as request_json_mock:
            status = await lighthouse.get_status()
            messages = await lighthouse.get_messages()
            self.assertEqual(status.status.value, "AVAILABLE")
            self.assertEqual(messages, [])
            self.assertEqual(
                request_json_mock.call_args_list[0].args[1],
                "https://api-latarnia-test.ksef.mf.gov.pl/status",
            )
            self.assertEqual(
                request_json_mock.call_args_list[1].args[1],
                "https://api-latarnia-test.ksef.mf.gov.pl/messages",
            )

    async def test_async_lighthouse_handles_invalid_payload_and_missing_base_url(self):
        response = HttpResponse(200, httpx.Headers({}), b"{}")
        http = DummyAsyncHttp(response)
        lighthouse = AsyncLighthouseClient(http, "https://api-latarnia-test.ksef.mf.gov.pl")
        with patch.object(
            lighthouse,
            "_request_json",
            AsyncMock(side_effect=[None, {"unexpected": True}]),
        ):
            status = await lighthouse.get_status()
            messages = await lighthouse.get_messages()
            self.assertEqual(status.status.value, "AVAILABLE")
            self.assertEqual(messages, [])

        missing_base = AsyncLighthouseClient(http, "")
        with self.assertRaises(ValueError):
            await missing_base.get_messages()


if __name__ == "__main__":
    unittest.main()
