import unittest
from unittest.mock import AsyncMock, Mock

import httpx

from ksef_client.clients.auth import AuthClient, AsyncAuthClient
from ksef_client.clients.sessions import SessionsClient, AsyncSessionsClient
from ksef_client.clients.invoices import InvoicesClient, AsyncInvoicesClient
from ksef_client.clients.permissions import PermissionsClient, AsyncPermissionsClient
from ksef_client.clients.certificates import CertificatesClient, AsyncCertificatesClient
from ksef_client.clients.tokens import TokensClient, AsyncTokensClient
from ksef_client.clients.limits import LimitsClient, AsyncLimitsClient
from ksef_client.clients.rate_limits import RateLimitsClient, AsyncRateLimitsClient
from ksef_client.clients.security import SecurityClient, AsyncSecurityClient
from ksef_client.clients.testdata import TestDataClient, AsyncTestDataClient
from ksef_client.clients.peppol import PeppolClient, AsyncPeppolClient
from ksef_client.http import HttpResponse


class ClientsTests(unittest.TestCase):
    def setUp(self):
        self.http = object()
        self.response = HttpResponse(200, httpx.Headers({"x-ms-meta-hash": "hash"}), b"<xml/>")

    def test_auth_client(self):
        client = AuthClient(self.http)
        client._request_json = Mock(return_value={"ok": True})
        client._request_bytes = Mock(return_value=b"{\"status\": \"ok\"}")

        client.get_active_sessions(page_size=10, continuation_token="cont", access_token="token")
        client.revoke_current_session("token")
        client.revoke_session("ref", "token")
        client.get_challenge()
        result = client.submit_xades_auth_request("<xml/>", verify_certificate_chain=True)
        self.assertEqual(result["status"], "ok")
        client._request_bytes = Mock(return_value=b"")
        self.assertIsNone(client.submit_xades_auth_request("<xml/>"))
        client.submit_ksef_token_auth({"a": 1})
        client.get_auth_status("ref", "auth")
        client.redeem_token("auth")
        client.refresh_access_token("refresh")

    def test_sessions_client(self):
        client = SessionsClient(self.http)
        client._request_json = Mock(return_value={"referenceNumber": "ref"})
        client._request_bytes = Mock(return_value=b"upo")

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
        client.get_session_invoices("ref", page_size=1, continuation_token="cont", access_token="token")
        client.get_session_failed_invoices("ref", page_size=1, continuation_token="cont", access_token="token")
        client.get_session_invoice_status("ref", "inv", access_token="token")
        client.get_session_invoice_upo_by_ref("ref", "inv", access_token="token")
        client.get_session_invoice_upo_by_ksef("ref", "ksef", access_token="token")
        client.get_session_upo("ref", "upo", access_token="token")

    def test_invoices_client(self):
        client = InvoicesClient(self.http)
        client._request_raw = Mock(return_value=self.response)
        client._request_json = Mock(return_value={"ok": True})
        client._request_bytes = Mock(return_value=b"bytes")

        invoice = client.get_invoice("ksef", access_token="token")
        self.assertEqual(invoice.sha256_base64, "hash")
        invoice_bytes = client.get_invoice_bytes("ksef", access_token="token")
        self.assertEqual(invoice_bytes.sha256_base64, "hash")
        client.query_invoice_metadata({"a": 1}, access_token="token", page_offset=0, page_size=10, sort_order="asc")
        client.export_invoices({"a": 1}, access_token="token")
        client.get_export_status("ref", access_token="token")
        client.download_export_part("https://example.com")
        client.download_package_part("https://example.com")
        with_hash = client.download_export_part_with_hash("https://example.com")
        self.assertEqual(with_hash.sha256_base64, "hash")

    def test_permissions_client(self):
        client = PermissionsClient(self.http)
        client._request_json = Mock(return_value={"ok": True})
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
        client.query_authorizations_grants(payload, page_offset=0, page_size=10, access_token="token")
        client.query_entities_roles(page_offset=0, page_size=10, access_token="token")
        client.query_eu_entities_grants(payload, page_offset=0, page_size=10, access_token="token")
        client.query_personal_grants(payload, page_offset=0, page_size=10, access_token="token")
        client.query_persons_grants(payload, page_offset=0, page_size=10, access_token="token")
        client.query_subordinate_entities_roles(payload, page_offset=0, page_size=10, access_token="token")
        client.query_subunits_grants(payload, page_offset=0, page_size=10, access_token="token")

    def test_certificates_client(self):
        client = CertificatesClient(self.http)
        client._request_json = Mock(return_value={"ok": True})
        payload = {"a": 1}
        client.get_limits("token")
        client.get_enrollment_data("token")
        client.send_enrollment(payload, access_token="token")
        client.get_enrollment_status("ref", access_token="token")
        client.query_certificates(payload, page_size=10, page_offset=0, access_token="token")
        client.retrieve_certificate(payload, access_token="token")
        client.revoke_certificate("serial", payload, access_token="token")

    def test_tokens_client(self):
        client = TokensClient(self.http)
        client._request_json = Mock(return_value={"ok": True})
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

    def test_limits_clients(self):
        client = LimitsClient(self.http)
        client._request_json = Mock(return_value={"ok": True})
        client.get_context_limits("token")
        client.get_subject_limits("token")

        rate_client = RateLimitsClient(self.http)
        rate_client._request_json = Mock(return_value={"ok": True})
        rate_client.get_rate_limits("token")

        security_client = SecurityClient(self.http)
        security_client._request_json = Mock(return_value={"ok": True})
        security_client.get_public_key_certificates()
        security_client._request_bytes = Mock(return_value=b"pem")
        self.assertEqual(security_client.get_public_key_pem(), "pem")

    def test_testdata_client(self):
        client = TestDataClient(self.http)
        client._request_json = Mock(return_value={"ok": True})
        payload = {"a": 1}
        client.create_subject(payload)
        client.remove_subject(payload)
        client.create_person(payload)
        client.remove_person(payload)
        client.grant_permissions(payload)
        client.revoke_permissions(payload)
        client.enable_attachment(payload)
        client.disable_attachment(payload)
        client.change_session_limits(payload, access_token="token")
        client.reset_session_limits(access_token="token")
        client.change_certificate_limits(payload, access_token="token")
        client.reset_certificate_limits(access_token="token")
        client.set_rate_limits(payload, access_token="token")
        client.reset_rate_limits(access_token="token")
        client.restore_production_rate_limits(access_token="token")

    def test_peppol_client(self):
        client = PeppolClient(self.http)
        client._request_json = Mock(return_value={"ok": True})
        client.list_providers(page_offset=0, page_size=10)


class AsyncClientsTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_clients(self):
        http = object()
        response = HttpResponse(200, httpx.Headers({"x-ms-meta-hash": "hash"}), b"<xml/>")

        auth = AsyncAuthClient(http)
        auth._request_json = AsyncMock(return_value={"ok": True})
        auth._request_bytes = AsyncMock(return_value=b"{\"status\": \"ok\"}")
        await auth.get_active_sessions(page_size=10, continuation_token="cont", access_token="token")
        await auth.revoke_current_session("token")
        await auth.revoke_session("ref", "token")
        await auth.get_challenge()
        result = await auth.submit_xades_auth_request("<xml/>", verify_certificate_chain=True)
        self.assertEqual(result["status"], "ok")
        auth._request_bytes = AsyncMock(return_value=b"")
        self.assertIsNone(await auth.submit_xades_auth_request("<xml/>", verify_certificate_chain=None))
        await auth.submit_ksef_token_auth({"a": 1})
        await auth.get_auth_status("ref", "auth")
        await auth.redeem_token("auth")
        await auth.refresh_access_token("refresh")

        sessions = AsyncSessionsClient(http)
        sessions._request_json = AsyncMock(return_value={"referenceNumber": "ref"})
        sessions._request_bytes = AsyncMock(return_value=b"upo")
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
        await sessions.open_online_session({"a": 1}, access_token="token", upo_v43=True)
        await sessions.close_online_session("ref", "token")
        await sessions.send_online_invoice("ref", {"a": 1}, access_token="token")
        await sessions.open_batch_session({"a": 1}, access_token="token", upo_v43=True)
        await sessions.close_batch_session("ref", "token")
        await sessions.get_session_status("ref", "token")
        await sessions.get_session_invoices("ref", page_size=1, continuation_token="cont", access_token="token")
        await sessions.get_session_failed_invoices("ref", page_size=1, continuation_token="cont", access_token="token")
        await sessions.get_session_invoice_status("ref", "inv", access_token="token")
        await sessions.get_session_invoice_upo_by_ref("ref", "inv", access_token="token")
        await sessions.get_session_invoice_upo_by_ksef("ref", "ksef", access_token="token")
        await sessions.get_session_upo("ref", "upo", access_token="token")

        invoices = AsyncInvoicesClient(http)
        invoices._request_raw = AsyncMock(return_value=response)
        invoices._request_json = AsyncMock(return_value={"ok": True})
        invoices._request_bytes = AsyncMock(return_value=b"bytes")
        await invoices.get_invoice("ksef", access_token="token")
        await invoices.get_invoice_bytes("ksef", access_token="token")
        await invoices.query_invoice_metadata({"a": 1}, access_token="token", page_offset=0, page_size=10, sort_order="asc")
        await invoices.export_invoices({"a": 1}, access_token="token")
        await invoices.get_export_status("ref", access_token="token")
        await invoices.download_export_part("https://example.com")
        await invoices.download_package_part("https://example.com")
        await invoices.download_export_part_with_hash("https://example.com")

        permissions = AsyncPermissionsClient(http)
        permissions._request_json = AsyncMock(return_value={"ok": True})
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
        await permissions.query_authorizations_grants(payload, page_offset=0, page_size=10, access_token="token")
        await permissions.query_entities_roles(page_offset=0, page_size=10, access_token="token")
        await permissions.query_eu_entities_grants(payload, page_offset=0, page_size=10, access_token="token")
        await permissions.query_personal_grants(payload, page_offset=0, page_size=10, access_token="token")
        await permissions.query_persons_grants(payload, page_offset=0, page_size=10, access_token="token")
        await permissions.query_subordinate_entities_roles(payload, page_offset=0, page_size=10, access_token="token")
        await permissions.query_subunits_grants(payload, page_offset=0, page_size=10, access_token="token")

        certificates = AsyncCertificatesClient(http)
        certificates._request_json = AsyncMock(return_value={"ok": True})
        await certificates.get_limits("token")
        await certificates.get_enrollment_data("token")
        await certificates.send_enrollment(payload, access_token="token")
        await certificates.get_enrollment_status("ref", access_token="token")
        await certificates.query_certificates(payload, page_size=10, page_offset=0, access_token="token")
        await certificates.retrieve_certificate(payload, access_token="token")
        await certificates.revoke_certificate("serial", payload, access_token="token")

        tokens = AsyncTokensClient(http)
        tokens._request_json = AsyncMock(return_value={"ok": True})
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

        limits = AsyncLimitsClient(http)
        limits._request_json = AsyncMock(return_value={"ok": True})
        await limits.get_context_limits("token")
        await limits.get_subject_limits("token")

        rate_limits = AsyncRateLimitsClient(http)
        rate_limits._request_json = AsyncMock(return_value={"ok": True})
        await rate_limits.get_rate_limits("token")

        security = AsyncSecurityClient(http)
        security._request_json = AsyncMock(return_value={"ok": True})
        await security.get_public_key_certificates()
        security._request_bytes = AsyncMock(return_value=b"pem")
        self.assertEqual(await security.get_public_key_pem(), "pem")

        testdata = AsyncTestDataClient(http)
        testdata._request_json = AsyncMock(return_value={"ok": True})
        await testdata.create_subject(payload)
        await testdata.remove_subject(payload)
        await testdata.create_person(payload)
        await testdata.remove_person(payload)
        await testdata.grant_permissions(payload)
        await testdata.revoke_permissions(payload)
        await testdata.enable_attachment(payload)
        await testdata.disable_attachment(payload)
        await testdata.change_session_limits(payload, access_token="token")
        await testdata.reset_session_limits(access_token="token")
        await testdata.change_certificate_limits(payload, access_token="token")
        await testdata.reset_certificate_limits(access_token="token")
        await testdata.set_rate_limits(payload, access_token="token")
        await testdata.reset_rate_limits(access_token="token")
        await testdata.restore_production_rate_limits(access_token="token")

        peppol = AsyncPeppolClient(http)
        peppol._request_json = AsyncMock(return_value={"ok": True})
        await peppol.list_providers(page_offset=0, page_size=10)


if __name__ == "__main__":
    unittest.main()
