import unittest
from typing import Any, cast
from unittest.mock import AsyncMock, Mock, patch

import httpx

from ksef_client import models as m
from ksef_client.clients.auth import AsyncAuthClient, AuthClient, _parse_init_response
from ksef_client.clients.base import _serialize_json_payload
from ksef_client.clients.certificates import AsyncCertificatesClient, CertificatesClient
from ksef_client.clients.invoices import (
    AsyncInvoicesClient,
    InvoicesClient,
    _build_invoice_query_filters,
    _normalize_datetime_without_offset,
    _normalize_invoice_date_range_payload,
    _normalize_invoice_query_date_type,
    _normalize_invoice_query_subject_type,
    _SerializedInvoicePayload,
)
from ksef_client.clients.lighthouse import AsyncLighthouseClient, LighthouseClient
from ksef_client.clients.limits import AsyncLimitsClient, LimitsClient
from ksef_client.clients.peppol import AsyncPeppolClient, PeppolClient
from ksef_client.clients.permissions import (
    AsyncPermissionsClient,
    PermissionsClient,
    _page_params,
)
from ksef_client.clients.rate_limits import AsyncRateLimitsClient, RateLimitsClient
from ksef_client.clients.security import (
    AsyncSecurityClient,
    SecurityClient,
    _normalize_certificate_usage,
)
from ksef_client.clients.sessions import AsyncSessionsClient, SessionsClient
from ksef_client.clients.testdata import AsyncTestDataClient, TestDataClient
from ksef_client.clients.tokens import AsyncTokensClient, TokensClient
from ksef_client.http import HttpResponse


class JsonPayload:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        _ = omit_none
        return dict(self._payload)


class DummyHttp:
    def __init__(self, response: HttpResponse) -> None:
        self._response = response
        self.last_request_args: tuple[Any, ...] | None = None
        self.last_request_kwargs: dict[str, Any] | None = None

    def request(self, *args: Any, **kwargs: Any) -> HttpResponse:
        self.last_request_args = args
        self.last_request_kwargs = kwargs
        return self._response


class DummyAsyncHttp:
    def __init__(self, response: HttpResponse) -> None:
        self._response = response
        self.last_request_args: tuple[Any, ...] | None = None
        self.last_request_kwargs: dict[str, Any] | None = None

    async def request(self, *args: Any, **kwargs: Any) -> HttpResponse:
        self.last_request_args = args
        self.last_request_kwargs = kwargs
        return self._response


def _query_payload() -> Any:
    return cast(
        Any,
        JsonPayload(
            {
                "subjectType": "Subject1",
                "dateRange": {
                    "dateType": "Issue",
                    "from": "2025-01-02T10:15:00",
                    "to": "2025-01-02T11:15:00",
                },
            }
        ),
    )


def _export_payload() -> Any:
    return cast(
        Any,
        JsonPayload(
            {
                "encryption": {
                    "encryptedSymmetricKey": "abc",
                    "initializationVector": "def",
                },
                "onlyMetadata": True,
                "filters": {
                    "subjectType": "Subject1",
                    "dateRange": {
                        "dateType": "Issue",
                        "from": "2025-07-02T10:15:00",
                        "to": "2025-07-02T11:15:00",
                    },
                },
            }
        ),
    )


class ClientsTests(unittest.TestCase):
    def setUp(self):
        self.response = HttpResponse(200, httpx.Headers({"x-ms-meta-hash": "hash"}), b"<xml/>")
        self.http = DummyHttp(self.response)

    def test_auth_client(self):
        client = AuthClient(self.http)
        with (
            patch.object(client, "_request_model", Mock(return_value=object())) as request_model,
            patch.object(client, "_request_json", Mock()) as request_json,
            patch.object(
                client,
                "_request_bytes",
                Mock(
                    side_effect=[
                        b'{"referenceNumber":"ref","authenticationToken":{"token":"auth","validUntil":"2026-03-27T12:00:00Z"}}',
                        b"",
                    ]
                ),
            ) as request_bytes,
        ):
            client.get_active_sessions(
                page_size=10, continuation_token="cont", access_token="token"
            )
            client.revoke_current_session("token")
            client.revoke_session("ref", "token")
            client.get_challenge()
            result = client.submit_xades_auth_request(
                "<xml/>", verify_certificate_chain=True, enforce_xades_compliance=True
            )
            assert result is not None
            self.assertEqual(result.reference_number, "ref")
            self.assertIsNone(client.submit_xades_auth_request("<xml/>"))
            client.submit_ksef_token_auth(cast(Any, object()))
            client.get_auth_status("ref", "auth")
            client.redeem_token("auth")
            client.refresh_access_token("refresh")

            self.assertEqual(
                request_model.call_args_list[0].kwargs["headers"], {"x-continuation-token": "cont"}
            )
            self.assertEqual(request_model.call_args_list[0].kwargs["params"], {"pageSize": 10})
            self.assertEqual(
                request_bytes.call_args_list[0].kwargs["headers"]["X-KSeF-Feature"],
                "enforce-xades-compliance",
            )
            request_json.assert_any_call(
                "DELETE", "/auth/sessions/current", access_token="token", expected_status={204}
            )

        with patch.object(client, "_request_model", Mock(return_value=object())) as request_model:
            client.get_active_sessions(continuation_token="", access_token="token")
            self.assertIsNone(request_model.call_args.kwargs["headers"])
            self.assertIsNone(request_model.call_args.kwargs["params"])

    def test_parse_init_response_rejects_non_object_payload(self):
        with self.assertRaises(TypeError):
            _parse_init_response(b"[]", path="/auth/xades-signature")

    def test_serialize_json_payload_requires_typed_model(self):
        with self.assertRaisesRegex(TypeError, "typed model payload"):
            _serialize_json_payload(cast(Any, {"x": 1}))
        self.assertEqual(_serialize_json_payload(JsonPayload({"x": 1})), {"x": 1})
        self.assertEqual(
            _serialize_json_payload(
                _SerializedInvoicePayload({"dateRange": {"from": "2025-01-02T10:15:00"}})
            ),
            {"dateRange": {"from": "2025-01-02T10:15:00"}},
        )

    def test_sessions_client(self):
        client = SessionsClient(self.http)
        with (
            patch.object(client, "_request_model", Mock(return_value=object())) as request_model,
            patch.object(client, "_request_json", Mock()) as request_json,
            patch.object(client, "_request_bytes", Mock(return_value=b"upo")) as request_bytes,
        ):
            payload: Any = object()
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
            client.open_online_session(payload, access_token="token", upo_v43=True)
            client.send_online_invoice("ref", payload, access_token="token")
            client.open_batch_session(payload, access_token="token", upo_v43=True)
            client.get_session_invoices(
                "ref", page_size=1, continuation_token="cont", access_token="token"
            )
            client.get_session_failed_invoices(
                "ref", page_size=1, continuation_token="cont", access_token="token"
            )
            client.get_session_status("ref", access_token="token")
            client.get_session_invoice_status("ref", "inv", access_token="token")
            self.assertEqual(
                client.get_session_invoice_upo_by_ref("ref", "inv", access_token="token"), b"upo"
            )
            self.assertEqual(
                client.get_session_invoice_upo_by_ksef("ref", "ksef", access_token="token"), b"upo"
            )
            self.assertEqual(client.get_session_upo("ref", "upo", access_token="token"), b"upo")
            client.close_online_session("ref", "token")
            client.close_batch_session("ref", "token")

            self.assertEqual(
                request_model.call_args_list[0].kwargs["headers"], {"x-continuation-token": "cont"}
            )
            self.assertEqual(
                request_model.call_args_list[1].kwargs["headers"], {"X-KSeF-Feature": "upo-v4-3"}
            )
            self.assertEqual(
                request_model.call_args_list[3].kwargs["headers"], {"X-KSeF-Feature": "upo-v4-3"}
            )
            request_json.assert_any_call(
                "POST", "/sessions/online/ref/close", access_token="token", expected_status={204}
            )
            request_bytes.assert_any_call("GET", "/sessions/ref/upo/upo", access_token="token")

        with patch.object(client, "_request_model", Mock(return_value=object())) as request_model:
            client.get_sessions(
                session_type="online", statuses=[], continuation_token="", access_token="token"
            )
            self.assertEqual(request_model.call_args.kwargs["params"], {"sessionType": "online"})
            self.assertIsNone(request_model.call_args.kwargs["headers"])

    def test_invoices_client_and_helpers(self):
        client = InvoicesClient(self.http)
        with (
            patch.object(client, "_request_raw", Mock(return_value=self.response)),
            patch.object(client, "_request_model", Mock(return_value=object())) as request_model,
            patch.object(client, "_request_bytes", Mock(return_value=b"bytes")),
        ):
            self.assertEqual(client.get_invoice("ksef", access_token="token").sha256_base64, "hash")
            self.assertEqual(
                client.get_invoice_bytes("ksef", access_token="token").sha256_base64, "hash"
            )
            client.query_invoice_metadata(
                _query_payload(),
                access_token="token",
                page_offset=0,
                page_size=10,
                sort_order="asc",
            )
            client.export_invoices(_export_payload(), access_token="token")
            client.get_export_status("ref", access_token="token")
            client.download_export_part("https://example.com")
            client.download_package_part("https://example.com")
            self.assertEqual(
                client.download_export_part_with_hash("https://example.com").sha256_base64, "hash"
            )
            client.query_invoice_metadata_by_date_range(
                subject_type="Subject1",
                date_type="Issue",
                date_from="2025-01-02T10:15:00",
                date_to="2025-01-02T11:15:00",
                access_token="token",
                page_size=5,
            )
            self.assertEqual(
                request_model.call_args_list[0].kwargs["json"]["dateRange"]["from"],
                "2025-01-02T10:15:00+01:00",
            )
            self.assertEqual(
                request_model.call_args_list[1].kwargs["json"]["filters"]["dateRange"]["from"],
                "2025-07-02T10:15:00+02:00",
            )
            self.assertTrue(request_model.call_args_list[1].kwargs["json"]["onlyMetadata"])
            self.assertEqual(
                request_model.call_args_list[3].kwargs["json"]["dateRange"]["dateType"],
                "Issue",
            )
            self.assertEqual(request_model.call_args_list[3].kwargs["params"], {"pageSize": 5})

        with patch.object(client, "_request_model", Mock(return_value=object())) as request_model:
            client.query_invoice_metadata(
                cast(Any, JsonPayload({"subjectType": "Subject1"})),
                access_token="token",
            )
            self.assertIsNone(request_model.call_args.kwargs["params"])
        with self.assertRaisesRegex(TypeError, "typed model payload"):
            client.query_invoice_metadata(
                cast(Any, {"subjectType": "Subject1"}),
                access_token="token",
            )
        with self.assertRaisesRegex(TypeError, "typed model payload"):
            client.export_invoices(cast(Any, {"filters": {}}), access_token="token")

        normalized = _normalize_invoice_date_range_payload(
            {"dateRange": {"from": 1, "to": None}, "filters": {"dateRange": "invalid"}}
        )
        self.assertEqual(normalized["dateRange"]["from"], 1)
        self.assertEqual(_normalize_datetime_without_offset("2025-01-02"), "2025-01-02")
        self.assertEqual(
            _normalize_datetime_without_offset("not-a-dateT10:15:00"), "not-a-dateT10:15:00"
        )
        self.assertEqual(
            _normalize_datetime_without_offset("2025-01-02T10:15:00+01"), "2025-01-02T10:15:00+01"
        )
        built_filters = _build_invoice_query_filters(
            subject_type="Subject1",
            date_type="Issue",
            date_from="2025-01-02T10:15:00",
            date_to="2025-01-02T11:15:00",
        )
        self.assertEqual(built_filters.subject_type.value, "Subject1")
        self.assertEqual(built_filters.date_range.date_type.value, "Issue")
        self.assertEqual(
            _normalize_invoice_query_subject_type(m.InvoiceQuerySubjectType.SUBJECT1),
            m.InvoiceQuerySubjectType.SUBJECT1,
        )
        self.assertEqual(
            _normalize_invoice_query_date_type(m.InvoiceQueryDateType.ISSUE),
            m.InvoiceQueryDateType.ISSUE,
        )
        with self.assertRaisesRegex(ValueError, "Unsupported invoice query subject type"):
            _normalize_invoice_query_subject_type("bad-value")
        with self.assertRaisesRegex(ValueError, "Unsupported invoice query date type"):
            _normalize_invoice_query_date_type("bad-value")
        with self.assertRaisesRegex(TypeError, "Invoice request payload is required"):
            client.query_invoice_metadata(cast(Any, None), access_token="token")
        payload_copy = _SerializedInvoicePayload({"filters": {"dateRange": {"from": "a"}}}).to_dict(
            omit_none=False
        )
        self.assertEqual(payload_copy["filters"]["dateRange"]["from"], "a")

    def test_invoices_client_query_metadata_serializes_typed_payload_once(self):
        response = HttpResponse(
            200,
            httpx.Headers(),
            (
                b'{"invoices":[{"ksefNumber":"KSEF-1","currency":"PLN","grossAmount":123.45}],'
                b'"continuationToken":"ct-1"}'
            ),
        )
        http = DummyHttp(response)
        client = InvoicesClient(http)
        invoice_payload = m.InvoiceQueryFilters.from_dict(
            {
                "subjectType": "Subject1",
                "dateRange": {
                    "dateType": "Issue",
                    "from": "2025-01-02T10:15:00",
                    "to": "2025-01-02T11:15:00",
                },
            }
        )

        result = client.query_invoice_metadata(invoice_payload, access_token="token")

        assert http.last_request_kwargs is not None
        self.assertEqual(
            http.last_request_kwargs["json"]["dateRange"]["from"],
            "2025-01-02T10:15:00+01:00",
        )
        self.assertEqual(
            http.last_request_kwargs["json"]["dateRange"]["to"],
            "2025-01-02T11:15:00+01:00",
        )
        self.assertEqual(result.invoices[0].ksef_number, "KSEF-1")
        self.assertEqual(result.invoices[0].currency, "PLN")
        self.assertEqual(result.invoices[0].gross_amount, 123.45)
        self.assertEqual(result.continuation_token, "ct-1")

    def test_other_clients(self):
        payload: Any = object()

        permissions = PermissionsClient(self.http)
        with patch.object(permissions, "_request_model", Mock(return_value=object())):
            permissions.check_attachment_permission_status("token")
            permissions.grant_authorization(payload, access_token="token")
            permissions.revoke_authorization("perm", access_token="token")
            permissions.revoke_common_permission("perm", access_token="token")
            permissions.grant_entity(payload, access_token="token")
            permissions.grant_eu_entity(payload, access_token="token")
            permissions.grant_eu_entity_admin(payload, access_token="token")
            permissions.grant_indirect(payload, access_token="token")
            permissions.grant_person(payload, access_token="token")
            permissions.grant_subunit(payload, access_token="token")
            permissions.get_operation_status("op-ref", access_token="token")
            permissions.query_authorizations_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            permissions.query_entities_roles(page_offset=0, page_size=10, access_token="token")
            permissions.query_entities_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            permissions.query_eu_entities_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            permissions.query_personal_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            permissions.query_persons_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            permissions.query_subordinate_entities_roles(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            permissions.query_subunits_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
        self.assertEqual(_page_params(None, None), {})

        certificates = CertificatesClient(self.http)
        with (
            patch.object(
                certificates, "_request_model", Mock(return_value=object())
            ) as request_model,
            patch.object(certificates, "_request_json", Mock()) as request_json,
        ):
            certificates.get_limits("token")
            certificates.get_enrollment_data("token")
            certificates.send_enrollment(payload, access_token="token")
            certificates.get_enrollment_status("ref", access_token="token")
            certificates.query_certificates(
                payload, page_size=10, page_offset=0, access_token="token"
            )
            certificates.retrieve_certificate(payload, access_token="token")
            certificates.revoke_certificate("serial", payload, access_token="token")
            self.assertEqual(
                request_model.call_args_list[4].kwargs["params"], {"pageSize": 10, "pageOffset": 0}
            )
            request_json.assert_called_once()

        tokens = TokensClient(self.http)
        with (
            patch.object(tokens, "_request_model", Mock(return_value=object())) as request_model,
            patch.object(tokens, "_request_json", Mock()) as request_json,
        ):
            tokens.generate_token(payload, access_token="token")
            tokens.list_tokens(
                access_token="token",
                statuses=["active"],
                description="desc",
                author_identifier="id",
                author_identifier_type="nip",
                page_size=10,
                continuation_token="cont",
            )
            tokens.get_token_status("ref", access_token="token")
            tokens.revoke_token("ref", access_token="token")
            self.assertEqual(
                request_model.call_args_list[1].kwargs["headers"], {"x-continuation-token": "cont"}
            )
            request_json.assert_called_once()

        with patch.object(tokens, "_request_model", Mock(return_value=object())) as request_model:
            tokens.list_tokens(
                access_token="token",
                statuses=[],
                description="",
                author_identifier="",
                author_identifier_type="",
                continuation_token="",
            )
            self.assertIsNone(request_model.call_args.kwargs["params"])
            self.assertIsNone(request_model.call_args.kwargs["headers"])

        limits = LimitsClient(self.http)
        with patch.object(limits, "_request_model", Mock(return_value=object())):
            limits.get_context_limits("token")
            limits.get_subject_limits("token")

        rate_limits = RateLimitsClient(self.http)
        with patch.object(rate_limits, "_request_model", Mock(return_value=object())):
            rate_limits.get_rate_limits("token")

        security = SecurityClient(self.http)
        with patch.object(
            security, "_request_model_list", Mock(return_value=[object()])
        ) as request_model_list:
            security.get_public_key_certificates()
            request_model_list.assert_called_once()
        security_certificates = [
            m.PublicKeyCertificate.from_dict(
                {
                    "certificate": "pem-1",
                    "usage": ["KsefTokenEncryption"],
                    "validFrom": "2026-01-01T00:00:00Z",
                    "validTo": "2026-12-31T23:59:59Z",
                }
            )
        ]
        with patch.object(
            security, "_request_model_list", Mock(return_value=security_certificates)
        ):
            selected = security.get_public_key_certificate(
                m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION
            )
            self.assertEqual(selected.certificate, "pem-1")
            selected_pem = security.get_public_key_certificate_pem("KsefTokenEncryption")
            self.assertEqual(selected_pem, "pem-1")
            selected_from_str = security.get_public_key_certificate("KsefTokenEncryption")
            self.assertEqual(selected_from_str.certificate, "pem-1")
            self.assertEqual(
                _normalize_certificate_usage("ksef_token_encryption"),
                m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
            )
            with self.assertRaises(ValueError):
                security.get_public_key_certificate("SymmetricKeyEncryption")
            with self.assertRaises(ValueError):
                _normalize_certificate_usage("bad-usage")

        testdata = TestDataClient(self.http)
        with (
            patch.object(testdata, "_request_model", Mock(return_value=object())) as request_model,
            patch.object(testdata, "_request_json", Mock()) as request_json,
        ):
            testdata.create_subject(payload)
            testdata.remove_subject(payload)
            testdata.create_person(payload)
            testdata.remove_person(payload)
            testdata.grant_permissions(payload)
            testdata.revoke_permissions(payload)
            testdata.enable_attachment(payload)
            testdata.disable_attachment(payload)
            testdata.block_context_authentication(payload)
            testdata.unblock_context_authentication(payload)
            testdata.change_session_limits(payload, access_token="token")
            testdata.reset_session_limits(access_token="token")
            testdata.change_certificate_limits(payload, access_token="token")
            testdata.reset_certificate_limits(access_token="token")
            testdata.set_rate_limits(payload, access_token="token")
            testdata.reset_rate_limits(access_token="token")
            testdata.restore_production_rate_limits(access_token="token")
            self.assertEqual(request_json.call_count, 10)
            self.assertEqual(request_model.call_count, 7)

        peppol = PeppolClient(self.http)
        with patch.object(peppol, "_request_model", Mock(return_value=object())) as request_model:
            peppol.list_providers(page_offset=0, page_size=10)
            self.assertEqual(
                request_model.call_args.kwargs["params"], {"pageOffset": 0, "pageSize": 10}
            )
        with patch.object(peppol, "_request_model", Mock(return_value=object())) as request_model:
            peppol.list_providers()
            self.assertIsNone(request_model.call_args.kwargs["params"])

    def test_lighthouse_client(self):
        client = LighthouseClient(self.http, "https://api-latarnia-test.ksef.mf.gov.pl")
        with patch.object(
            client,
            "_request_json",
            Mock(side_effect=[{"status": "AVAILABLE", "messages": []}, []]),
        ) as request_json:
            self.assertEqual(client.get_status().status.value, "AVAILABLE")
            self.assertEqual(client.get_messages(), [])
            self.assertEqual(
                request_json.call_args_list[0].args[1],
                "https://api-latarnia-test.ksef.mf.gov.pl/status",
            )
            self.assertEqual(
                request_json.call_args_list[1].args[1],
                "https://api-latarnia-test.ksef.mf.gov.pl/messages",
            )

        with patch.object(client, "_request_json", Mock(side_effect=[None, {"unexpected": True}])):
            self.assertEqual(client.get_status().status.value, "AVAILABLE")
            self.assertEqual(client.get_messages(), [])

        with self.assertRaises(ValueError):
            LighthouseClient(self.http, "").get_status()


class AsyncClientsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.response = HttpResponse(200, httpx.Headers({"x-ms-meta-hash": "hash"}), b"<xml/>")
        self.http = DummyAsyncHttp(self.response)

    async def test_async_auth_client(self):
        auth = AsyncAuthClient(self.http)
        with (
            patch.object(auth, "_request_model", AsyncMock(return_value=object())) as request_model,
            patch.object(auth, "_request_json", AsyncMock()) as request_json,
            patch.object(
                auth,
                "_request_bytes",
                AsyncMock(
                    side_effect=[
                        b'{"referenceNumber":"ref","authenticationToken":{"token":"auth","validUntil":"2026-03-27T12:00:00Z"}}',
                        b"",
                    ]
                ),
            ) as request_bytes,
        ):
            await auth.get_active_sessions(
                page_size=10, continuation_token="cont", access_token="token"
            )
            await auth.revoke_current_session("token")
            await auth.revoke_session("ref", "token")
            await auth.get_challenge()
            result = await auth.submit_xades_auth_request(
                "<xml/>",
                verify_certificate_chain=True,
                enforce_xades_compliance=True,
            )
            assert result is not None
            self.assertEqual(result.reference_number, "ref")
            self.assertIsNone(await auth.submit_xades_auth_request("<xml/>"))
            await auth.submit_ksef_token_auth(cast(Any, object()))
            await auth.get_auth_status("ref", "auth")
            await auth.redeem_token("auth")
            await auth.refresh_access_token("refresh")
            self.assertEqual(
                request_model.call_args_list[0].kwargs["headers"], {"x-continuation-token": "cont"}
            )
            self.assertEqual(
                request_bytes.call_args_list[0].kwargs["headers"]["X-KSeF-Feature"],
                "enforce-xades-compliance",
            )
            request_json.assert_any_await(
                "DELETE", "/auth/sessions/current", access_token="token", expected_status={204}
            )

        with patch.object(
            auth, "_request_model", AsyncMock(return_value=object())
        ) as request_model:
            await auth.get_active_sessions(continuation_token="", access_token="token")
            self.assertIsNone(request_model.call_args.kwargs["headers"])
            self.assertIsNone(request_model.call_args.kwargs["params"])

    async def test_async_sessions_invoices_and_other_clients(self):
        payload: Any = object()

        sessions = AsyncSessionsClient(self.http)
        with (
            patch.object(
                sessions, "_request_model", AsyncMock(return_value=object())
            ) as request_model,
            patch.object(sessions, "_request_json", AsyncMock()) as request_json,
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
            await sessions.open_online_session(payload, access_token="token", upo_v43=True)
            await sessions.send_online_invoice("ref", payload, access_token="token")
            await sessions.open_batch_session(payload, access_token="token", upo_v43=True)
            await sessions.get_session_invoices(
                "ref", page_size=1, continuation_token="cont", access_token="token"
            )
            await sessions.get_session_failed_invoices(
                "ref", page_size=1, continuation_token="cont", access_token="token"
            )
            await sessions.get_session_invoice_status("ref", "inv", access_token="token")
            await sessions.get_session_invoice_upo_by_ref("ref", "inv", access_token="token")
            await sessions.get_session_invoice_upo_by_ksef("ref", "ksef", access_token="token")
            await sessions.get_session_upo("ref", "upo", access_token="token")
            await sessions.close_online_session("ref", "token")
            await sessions.close_batch_session("ref", "token")
            await sessions.get_session_status("ref", "token")
            self.assertEqual(
                request_model.call_args_list[0].kwargs["params"]["referenceNumber"], "ref"
            )
            self.assertEqual(
                request_model.call_args_list[1].kwargs["headers"], {"X-KSeF-Feature": "upo-v4-3"}
            )
            request_json.assert_any_await(
                "POST", "/sessions/online/ref/close", access_token="token", expected_status={204}
            )

        invoices = AsyncInvoicesClient(self.http)
        with (
            patch.object(invoices, "_request_raw", AsyncMock(return_value=self.response)),
            patch.object(
                invoices, "_request_model", AsyncMock(return_value=object())
            ) as request_model,
            patch.object(invoices, "_request_bytes", AsyncMock(return_value=b"bytes")),
        ):
            await invoices.get_invoice("ksef", access_token="token")
            await invoices.get_invoice_bytes("ksef", access_token="token")
            await invoices.query_invoice_metadata(_query_payload(), access_token="token")
            await invoices.query_invoice_metadata_by_date_range(
                subject_type="Subject1",
                date_type="Issue",
                date_from="2025-01-02T10:15:00",
                date_to="2025-01-02T11:15:00",
                access_token="token",
                page_offset=0,
                page_size=5,
                sort_order="Desc",
            )
            await invoices.export_invoices(_export_payload(), access_token="token")
            await invoices.get_export_status("ref", access_token="token")
            await invoices.download_export_part("https://example.com")
            await invoices.download_package_part("https://example.com")
            await invoices.download_export_part_with_hash("https://example.com")
            self.assertEqual(
                request_model.call_args_list[0].kwargs["json"]["dateRange"]["from"],
                "2025-01-02T10:15:00+01:00",
            )
            self.assertEqual(
                request_model.call_args_list[2].kwargs["json"]["filters"]["dateRange"]["from"],
                "2025-07-02T10:15:00+02:00",
            )
            self.assertEqual(
                request_model.call_args_list[1].kwargs["params"],
                {"pageOffset": 0, "pageSize": 5, "sortOrder": "Desc"},
            )
        with self.assertRaisesRegex(TypeError, "typed model payload"):
            await invoices.query_invoice_metadata(
                cast(Any, {"subjectType": "Subject1"}),
                access_token="token",
            )
        with self.assertRaisesRegex(TypeError, "typed model payload"):
            await invoices.export_invoices(cast(Any, {"filters": {}}), access_token="token")

    async def test_async_invoices_client_query_metadata_serializes_typed_payload_once(self):
        response = HttpResponse(
            200,
            httpx.Headers(),
            (
                b'{"invoices":[{"ksefNumber":"KSEF-1","currency":"PLN","grossAmount":123.45}],'
                b'"continuationToken":"ct-1"}'
            ),
        )
        http = DummyAsyncHttp(response)
        invoices = AsyncInvoicesClient(http)
        invoice_payload = m.InvoiceQueryFilters.from_dict(
            {
                "subjectType": "Subject1",
                "dateRange": {
                    "dateType": "Issue",
                    "from": "2025-01-02T10:15:00",
                    "to": "2025-01-02T11:15:00",
                },
            }
        )

        result = await invoices.query_invoice_metadata(invoice_payload, access_token="token")

        assert http.last_request_kwargs is not None
        self.assertEqual(
            http.last_request_kwargs["json"]["dateRange"]["from"],
            "2025-01-02T10:15:00+01:00",
        )
        self.assertEqual(
            http.last_request_kwargs["json"]["dateRange"]["to"],
            "2025-01-02T11:15:00+01:00",
        )
        self.assertEqual(result.invoices[0].ksef_number, "KSEF-1")
        self.assertEqual(result.invoices[0].currency, "PLN")
        self.assertEqual(result.invoices[0].gross_amount, 123.45)
        self.assertEqual(result.continuation_token, "ct-1")

        payload: Any = object()
        permissions = AsyncPermissionsClient(self.http)
        with patch.object(permissions, "_request_model", AsyncMock(return_value=object())):
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
            await permissions.get_operation_status("op-ref", access_token="token")
            await permissions.query_authorizations_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            await permissions.query_entities_roles(
                page_offset=0, page_size=10, access_token="token"
            )
            await permissions.query_entities_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            await permissions.query_eu_entities_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            await permissions.query_personal_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            await permissions.query_persons_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            await permissions.query_subordinate_entities_roles(
                payload, page_offset=0, page_size=10, access_token="token"
            )
            await permissions.query_subunits_grants(
                payload, page_offset=0, page_size=10, access_token="token"
            )

        certificates = AsyncCertificatesClient(self.http)
        with (
            patch.object(
                certificates, "_request_model", AsyncMock(return_value=object())
            ) as request_model,
            patch.object(certificates, "_request_json", AsyncMock()) as request_json,
        ):
            await certificates.get_limits("token")
            await certificates.get_enrollment_data("token")
            await certificates.send_enrollment(payload, access_token="token")
            await certificates.get_enrollment_status("ref", access_token="token")
            await certificates.query_certificates(
                payload, page_size=10, page_offset=0, access_token="token"
            )
            await certificates.retrieve_certificate(payload, access_token="token")
            await certificates.revoke_certificate("serial", payload, access_token="token")
            self.assertEqual(
                request_model.call_args_list[4].kwargs["params"], {"pageSize": 10, "pageOffset": 0}
            )
            request_json.assert_awaited_once()

        tokens = AsyncTokensClient(self.http)
        with (
            patch.object(
                tokens, "_request_model", AsyncMock(return_value=object())
            ) as request_model,
            patch.object(tokens, "_request_json", AsyncMock()) as request_json,
        ):
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
            self.assertEqual(
                request_model.call_args_list[1].kwargs["headers"], {"x-continuation-token": "cont"}
            )
            self.assertEqual(request_model.call_args_list[1].kwargs["params"]["pageSize"], 10)
            request_json.assert_awaited_once()
        with patch.object(
            tokens, "_request_model", AsyncMock(return_value=object())
        ) as request_model:
            await tokens.list_tokens(access_token="token", continuation_token="")
            self.assertIsNone(request_model.call_args.kwargs["headers"])

        limits = AsyncLimitsClient(self.http)
        with patch.object(limits, "_request_model", AsyncMock(return_value=object())):
            await limits.get_context_limits("token")
            await limits.get_subject_limits("token")

        rate_limits = AsyncRateLimitsClient(self.http)
        with patch.object(rate_limits, "_request_model", AsyncMock(return_value=object())):
            await rate_limits.get_rate_limits("token")

        security = AsyncSecurityClient(self.http)
        with patch.object(
            security, "_request_model_list", AsyncMock(return_value=[object()])
        ) as request_model_list:
            await security.get_public_key_certificates()
            request_model_list.assert_awaited_once()
        security_certificates = [
            m.PublicKeyCertificate.from_dict(
                {
                    "certificate": "pem-1",
                    "usage": ["SymmetricKeyEncryption"],
                    "validFrom": "2026-01-01T00:00:00Z",
                    "validTo": "2026-12-31T23:59:59Z",
                }
            )
        ]
        with patch.object(
            security, "_request_model_list", AsyncMock(return_value=security_certificates)
        ):
            selected = await security.get_public_key_certificate(
                m.PublicKeyCertificateUsage.SYMMETRICKEYENCRYPTION
            )
            self.assertEqual(selected.certificate, "pem-1")
            selected_pem = await security.get_public_key_certificate_pem(
                "SymmetricKeyEncryption"
            )
            self.assertEqual(selected_pem, "pem-1")
            selected_from_str = await security.get_public_key_certificate(
                "SymmetricKeyEncryption"
            )
            self.assertEqual(selected_from_str.certificate, "pem-1")
            self.assertEqual(
                _normalize_certificate_usage("symmetric-key-encryption"),
                m.PublicKeyCertificateUsage.SYMMETRICKEYENCRYPTION,
            )
            with self.assertRaises(ValueError):
                await security.get_public_key_certificate("KsefTokenEncryption")

        testdata = AsyncTestDataClient(self.http)
        with (
            patch.object(
                testdata, "_request_model", AsyncMock(return_value=object())
            ) as request_model,
            patch.object(testdata, "_request_json", AsyncMock()) as request_json,
        ):
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
            self.assertEqual(request_json.await_count, 10)
            self.assertEqual(request_model.await_count, 7)

        peppol = AsyncPeppolClient(self.http)
        with patch.object(
            peppol, "_request_model", AsyncMock(return_value=object())
        ) as request_model:
            await peppol.list_providers(page_offset=0, page_size=10)
            await peppol.list_providers()
            self.assertIsNone(request_model.call_args.kwargs["params"])

    async def test_async_lighthouse_client(self):
        client = AsyncLighthouseClient(self.http, "https://api-latarnia-test.ksef.mf.gov.pl")
        with patch.object(
            client,
            "_request_json",
            AsyncMock(side_effect=[{"status": "AVAILABLE", "messages": []}, []]),
        ) as request_json:
            self.assertEqual((await client.get_status()).status.value, "AVAILABLE")
            self.assertEqual(await client.get_messages(), [])
            self.assertEqual(
                request_json.call_args_list[0].args[1],
                "https://api-latarnia-test.ksef.mf.gov.pl/status",
            )
            self.assertEqual(
                request_json.call_args_list[1].args[1],
                "https://api-latarnia-test.ksef.mf.gov.pl/messages",
            )

        with patch.object(
            client, "_request_json", AsyncMock(side_effect=[None, {"unexpected": True}])
        ):
            self.assertEqual((await client.get_status()).status.value, "AVAILABLE")
            self.assertEqual(await client.get_messages(), [])

        with self.assertRaises(ValueError):
            await AsyncLighthouseClient(self.http, "").get_messages()


if __name__ == "__main__":
    unittest.main()
