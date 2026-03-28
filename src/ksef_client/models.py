from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import openapi_models as _openapi_models

for _name in dir(_openapi_models):
    if not _name.startswith("_"):
        globals()[_name] = getattr(_openapi_models, _name)

AuthenticationMethod = _openapi_models.AuthenticationMethod
AuthenticationMethodInfo = _openapi_models.AuthenticationMethodInfo
InvoicingMode = _openapi_models.InvoicingMode
PublicKeyCertificateUsage = _openapi_models.PublicKeyCertificateUsage


@dataclass(frozen=True)
class FileMetadata:
    file_size: int
    sha256_base64: str


@dataclass(frozen=True)
class InvoiceContent:
    content: str
    sha256_base64: str | None = None


@dataclass(frozen=True)
class BinaryContent:
    content: bytes
    sha256_base64: str | None = None


@dataclass(frozen=True)
class StatusInfo:
    code: int
    description: str
    details: list[str] | None = None
    extensions: dict[str, Any] | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> StatusInfo:
        raw_extensions = data.get("extensions")
        return StatusInfo(
            code=int(data.get("code", 0)),
            description=str(data.get("description", "")),
            details=data.get("details"),
            extensions=raw_extensions if isinstance(raw_extensions, dict) else None,
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "description": self.description,
        }
        if not omit_none or self.details is not None:
            payload["details"] = self.details
        if not omit_none or self.extensions is not None:
            payload["extensions"] = self.extensions
        return payload


@dataclass(frozen=True)
class TokenInfo:
    token: str
    valid_until: str | None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> TokenInfo:
        return TokenInfo(
            token=str(data.get("token", "")),
            valid_until=data.get("validUntil"),
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {"token": self.token}
        if not omit_none or self.valid_until is not None:
            payload["validUntil"] = self.valid_until
        return payload


@dataclass(frozen=True)
class AuthenticationChallengeResponse:
    challenge: str
    timestamp: str
    timestamp_ms: int
    client_ip: str | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> AuthenticationChallengeResponse:
        raw_client_ip = data.get("clientIp")
        return AuthenticationChallengeResponse(
            challenge=str(data.get("challenge", "")),
            timestamp=str(data.get("timestamp", "")),
            timestamp_ms=int(data.get("timestampMs", 0)),
            client_ip=str(raw_client_ip) if raw_client_ip is not None else None,
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "challenge": self.challenge,
            "timestamp": self.timestamp,
            "timestampMs": self.timestamp_ms,
        }
        if not omit_none or self.client_ip is not None:
            payload["clientIp"] = self.client_ip
        return payload


@dataclass(frozen=True)
class AuthenticationInitResponse:
    reference_number: str
    authentication_token: TokenInfo

    @staticmethod
    def from_dict(data: dict[str, Any]) -> AuthenticationInitResponse:
        return AuthenticationInitResponse(
            reference_number=str(data.get("referenceNumber", "")),
            authentication_token=TokenInfo.from_dict(data.get("authenticationToken", {})),
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        return {
            "referenceNumber": self.reference_number,
            "authenticationToken": self.authentication_token.to_dict(omit_none=omit_none),
        }


@dataclass(frozen=True)
class AuthenticationOperationStatusResponse:
    status: StatusInfo
    authentication_method: AuthenticationMethod | None = None
    authentication_method_info: AuthenticationMethodInfo | None = None
    start_date: str | None = None
    is_token_redeemed: bool | None = None
    last_token_refresh_date: str | None = None
    refresh_token_valid_until: str | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> AuthenticationOperationStatusResponse:
        raw_method = data.get("authenticationMethod")
        raw_method_info = data.get("authenticationMethodInfo")
        return AuthenticationOperationStatusResponse(
            status=StatusInfo.from_dict(data.get("status", {})),
            authentication_method=(
                AuthenticationMethod(raw_method) if raw_method is not None else None
            ),
            authentication_method_info=(
                AuthenticationMethodInfo.from_dict(raw_method_info)
                if isinstance(raw_method_info, dict)
                else None
            ),
            start_date=str(data["startDate"]) if data.get("startDate") is not None else None,
            is_token_redeemed=(
                bool(data["isTokenRedeemed"])
                if data.get("isTokenRedeemed") is not None
                else None
            ),
            last_token_refresh_date=(
                str(data["lastTokenRefreshDate"])
                if data.get("lastTokenRefreshDate") is not None
                else None
            ),
            refresh_token_valid_until=(
                str(data["refreshTokenValidUntil"])
                if data.get("refreshTokenValidUntil") is not None
                else None
            ),
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status.to_dict(omit_none=omit_none),
        }
        if not omit_none or self.authentication_method is not None:
            payload["authenticationMethod"] = (
                self.authentication_method.value
                if self.authentication_method is not None
                else None
            )
        if not omit_none or self.authentication_method_info is not None:
            payload["authenticationMethodInfo"] = (
                self.authentication_method_info.to_dict(omit_none=omit_none)
                if self.authentication_method_info is not None
                else None
            )
        if not omit_none or self.start_date is not None:
            payload["startDate"] = self.start_date
        if not omit_none or self.is_token_redeemed is not None:
            payload["isTokenRedeemed"] = self.is_token_redeemed
        if not omit_none or self.last_token_refresh_date is not None:
            payload["lastTokenRefreshDate"] = self.last_token_refresh_date
        if not omit_none or self.refresh_token_valid_until is not None:
            payload["refreshTokenValidUntil"] = self.refresh_token_valid_until
        return payload


@dataclass(frozen=True)
class AuthenticationTokensResponse:
    access_token: TokenInfo
    refresh_token: TokenInfo

    @staticmethod
    def from_dict(data: dict[str, Any]) -> AuthenticationTokensResponse:
        return AuthenticationTokensResponse(
            access_token=TokenInfo.from_dict(data.get("accessToken", {})),
            refresh_token=TokenInfo.from_dict(data.get("refreshToken", {})),
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        return {
            "accessToken": self.access_token.to_dict(omit_none=omit_none),
            "refreshToken": self.refresh_token.to_dict(omit_none=omit_none),
        }


@dataclass(frozen=True)
class AuthenticationTokenRefreshResponse:
    access_token: TokenInfo

    @staticmethod
    def from_dict(data: dict[str, Any]) -> AuthenticationTokenRefreshResponse:
        return AuthenticationTokenRefreshResponse(
            access_token=TokenInfo.from_dict(data.get("accessToken", {})),
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        return {"accessToken": self.access_token.to_dict(omit_none=omit_none)}


class LighthouseKsefStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    MAINTENANCE = "MAINTENANCE"
    FAILURE = "FAILURE"
    TOTAL_FAILURE = "TOTAL_FAILURE"


class LighthouseMessageCategory(str, Enum):
    FAILURE = "FAILURE"
    TOTAL_FAILURE = "TOTAL_FAILURE"
    MAINTENANCE = "MAINTENANCE"


class LighthouseMessageType(str, Enum):
    FAILURE_START = "FAILURE_START"
    FAILURE_END = "FAILURE_END"
    MAINTENANCE_ANNOUNCEMENT = "MAINTENANCE_ANNOUNCEMENT"


def _parse_enum(value: Any, enum_type: type[Enum], default: Enum) -> Enum:
    try:
        return enum_type(value)
    except Exception:
        return default


@dataclass(frozen=True)
class LighthouseMessage:
    id: str
    event_id: int
    category: LighthouseMessageCategory
    type: LighthouseMessageType
    title: str
    text: str
    start: str
    end: str | None
    version: int
    published: str

    @staticmethod
    def from_dict(data: dict[str, Any]) -> LighthouseMessage:
        return LighthouseMessage(
            id=str(data.get("id", "")),
            event_id=int(data.get("eventId", 0)),
            category=LighthouseMessageCategory(
                _parse_enum(
                    data.get("category"),
                    LighthouseMessageCategory,
                    LighthouseMessageCategory.FAILURE,
                )
            ),
            type=LighthouseMessageType(
                _parse_enum(
                    data.get("type"),
                    LighthouseMessageType,
                    LighthouseMessageType.FAILURE_START,
                )
            ),
            title=str(data.get("title", "")),
            text=str(data.get("text", "")),
            start=str(data.get("start", "")),
            end=str(data["end"]) if data.get("end") is not None else None,
            version=int(data.get("version", 0)),
            published=str(data.get("published", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "eventId": self.event_id,
            "category": self.category.value,
            "type": self.type.value,
            "title": self.title,
            "text": self.text,
            "start": self.start,
            "end": self.end,
            "version": self.version,
            "published": self.published,
        }


@dataclass(frozen=True)
class LighthouseStatusResponse:
    status: LighthouseKsefStatus
    messages: list[LighthouseMessage] | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> LighthouseStatusResponse:
        raw_messages = data.get("messages")
        messages = (
            [LighthouseMessage.from_dict(item) for item in raw_messages]
            if isinstance(raw_messages, list)
            else None
        )
        return LighthouseStatusResponse(
            status=LighthouseKsefStatus(
                _parse_enum(
                    data.get("status"),
                    LighthouseKsefStatus,
                    LighthouseKsefStatus.AVAILABLE,
                )
            ),
            messages=messages,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"status": self.status.value}
        if self.messages is not None:
            payload["messages"] = [message.to_dict() for message in self.messages]
        return payload


@dataclass(frozen=True)
class PublicKeyCertificate:
    certificate: str
    usage: list[PublicKeyCertificateUsage] = field(default_factory=list)
    valid_from: str | None = None
    valid_to: str | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> PublicKeyCertificate:
        raw_usage = data.get("usage")
        usage_values = raw_usage if isinstance(raw_usage, list) else []
        return PublicKeyCertificate(
            certificate=str(data.get("certificate", "")),
            usage=[PublicKeyCertificateUsage(str(item)) for item in usage_values],
            valid_from=str(data["validFrom"]) if data.get("validFrom") is not None else None,
            valid_to=str(data["validTo"]) if data.get("validTo") is not None else None,
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "certificate": self.certificate,
            "usage": [item.value for item in self.usage],
        }
        if not omit_none or self.valid_from is not None:
            payload["validFrom"] = self.valid_from
        if not omit_none or self.valid_to is not None:
            payload["validTo"] = self.valid_to
        return payload


@dataclass(frozen=True)
class OpenOnlineSessionResponse:
    reference_number: str
    valid_until: str | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> OpenOnlineSessionResponse:
        return OpenOnlineSessionResponse(
            reference_number=str(data.get("referenceNumber", "")),
            valid_until=str(data["validUntil"]) if data.get("validUntil") is not None else None,
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {"referenceNumber": self.reference_number}
        if not omit_none or self.valid_until is not None:
            payload["validUntil"] = self.valid_until
        return payload


@dataclass(frozen=True)
class InvoiceMetadata:
    ksef_number: str | None = None
    invoice_number: str | None = None
    invoice_hash: str | None = None
    issue_date: str | None = None
    invoicing_date: str | None = None
    permanent_storage_date: str | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> InvoiceMetadata:
        return InvoiceMetadata(
            ksef_number=str(data["ksefNumber"]) if data.get("ksefNumber") is not None else None,
            invoice_number=(
                str(data["invoiceNumber"]) if data.get("invoiceNumber") is not None else None
            ),
            invoice_hash=(
                str(data["invoiceHash"]) if data.get("invoiceHash") is not None else None
            ),
            issue_date=str(data["issueDate"]) if data.get("issueDate") is not None else None,
            invoicing_date=(
                str(data["invoicingDate"]) if data.get("invoicingDate") is not None else None
            ),
            permanent_storage_date=(
                str(data["permanentStorageDate"])
                if data.get("permanentStorageDate") is not None
                else None
            ),
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if not omit_none or self.ksef_number is not None:
            payload["ksefNumber"] = self.ksef_number
        if not omit_none or self.invoice_number is not None:
            payload["invoiceNumber"] = self.invoice_number
        if not omit_none or self.invoice_hash is not None:
            payload["invoiceHash"] = self.invoice_hash
        if not omit_none or self.issue_date is not None:
            payload["issueDate"] = self.issue_date
        if not omit_none or self.invoicing_date is not None:
            payload["invoicingDate"] = self.invoicing_date
        if not omit_none or self.permanent_storage_date is not None:
            payload["permanentStorageDate"] = self.permanent_storage_date
        return payload


@dataclass(frozen=True)
class QueryInvoicesMetadataResponse:
    invoices: list[InvoiceMetadata]
    has_more: bool = False
    is_truncated: bool = False
    permanent_storage_hwm_date: str | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> QueryInvoicesMetadataResponse:
        raw_invoices = data.get("invoices")
        if not isinstance(raw_invoices, list):
            invoice_list = data.get("invoiceList")
            raw_invoices = invoice_list if isinstance(invoice_list, list) else []
        invoices = [
            InvoiceMetadata.from_dict(item) for item in raw_invoices if isinstance(item, dict)
        ]
        return QueryInvoicesMetadataResponse(
            invoices=invoices,
            has_more=bool(data.get("hasMore", False)),
            is_truncated=bool(data.get("isTruncated", False)),
            permanent_storage_hwm_date=(
                str(data["permanentStorageHwmDate"])
                if data.get("permanentStorageHwmDate") is not None
                else None
            ),
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "invoices": [invoice.to_dict(omit_none=omit_none) for invoice in self.invoices],
            "hasMore": self.has_more,
            "isTruncated": self.is_truncated,
        }
        if not omit_none or self.permanent_storage_hwm_date is not None:
            payload["permanentStorageHwmDate"] = self.permanent_storage_hwm_date
        return payload


@dataclass(frozen=True)
class SessionInvoiceStatusResponse:
    status: StatusInfo
    invoice_hash: str | None = None
    invoicing_date: str | None = None
    ordinal_number: int | None = None
    reference_number: str | None = None
    acquisition_date: str | None = None
    invoice_file_name: str | None = None
    invoice_number: str | None = None
    invoicing_mode: InvoicingMode | None = None
    ksef_number: str | None = None
    permanent_storage_date: str | None = None
    upo_download_url: str | None = None
    upo_download_url_expiration_date: str | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> SessionInvoiceStatusResponse:
        raw_invoicing_mode = data.get("invoicingMode")
        return SessionInvoiceStatusResponse(
            status=StatusInfo.from_dict(data.get("status", {})),
            invoice_hash=str(data["invoiceHash"]) if data.get("invoiceHash") is not None else None,
            invoicing_date=(
                str(data["invoicingDate"]) if data.get("invoicingDate") is not None else None
            ),
            ordinal_number=(
                int(data["ordinalNumber"]) if data.get("ordinalNumber") is not None else None
            ),
            reference_number=(
                str(data["referenceNumber"]) if data.get("referenceNumber") is not None else None
            ),
            acquisition_date=(
                str(data["acquisitionDate"]) if data.get("acquisitionDate") is not None else None
            ),
            invoice_file_name=(
                str(data["invoiceFileName"]) if data.get("invoiceFileName") is not None else None
            ),
            invoice_number=(
                str(data["invoiceNumber"]) if data.get("invoiceNumber") is not None else None
            ),
            invoicing_mode=(
                InvoicingMode(raw_invoicing_mode) if raw_invoicing_mode is not None else None
            ),
            ksef_number=str(data["ksefNumber"]) if data.get("ksefNumber") is not None else None,
            permanent_storage_date=(
                str(data["permanentStorageDate"])
                if data.get("permanentStorageDate") is not None
                else None
            ),
            upo_download_url=(
                str(data["upoDownloadUrl"]) if data.get("upoDownloadUrl") is not None else None
            ),
            upo_download_url_expiration_date=(
                str(data["upoDownloadUrlExpirationDate"])
                if data.get("upoDownloadUrlExpirationDate") is not None
                else None
            ),
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status.to_dict(omit_none=omit_none),
        }
        if not omit_none or self.invoice_hash is not None:
            payload["invoiceHash"] = self.invoice_hash
        if not omit_none or self.invoicing_date is not None:
            payload["invoicingDate"] = self.invoicing_date
        if not omit_none or self.ordinal_number is not None:
            payload["ordinalNumber"] = self.ordinal_number
        if not omit_none or self.reference_number is not None:
            payload["referenceNumber"] = self.reference_number
        if not omit_none or self.acquisition_date is not None:
            payload["acquisitionDate"] = self.acquisition_date
        if not omit_none or self.invoice_file_name is not None:
            payload["invoiceFileName"] = self.invoice_file_name
        if not omit_none or self.invoice_number is not None:
            payload["invoiceNumber"] = self.invoice_number
        if not omit_none or self.invoicing_mode is not None:
            payload["invoicingMode"] = (
                self.invoicing_mode.value if self.invoicing_mode is not None else None
            )
        if not omit_none or self.ksef_number is not None:
            payload["ksefNumber"] = self.ksef_number
        if not omit_none or self.permanent_storage_date is not None:
            payload["permanentStorageDate"] = self.permanent_storage_date
        if not omit_none or self.upo_download_url is not None:
            payload["upoDownloadUrl"] = self.upo_download_url
        if not omit_none or self.upo_download_url_expiration_date is not None:
            payload["upoDownloadUrlExpirationDate"] = self.upo_download_url_expiration_date
        return payload


@dataclass(frozen=True)
class SessionInvoicesResponse:
    invoices: list[SessionInvoiceStatusResponse]
    continuation_token: str | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> SessionInvoicesResponse:
        raw_invoices = data.get("invoices") if isinstance(data.get("invoices"), list) else []
        return SessionInvoicesResponse(
            invoices=[
                SessionInvoiceStatusResponse.from_dict(item)
                for item in raw_invoices
                if isinstance(item, dict)
            ],
            continuation_token=(
                str(data["continuationToken"])
                if data.get("continuationToken") is not None
                else None
            ),
        )

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "invoices": [invoice.to_dict(omit_none=omit_none) for invoice in self.invoices]
        }
        if not omit_none or self.continuation_token is not None:
            payload["continuationToken"] = self.continuation_token
        return payload


@dataclass(frozen=True)
class UnknownApiProblem:
    status: int
    title: str
    detail: str | None = None
    raw: dict[str, Any] | None = None


__all__ = [
    *[name for name in dir(_openapi_models) if not name.startswith("_")],
    "BinaryContent",
    "FileMetadata",
    "InvoiceContent",
    "LighthouseKsefStatus",
    "LighthouseMessage",
    "LighthouseMessageCategory",
    "LighthouseMessageType",
    "LighthouseStatusResponse",
    "UnknownApiProblem",
]
