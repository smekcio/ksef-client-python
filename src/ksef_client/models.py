from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FileMetadata:
    file_size: int
    sha256_base64: str


@dataclass(frozen=True)
class EncryptionInfo:
    encrypted_symmetric_key: str
    initialization_vector: str


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

    @staticmethod
    def from_dict(data: dict[str, Any]) -> StatusInfo:
        return StatusInfo(
            code=int(data.get("code", 0)),
            description=str(data.get("description", "")),
            details=data.get("details"),
        )


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


@dataclass(frozen=True)
class AuthenticationChallengeResponse:
    challenge: str
    timestamp: str
    timestamp_ms: int

    @staticmethod
    def from_dict(data: dict[str, Any]) -> AuthenticationChallengeResponse:
        return AuthenticationChallengeResponse(
            challenge=str(data.get("challenge", "")),
            timestamp=str(data.get("timestamp", "")),
            timestamp_ms=int(data.get("timestampMs", 0)),
        )


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


@dataclass(frozen=True)
class AuthenticationTokenRefreshResponse:
    access_token: TokenInfo

    @staticmethod
    def from_dict(data: dict[str, Any]) -> AuthenticationTokenRefreshResponse:
        return AuthenticationTokenRefreshResponse(
            access_token=TokenInfo.from_dict(data.get("accessToken", {})),
        )


@dataclass(frozen=True)
class InvoicePackagePart:
    ordinal_number: int
    part_name: str
    method: str
    url: str
    part_size: int
    part_hash: str
    encrypted_part_size: int
    encrypted_part_hash: str
    expiration_date: str

    @staticmethod
    def from_dict(data: dict[str, Any]) -> InvoicePackagePart:
        return InvoicePackagePart(
            ordinal_number=int(data.get("ordinalNumber", 0)),
            part_name=str(data.get("partName", "")),
            method=str(data.get("method", "")),
            url=str(data.get("url", "")),
            part_size=int(data.get("partSize", 0)),
            part_hash=str(data.get("partHash", "")),
            encrypted_part_size=int(data.get("encryptedPartSize", 0)),
            encrypted_part_hash=str(data.get("encryptedPartHash", "")),
            expiration_date=str(data.get("expirationDate", "")),
        )


@dataclass(frozen=True)
class InvoicePackage:
    invoice_count: int
    size: int
    parts: list[InvoicePackagePart]
    is_truncated: bool
    last_issue_date: str | None = None
    last_invoicing_date: str | None = None
    last_permanent_storage_date: str | None = None
    permanent_storage_hwm_date: str | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> InvoicePackage:
        return InvoicePackage(
            invoice_count=int(data.get("invoiceCount", 0)),
            size=int(data.get("size", 0)),
            parts=[InvoicePackagePart.from_dict(p) for p in data.get("parts", [])],
            is_truncated=bool(data.get("isTruncated", False)),
            last_issue_date=data.get("lastIssueDate"),
            last_invoicing_date=data.get("lastInvoicingDate"),
            last_permanent_storage_date=data.get("lastPermanentStorageDate"),
            permanent_storage_hwm_date=data.get("permanentStorageHwmDate"),
        )


@dataclass(frozen=True)
class InvoiceExportStatusResponse:
    status: StatusInfo
    completed_date: str | None = None
    package_expiration_date: str | None = None
    package: InvoicePackage | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> InvoiceExportStatusResponse:
        return InvoiceExportStatusResponse(
            status=StatusInfo.from_dict(data.get("status", {})),
            completed_date=data.get("completedDate"),
            package_expiration_date=data.get("packageExpirationDate"),
            package=InvoicePackage.from_dict(data["package"]) if data.get("package") else None,
        )


@dataclass(frozen=True)
class PartUploadRequest:
    ordinal_number: int
    method: str
    url: str
    headers: dict[str, str | None]

    @staticmethod
    def from_dict(data: dict[str, Any]) -> PartUploadRequest:
        return PartUploadRequest(
            ordinal_number=int(data.get("ordinalNumber", 0)),
            method=str(data.get("method", "")),
            url=str(data.get("url", "")),
            headers=data.get("headers", {}) or {},
        )
