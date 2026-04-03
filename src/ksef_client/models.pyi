# ruff: noqa: F401, I001
from __future__ import annotations

from dataclasses import dataclass as _dataclass
from enum import Enum as _Enum
from typing import Any as _Any

from .openapi_models import (
    AmountType,
    AuthenticationContextIdentifierType,
    AuthenticationMethod,
    AuthenticationMethodCategory,
    AuthenticationTokenStatus,
    BuyerIdentifierType,
    CertificateListItemStatus,
    CertificateRevocationReason,
    CertificateSubjectIdentifierType,
    CommonSessionStatus,
    CurrencyCode,
    EntityAuthorizationPermissionType,
    EntityAuthorizationPermissionsSubjectIdentifierType,
    EntityAuthorizationsAuthorIdentifierType,
    EntityAuthorizationsAuthorizedEntityIdentifierType,
    EntityAuthorizationsAuthorizingEntityIdentifierType,
    EntityPermissionItemScope,
    EntityPermissionType,
    EntityPermissionsContextIdentifierType,
    EntityPermissionsSubjectIdentifierType,
    EntityPermissionsSubordinateEntityIdentifierType,
    EntityRoleType,
    EntityRolesParentEntityIdentifierType,
    EntitySubjectByFingerprintDetailsType,
    EntitySubjectByIdentifierDetailsType,
    EntitySubjectDetailsType,
    EuEntityAdministrationPermissionsContextIdentifierType,
    EuEntityAdministrationPermissionsSubjectIdentifierType,
    EuEntityPermissionSubjectDetailsType,
    EuEntityPermissionType,
    EuEntityPermissionsAuthorIdentifierType,
    EuEntityPermissionsQueryPermissionType,
    EuEntityPermissionsSubjectIdentifierType,
    IndirectPermissionType,
    IndirectPermissionsSubjectIdentifierType,
    IndirectPermissionsTargetIdentifierType,
    InvoicePermissionType,
    InvoiceQueryDateType,
    InvoiceQueryFormType,
    InvoiceQuerySubjectType,
    InvoiceType,
    InvoicingMode,
    KsefCertificateType,
    PermissionState,
    PersonIdentifierType,
    PersonPermissionScope,
    PersonPermissionSubjectDetailsType,
    PersonPermissionType,
    PersonPermissionsAuthorIdentifierType,
    PersonPermissionsAuthorizedIdentifierType,
    PersonPermissionsContextIdentifierType,
    PersonPermissionsQueryType,
    PersonPermissionsSubjectIdentifierType,
    PersonPermissionsTargetIdentifierType,
    PersonSubjectByFingerprintDetailsType,
    PersonSubjectDetailsType,
    PersonalPermissionScope,
    PersonalPermissionType,
    PersonalPermissionsAuthorizedIdentifierType,
    PersonalPermissionsContextIdentifierType,
    PersonalPermissionsTargetIdentifierType,
    PublicKeyCertificateUsage,
    QueryType,
    SessionType,
    SortOrder,
    SubjectIdentifierType,
    SubjectType,
    SubordinateEntityRoleType,
    SubordinateRoleSubordinateEntityIdentifierType,
    SubunitPermissionScope,
    SubunitPermissionsAuthorIdentifierType,
    SubunitPermissionsContextIdentifierType,
    SubunitPermissionsSubjectIdentifierType,
    SubunitPermissionsSubunitIdentifierType,
    TestDataAuthenticationContextIdentifierType,
    TestDataAuthorizedIdentifierType,
    TestDataContextIdentifierType,
    TestDataPermissionType,
    ThirdSubjectIdentifierType,
    TokenAuthorIdentifierType,
    TokenContextIdentifierType,
    TokenPermissionType,
    Challenge,
    InternalId,
    KsefNumber,
    Nip,
    NipVatUe,
    PeppolId,
    PermissionId,
    Pesel,
    ReferenceNumber,
    RetryAfter,
    Sha256HashBase64,
    AllowedIps,
    ApiRateLimitValuesOverride,
    ApiRateLimitsOverride,
    AttachmentPermissionGrantRequest,
    AttachmentPermissionRevokeRequest,
    AuthenticationContextIdentifier,
    AuthenticationListItem,
    AuthenticationListResponse,
    AuthenticationMethodInfo,
    AuthorizationPolicy,
    BatchFileInfo,
    BatchFilePartInfo,
    BatchSessionContextLimitsOverride,
    BatchSessionEffectiveContextLimits,
    BlockContextAuthenticationRequest,
    CertificateEffectiveSubjectLimits,
    CertificateEnrollmentDataResponse,
    CertificateEnrollmentStatusResponse,
    CertificateLimit,
    CertificateLimitsResponse,
    CertificateListItem,
    CertificateSubjectIdentifier,
    CertificateSubjectLimitsOverride,
    CheckAttachmentPermissionStatusResponse,
    EffectiveApiRateLimitValues,
    EffectiveApiRateLimits,
    EffectiveContextLimits,
    EffectiveSubjectLimits,
    EncryptionInfo,
    EnrollCertificateRequest,
    EnrollCertificateResponse,
    EnrollmentEffectiveSubjectLimits,
    EnrollmentSubjectLimitsOverride,
    EntityAuthorizationGrant,
    EntityAuthorizationPermissionsGrantRequest,
    EntityAuthorizationPermissionsQueryRequest,
    EntityAuthorizationPermissionsSubjectIdentifier,
    EntityAuthorizationsAuthorIdentifier,
    EntityAuthorizationsAuthorizedEntityIdentifier,
    EntityAuthorizationsAuthorizingEntityIdentifier,
    EntityByFingerprintDetails,
    EntityDetails,
    EntityPermission,
    EntityPermissionItem,
    EntityPermissionsContextIdentifier,
    EntityPermissionsGrantRequest,
    EntityPermissionsQueryRequest,
    EntityPermissionsSubjectIdentifier,
    EntityPermissionsSubordinateEntityIdentifier,
    EntityRole,
    EntityRolesParentEntityIdentifier,
    EuEntityAdministrationPermissionsContextIdentifier,
    EuEntityAdministrationPermissionsGrantRequest,
    EuEntityAdministrationPermissionsSubjectIdentifier,
    EuEntityDetails,
    EuEntityPermission,
    EuEntityPermissionSubjectDetails,
    EuEntityPermissionsAuthorIdentifier,
    EuEntityPermissionsGrantRequest,
    EuEntityPermissionsQueryRequest,
    EuEntityPermissionsSubjectIdentifier,
    ExceptionDetails,
    ExceptionInfo,
    ExceptionResponse,
    ExportInvoicesResponse,
    ForbiddenProblemDetails,
    FormCode,
    GenerateTokenRequest,
    GenerateTokenResponse,
    IdDocument,
    IndirectPermissionsGrantRequest,
    IndirectPermissionsSubjectIdentifier,
    IndirectPermissionsTargetIdentifier,
    InitTokenAuthenticationRequest,
    InvoiceExportRequest,
    InvoiceExportStatusResponse,
    InvoiceMetadataAuthorizedSubject,
    InvoiceMetadataBuyer,
    InvoiceMetadataBuyerIdentifier,
    InvoiceMetadataSeller,
    InvoiceMetadataThirdSubject,
    InvoiceMetadataThirdSubjectIdentifier,
    InvoicePackage,
    InvoicePackagePart,
    InvoiceQueryAmount,
    InvoiceQueryBuyerIdentifier,
    InvoiceQueryDateRange,
    InvoiceQueryFilters,
    InvoiceStatusInfo,
    OnlineSessionContextLimitsOverride,
    OnlineSessionEffectiveContextLimits,
    OpenBatchSessionRequest,
    OpenBatchSessionResponse,
    OpenOnlineSessionRequest,
    PartUploadRequest,
    PeppolProvider,
    PermissionsEuEntityDetails,
    PermissionsOperationResponse,
    PermissionsOperationStatusResponse,
    PermissionsSubjectEntityByFingerprintDetails,
    PermissionsSubjectEntityByIdentifierDetails,
    PermissionsSubjectEntityDetails,
    PermissionsSubjectPersonByFingerprintDetails,
    PermissionsSubjectPersonDetails,
    PersonByFingerprintWithIdentifierDetails,
    PersonByFingerprintWithoutIdentifierDetails,
    PersonCreateRequest,
    PersonDetails,
    PersonIdentifier,
    PersonPermission,
    PersonPermissionSubjectDetails,
    PersonPermissionsAuthorIdentifier,
    PersonPermissionsAuthorizedIdentifier,
    PersonPermissionsContextIdentifier,
    PersonPermissionsGrantRequest,
    PersonPermissionsQueryRequest,
    PersonPermissionsSubjectIdentifier,
    PersonPermissionsTargetIdentifier,
    PersonRemoveRequest,
    PersonalPermission,
    PersonalPermissionsAuthorizedIdentifier,
    PersonalPermissionsContextIdentifier,
    PersonalPermissionsQueryRequest,
    PersonalPermissionsTargetIdentifier,
    QueryCertificatesRequest,
    QueryCertificatesResponse,
    QueryEntityAuthorizationPermissionsResponse,
    QueryEntityPermissionsResponse,
    QueryEntityRolesResponse,
    QueryEuEntityPermissionsResponse,
    QueryPeppolProvidersResponse,
    QueryPersonPermissionsResponse,
    QueryPersonalPermissionsResponse,
    QuerySubordinateEntityRolesResponse,
    QuerySubunitPermissionsResponse,
    QueryTokensResponse,
    QueryTokensResponseItem,
    RetrieveCertificatesListItem,
    RetrieveCertificatesRequest,
    RetrieveCertificatesResponse,
    RevokeCertificateRequest,
    SendInvoiceRequest,
    SendInvoiceResponse,
    SessionStatusResponse,
    SessionsQueryResponse,
    SessionsQueryResponseItem,
    SetRateLimitsRequest,
    SetSessionLimitsRequest,
    SetSubjectLimitsRequest,
    SubjectCreateRequest,
    SubjectRemoveRequest,
    SubordinateEntityRole,
    SubordinateEntityRolesQueryRequest,
    SubordinateRoleSubordinateEntityIdentifier,
    Subunit,
    SubunitPermission,
    SubunitPermissionsAuthorIdentifier,
    SubunitPermissionsAuthorizedIdentifier,
    SubunitPermissionsContextIdentifier,
    SubunitPermissionsGrantRequest,
    SubunitPermissionsQueryRequest,
    SubunitPermissionsSubjectIdentifier,
    SubunitPermissionsSubunitIdentifier,
    TestDataAuthenticationContextIdentifier,
    TestDataAuthorizedIdentifier,
    TestDataContextIdentifier,
    TestDataPermission,
    TestDataPermissionsGrantRequest,
    TestDataPermissionsRevokeRequest,
    TokenAuthorIdentifierTypeIdentifier,
    TokenContextIdentifierTypeIdentifier,
    TokenStatusResponse,
    TooManyRequestsResponse,
    UnauthorizedProblemDetails,
    UnblockContextAuthenticationRequest,
    UpoPageResponse,
    UpoResponse,
)

@_dataclass(frozen=True)
class BinaryContent:
    content: bytes
    sha256_base64: str | None = None


@_dataclass(frozen=True)
class FileMetadata:
    file_size: int
    sha256_base64: str


@_dataclass(frozen=True)
class InvoiceContent:
    content: str
    sha256_base64: str | None = None


@_dataclass(frozen=True)
class StatusInfo:
    code: int
    description: str
    details: list[str] | None = None
    extensions: dict[str, _Any] | None = None
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> StatusInfo:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class TokenInfo:
    token: str
    valid_until: str | None
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> TokenInfo:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class AuthenticationChallengeResponse:
    challenge: str
    timestamp: str
    timestamp_ms: int
    client_ip: str | None = None
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> AuthenticationChallengeResponse:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class AuthenticationInitResponse:
    reference_number: str
    authentication_token: TokenInfo
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> AuthenticationInitResponse:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class AuthenticationOperationStatusResponse:
    status: StatusInfo
    authentication_method: AuthenticationMethod | None = None
    authentication_method_info: AuthenticationMethodInfo | None = None
    start_date: str | None = None
    is_token_redeemed: bool | None = None
    last_token_refresh_date: str | None = None
    refresh_token_valid_until: str | None = None
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> AuthenticationOperationStatusResponse:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class AuthenticationTokensResponse:
    access_token: TokenInfo
    refresh_token: TokenInfo
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> AuthenticationTokensResponse:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class AuthenticationTokenRefreshResponse:
    access_token: TokenInfo
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> AuthenticationTokenRefreshResponse:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


class LighthouseKsefStatus(str, _Enum):
    AVAILABLE = ...
    MAINTENANCE = ...
    FAILURE = ...
    TOTAL_FAILURE = ...


@_dataclass(frozen=True)
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
    def from_dict(data: dict[str, _Any]) -> LighthouseMessage:
        ...
    def to_dict(self) -> dict[str, _Any]:
        ...


class LighthouseMessageCategory(str, _Enum):
    FAILURE = ...
    TOTAL_FAILURE = ...
    MAINTENANCE = ...


class LighthouseMessageType(str, _Enum):
    FAILURE_START = ...
    FAILURE_END = ...
    MAINTENANCE_ANNOUNCEMENT = ...


@_dataclass(frozen=True)
class LighthouseStatusResponse:
    status: LighthouseKsefStatus
    messages: list[LighthouseMessage] | None = None
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> LighthouseStatusResponse:
        ...
    def to_dict(self) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class PublicKeyCertificate:
    certificate: str
    usage: list[PublicKeyCertificateUsage] = ...
    valid_from: str | None = None
    valid_to: str | None = None
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> PublicKeyCertificate:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class OpenOnlineSessionResponse:
    reference_number: str
    valid_until: str | None = None
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> OpenOnlineSessionResponse:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class InvoiceMetadata:
    acquisition_date: str | None = None
    buyer: InvoiceMetadataBuyer | None = None
    currency: str | None = None
    form_code: FormCode | None = None
    gross_amount: float | None = None
    has_attachment: bool | None = None
    invoice_hash: str | None = None
    invoice_number: str | None = None
    invoice_type: InvoiceType | None = None
    invoicing_date: str | None = None
    invoicing_mode: InvoicingMode | None = None
    is_self_invoicing: bool | None = None
    issue_date: str | None = None
    ksef_number: str | None = None
    net_amount: float | None = None
    permanent_storage_date: str | None = None
    seller: InvoiceMetadataSeller | None = None
    vat_amount: float | None = None
    authorized_subject: InvoiceMetadataAuthorizedSubject | None = None
    hash_of_corrected_invoice: str | None = None
    third_subjects: list[InvoiceMetadataThirdSubject] | None = None
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> InvoiceMetadata:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class QueryInvoicesMetadataResponse:
    invoices: list[InvoiceMetadata] = ...
    has_more: bool = False
    is_truncated: bool = False
    continuation_token: str | None = None
    last_permanent_storage_date: str | None = None
    permanent_storage_hwm_date: str | None = None
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> QueryInvoicesMetadataResponse:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
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
    def from_dict(data: dict[str, _Any]) -> SessionInvoiceStatusResponse:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class SessionInvoicesResponse:
    invoices: list[SessionInvoiceStatusResponse]
    continuation_token: str | None = None
    @staticmethod
    def from_dict(data: dict[str, _Any]) -> SessionInvoicesResponse:
        ...
    def to_dict(self, omit_none: bool=True) -> dict[str, _Any]:
        ...


@_dataclass(frozen=True)
class UnknownApiProblem:
    status: int
    title: str
    detail: str | None = None
    raw: dict[str, _Any] | None = None


__all__ = [
    "AmountType",
    "AuthenticationContextIdentifierType",
    "AuthenticationMethod",
    "AuthenticationMethodCategory",
    "AuthenticationTokenStatus",
    "BuyerIdentifierType",
    "CertificateListItemStatus",
    "CertificateRevocationReason",
    "CertificateSubjectIdentifierType",
    "CommonSessionStatus",
    "CurrencyCode",
    "EntityAuthorizationPermissionType",
    "EntityAuthorizationPermissionsSubjectIdentifierType",
    "EntityAuthorizationsAuthorIdentifierType",
    "EntityAuthorizationsAuthorizedEntityIdentifierType",
    "EntityAuthorizationsAuthorizingEntityIdentifierType",
    "EntityPermissionItemScope",
    "EntityPermissionType",
    "EntityPermissionsContextIdentifierType",
    "EntityPermissionsSubjectIdentifierType",
    "EntityPermissionsSubordinateEntityIdentifierType",
    "EntityRoleType",
    "EntityRolesParentEntityIdentifierType",
    "EntitySubjectByFingerprintDetailsType",
    "EntitySubjectByIdentifierDetailsType",
    "EntitySubjectDetailsType",
    "EuEntityAdministrationPermissionsContextIdentifierType",
    "EuEntityAdministrationPermissionsSubjectIdentifierType",
    "EuEntityPermissionSubjectDetailsType",
    "EuEntityPermissionType",
    "EuEntityPermissionsAuthorIdentifierType",
    "EuEntityPermissionsQueryPermissionType",
    "EuEntityPermissionsSubjectIdentifierType",
    "IndirectPermissionType",
    "IndirectPermissionsSubjectIdentifierType",
    "IndirectPermissionsTargetIdentifierType",
    "InvoicePermissionType",
    "InvoiceQueryDateType",
    "InvoiceQueryFormType",
    "InvoiceQuerySubjectType",
    "InvoiceType",
    "InvoicingMode",
    "KsefCertificateType",
    "PermissionState",
    "PersonIdentifierType",
    "PersonPermissionScope",
    "PersonPermissionSubjectDetailsType",
    "PersonPermissionType",
    "PersonPermissionsAuthorIdentifierType",
    "PersonPermissionsAuthorizedIdentifierType",
    "PersonPermissionsContextIdentifierType",
    "PersonPermissionsQueryType",
    "PersonPermissionsSubjectIdentifierType",
    "PersonPermissionsTargetIdentifierType",
    "PersonSubjectByFingerprintDetailsType",
    "PersonSubjectDetailsType",
    "PersonalPermissionScope",
    "PersonalPermissionType",
    "PersonalPermissionsAuthorizedIdentifierType",
    "PersonalPermissionsContextIdentifierType",
    "PersonalPermissionsTargetIdentifierType",
    "PublicKeyCertificateUsage",
    "QueryType",
    "SessionType",
    "SortOrder",
    "SubjectIdentifierType",
    "SubjectType",
    "SubordinateEntityRoleType",
    "SubordinateRoleSubordinateEntityIdentifierType",
    "SubunitPermissionScope",
    "SubunitPermissionsAuthorIdentifierType",
    "SubunitPermissionsContextIdentifierType",
    "SubunitPermissionsSubjectIdentifierType",
    "SubunitPermissionsSubunitIdentifierType",
    "TestDataAuthenticationContextIdentifierType",
    "TestDataAuthorizedIdentifierType",
    "TestDataContextIdentifierType",
    "TestDataPermissionType",
    "ThirdSubjectIdentifierType",
    "TokenAuthorIdentifierType",
    "TokenContextIdentifierType",
    "TokenPermissionType",
    "Challenge",
    "InternalId",
    "KsefNumber",
    "Nip",
    "NipVatUe",
    "PeppolId",
    "PermissionId",
    "Pesel",
    "ReferenceNumber",
    "RetryAfter",
    "Sha256HashBase64",
    "AllowedIps",
    "ApiRateLimitValuesOverride",
    "ApiRateLimitsOverride",
    "AttachmentPermissionGrantRequest",
    "AttachmentPermissionRevokeRequest",
    "AuthenticationContextIdentifier",
    "AuthenticationListItem",
    "AuthenticationListResponse",
    "AuthenticationMethodInfo",
    "AuthorizationPolicy",
    "BatchFileInfo",
    "BatchFilePartInfo",
    "BatchSessionContextLimitsOverride",
    "BatchSessionEffectiveContextLimits",
    "BlockContextAuthenticationRequest",
    "CertificateEffectiveSubjectLimits",
    "CertificateEnrollmentDataResponse",
    "CertificateEnrollmentStatusResponse",
    "CertificateLimit",
    "CertificateLimitsResponse",
    "CertificateListItem",
    "CertificateSubjectIdentifier",
    "CertificateSubjectLimitsOverride",
    "CheckAttachmentPermissionStatusResponse",
    "EffectiveApiRateLimitValues",
    "EffectiveApiRateLimits",
    "EffectiveContextLimits",
    "EffectiveSubjectLimits",
    "EncryptionInfo",
    "EnrollCertificateRequest",
    "EnrollCertificateResponse",
    "EnrollmentEffectiveSubjectLimits",
    "EnrollmentSubjectLimitsOverride",
    "EntityAuthorizationGrant",
    "EntityAuthorizationPermissionsGrantRequest",
    "EntityAuthorizationPermissionsQueryRequest",
    "EntityAuthorizationPermissionsSubjectIdentifier",
    "EntityAuthorizationsAuthorIdentifier",
    "EntityAuthorizationsAuthorizedEntityIdentifier",
    "EntityAuthorizationsAuthorizingEntityIdentifier",
    "EntityByFingerprintDetails",
    "EntityDetails",
    "EntityPermission",
    "EntityPermissionItem",
    "EntityPermissionsContextIdentifier",
    "EntityPermissionsGrantRequest",
    "EntityPermissionsQueryRequest",
    "EntityPermissionsSubjectIdentifier",
    "EntityPermissionsSubordinateEntityIdentifier",
    "EntityRole",
    "EntityRolesParentEntityIdentifier",
    "EuEntityAdministrationPermissionsContextIdentifier",
    "EuEntityAdministrationPermissionsGrantRequest",
    "EuEntityAdministrationPermissionsSubjectIdentifier",
    "EuEntityDetails",
    "EuEntityPermission",
    "EuEntityPermissionSubjectDetails",
    "EuEntityPermissionsAuthorIdentifier",
    "EuEntityPermissionsGrantRequest",
    "EuEntityPermissionsQueryRequest",
    "EuEntityPermissionsSubjectIdentifier",
    "ExceptionDetails",
    "ExceptionInfo",
    "ExceptionResponse",
    "ExportInvoicesResponse",
    "ForbiddenProblemDetails",
    "FormCode",
    "GenerateTokenRequest",
    "GenerateTokenResponse",
    "IdDocument",
    "IndirectPermissionsGrantRequest",
    "IndirectPermissionsSubjectIdentifier",
    "IndirectPermissionsTargetIdentifier",
    "InitTokenAuthenticationRequest",
    "InvoiceExportRequest",
    "InvoiceExportStatusResponse",
    "InvoiceMetadataAuthorizedSubject",
    "InvoiceMetadataBuyer",
    "InvoiceMetadataBuyerIdentifier",
    "InvoiceMetadataSeller",
    "InvoiceMetadataThirdSubject",
    "InvoiceMetadataThirdSubjectIdentifier",
    "InvoicePackage",
    "InvoicePackagePart",
    "InvoiceQueryAmount",
    "InvoiceQueryBuyerIdentifier",
    "InvoiceQueryDateRange",
    "InvoiceQueryFilters",
    "InvoiceStatusInfo",
    "OnlineSessionContextLimitsOverride",
    "OnlineSessionEffectiveContextLimits",
    "OpenBatchSessionRequest",
    "OpenBatchSessionResponse",
    "OpenOnlineSessionRequest",
    "PartUploadRequest",
    "PeppolProvider",
    "PermissionsEuEntityDetails",
    "PermissionsOperationResponse",
    "PermissionsOperationStatusResponse",
    "PermissionsSubjectEntityByFingerprintDetails",
    "PermissionsSubjectEntityByIdentifierDetails",
    "PermissionsSubjectEntityDetails",
    "PermissionsSubjectPersonByFingerprintDetails",
    "PermissionsSubjectPersonDetails",
    "PersonByFingerprintWithIdentifierDetails",
    "PersonByFingerprintWithoutIdentifierDetails",
    "PersonCreateRequest",
    "PersonDetails",
    "PersonIdentifier",
    "PersonPermission",
    "PersonPermissionSubjectDetails",
    "PersonPermissionsAuthorIdentifier",
    "PersonPermissionsAuthorizedIdentifier",
    "PersonPermissionsContextIdentifier",
    "PersonPermissionsGrantRequest",
    "PersonPermissionsQueryRequest",
    "PersonPermissionsSubjectIdentifier",
    "PersonPermissionsTargetIdentifier",
    "PersonRemoveRequest",
    "PersonalPermission",
    "PersonalPermissionsAuthorizedIdentifier",
    "PersonalPermissionsContextIdentifier",
    "PersonalPermissionsQueryRequest",
    "PersonalPermissionsTargetIdentifier",
    "QueryCertificatesRequest",
    "QueryCertificatesResponse",
    "QueryEntityAuthorizationPermissionsResponse",
    "QueryEntityPermissionsResponse",
    "QueryEntityRolesResponse",
    "QueryEuEntityPermissionsResponse",
    "QueryPeppolProvidersResponse",
    "QueryPersonPermissionsResponse",
    "QueryPersonalPermissionsResponse",
    "QuerySubordinateEntityRolesResponse",
    "QuerySubunitPermissionsResponse",
    "QueryTokensResponse",
    "QueryTokensResponseItem",
    "RetrieveCertificatesListItem",
    "RetrieveCertificatesRequest",
    "RetrieveCertificatesResponse",
    "RevokeCertificateRequest",
    "SendInvoiceRequest",
    "SendInvoiceResponse",
    "SessionStatusResponse",
    "SessionsQueryResponse",
    "SessionsQueryResponseItem",
    "SetRateLimitsRequest",
    "SetSessionLimitsRequest",
    "SetSubjectLimitsRequest",
    "SubjectCreateRequest",
    "SubjectRemoveRequest",
    "SubordinateEntityRole",
    "SubordinateEntityRolesQueryRequest",
    "SubordinateRoleSubordinateEntityIdentifier",
    "Subunit",
    "SubunitPermission",
    "SubunitPermissionsAuthorIdentifier",
    "SubunitPermissionsAuthorizedIdentifier",
    "SubunitPermissionsContextIdentifier",
    "SubunitPermissionsGrantRequest",
    "SubunitPermissionsQueryRequest",
    "SubunitPermissionsSubjectIdentifier",
    "SubunitPermissionsSubunitIdentifier",
    "TestDataAuthenticationContextIdentifier",
    "TestDataAuthorizedIdentifier",
    "TestDataContextIdentifier",
    "TestDataPermission",
    "TestDataPermissionsGrantRequest",
    "TestDataPermissionsRevokeRequest",
    "TokenAuthorIdentifierTypeIdentifier",
    "TokenContextIdentifierTypeIdentifier",
    "TokenStatusResponse",
    "TooManyRequestsResponse",
    "UnauthorizedProblemDetails",
    "UnblockContextAuthenticationRequest",
    "UpoPageResponse",
    "UpoResponse",
    "BinaryContent",
    "FileMetadata",
    "InvoiceContent",
    "StatusInfo",
    "TokenInfo",
    "AuthenticationChallengeResponse",
    "AuthenticationInitResponse",
    "AuthenticationOperationStatusResponse",
    "AuthenticationTokensResponse",
    "AuthenticationTokenRefreshResponse",
    "LighthouseKsefStatus",
    "LighthouseMessage",
    "LighthouseMessageCategory",
    "LighthouseMessageType",
    "LighthouseStatusResponse",
    "PublicKeyCertificate",
    "OpenOnlineSessionResponse",
    "InvoiceMetadata",
    "QueryInvoicesMetadataResponse",
    "SessionInvoiceStatusResponse",
    "SessionInvoicesResponse",
    "UnknownApiProblem",
]
