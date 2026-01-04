# Generated from ksef-docs/open-api.json. Do not edit manually.
from __future__ import annotations

import sys
from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Any, TypeAlias, TypeVar, cast, get_args, get_origin, get_type_hints

JsonValue: TypeAlias = Any

T = TypeVar("T", bound="OpenApiModel")
_TYPE_CACHE: dict[type, dict[str, Any]] = {}


def _get_type_map(cls: type) -> dict[str, Any]:
    cached = _TYPE_CACHE.get(cls)
    if cached is not None:
        return cached
    module = sys.modules[cls.__module__]
    hints = get_type_hints(cls, globalns=vars(module), localns=vars(module))
    _TYPE_CACHE[cls] = hints
    return hints


def _convert_value(type_hint: Any, value: Any) -> Any:
    if value is None:
        return None
    origin = get_origin(type_hint)
    if origin is list:
        item_type = get_args(type_hint)[0] if get_args(type_hint) else Any
        return [_convert_value(item_type, item) for item in value]
    if origin is dict:
        key_type, value_type = (get_args(type_hint) + (Any, Any))[:2]
        return {
            _convert_value(key_type, key): _convert_value(value_type, item)
            for key, item in value.items()
        }
    if origin is not None:
        args = [arg for arg in get_args(type_hint) if arg is not type(None)]
        if args:
            return _convert_value(args[0], value)
    if isinstance(type_hint, type) and issubclass(type_hint, Enum):
        return type_hint(value)
    if (
        isinstance(type_hint, type)
        and issubclass(type_hint, OpenApiModel)
        and isinstance(value, dict)
    ):
        return type_hint.from_dict(value)
    return value


def _serialize_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, OpenApiModel):
        return value.to_dict()
    if isinstance(value, list):
        return [_serialize_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _serialize_value(item) for key, item in value.items()}
    return value


class OpenApiModel:
    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        if data is None:
            raise ValueError("data is None")
        type_map = _get_type_map(cls)
        kwargs: dict[str, Any] = {}
        for model_field in fields(cast(Any, cls)):
            json_key = model_field.metadata.get("json_key", model_field.name)
            if json_key in data:
                type_hint = type_map.get(model_field.name, Any)
                kwargs[model_field.name] = _convert_value(type_hint, data[json_key])
        return cls(**kwargs)

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for model_field in fields(cast(Any, self)):
            json_key = model_field.metadata.get("json_key", model_field.name)
            value = getattr(self, model_field.name)
            if omit_none and value is None:
                continue
            result[json_key] = _serialize_value(value)
        return result


class AmountType(Enum):
    BRUTTO = "Brutto"
    NETTO = "Netto"
    VAT = "Vat"


class AuthenticationContextIdentifierType(Enum):
    NIP = "Nip"
    INTERNALID = "InternalId"
    NIPVATUE = "NipVatUe"
    PEPPOLID = "PeppolId"


class AuthenticationMethod(Enum):
    TOKEN = "Token"
    TRUSTEDPROFILE = "TrustedProfile"
    INTERNALCERTIFICATE = "InternalCertificate"
    QUALIFIEDSIGNATURE = "QualifiedSignature"
    QUALIFIEDSEAL = "QualifiedSeal"
    PERSONALSIGNATURE = "PersonalSignature"
    PEPPOLSIGNATURE = "PeppolSignature"


class AuthenticationTokenStatus(Enum):
    PENDING = "Pending"
    ACTIVE = "Active"
    REVOKING = "Revoking"
    REVOKED = "Revoked"
    FAILED = "Failed"


class BuyerIdentifierType(Enum):
    NIP = "Nip"
    VATUE = "VatUe"
    OTHER = "Other"
    NONE = "None"


class CertificateListItemStatus(Enum):
    ACTIVE = "Active"
    BLOCKED = "Blocked"
    REVOKED = "Revoked"
    EXPIRED = "Expired"


class CertificateRevocationReason(Enum):
    UNSPECIFIED = "Unspecified"
    SUPERSEDED = "Superseded"
    KEYCOMPROMISE = "KeyCompromise"


class CertificateSubjectIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class CommonSessionStatus(Enum):
    INPROGRESS = "InProgress"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELLED = "Cancelled"


class CurrencyCode(Enum):
    AED = "AED"
    AFN = "AFN"
    ALL = "ALL"
    AMD = "AMD"
    ANG = "ANG"
    AOA = "AOA"
    ARS = "ARS"
    AUD = "AUD"
    AWG = "AWG"
    AZN = "AZN"
    BAM = "BAM"
    BBD = "BBD"
    BDT = "BDT"
    BGN = "BGN"
    BHD = "BHD"
    BIF = "BIF"
    BMD = "BMD"
    BND = "BND"
    BOB = "BOB"
    BOV = "BOV"
    BRL = "BRL"
    BSD = "BSD"
    BTN = "BTN"
    BWP = "BWP"
    BYN = "BYN"
    BZD = "BZD"
    CAD = "CAD"
    CDF = "CDF"
    CHE = "CHE"
    CHF = "CHF"
    CHW = "CHW"
    CLF = "CLF"
    CLP = "CLP"
    CNY = "CNY"
    COP = "COP"
    COU = "COU"
    CRC = "CRC"
    CUC = "CUC"
    CUP = "CUP"
    CVE = "CVE"
    CZK = "CZK"
    DJF = "DJF"
    DKK = "DKK"
    DOP = "DOP"
    DZD = "DZD"
    EGP = "EGP"
    ERN = "ERN"
    ETB = "ETB"
    EUR = "EUR"
    FJD = "FJD"
    FKP = "FKP"
    GBP = "GBP"
    GEL = "GEL"
    GGP = "GGP"
    GHS = "GHS"
    GIP = "GIP"
    GMD = "GMD"
    GNF = "GNF"
    GTQ = "GTQ"
    GYD = "GYD"
    HKD = "HKD"
    HNL = "HNL"
    HRK = "HRK"
    HTG = "HTG"
    HUF = "HUF"
    IDR = "IDR"
    ILS = "ILS"
    IMP = "IMP"
    INR = "INR"
    IQD = "IQD"
    IRR = "IRR"
    ISK = "ISK"
    JEP = "JEP"
    JMD = "JMD"
    JOD = "JOD"
    JPY = "JPY"
    KES = "KES"
    KGS = "KGS"
    KHR = "KHR"
    KMF = "KMF"
    KPW = "KPW"
    KRW = "KRW"
    KWD = "KWD"
    KYD = "KYD"
    KZT = "KZT"
    LAK = "LAK"
    LBP = "LBP"
    LKR = "LKR"
    LRD = "LRD"
    LSL = "LSL"
    LYD = "LYD"
    MAD = "MAD"
    MDL = "MDL"
    MGA = "MGA"
    MKD = "MKD"
    MMK = "MMK"
    MNT = "MNT"
    MOP = "MOP"
    MRU = "MRU"
    MUR = "MUR"
    MVR = "MVR"
    MWK = "MWK"
    MXN = "MXN"
    MXV = "MXV"
    MYR = "MYR"
    MZN = "MZN"
    NAD = "NAD"
    NGN = "NGN"
    NIO = "NIO"
    NOK = "NOK"
    NPR = "NPR"
    NZD = "NZD"
    OMR = "OMR"
    PAB = "PAB"
    PEN = "PEN"
    PGK = "PGK"
    PHP = "PHP"
    PKR = "PKR"
    PLN = "PLN"
    PYG = "PYG"
    QAR = "QAR"
    RON = "RON"
    RSD = "RSD"
    RUB = "RUB"
    RWF = "RWF"
    SAR = "SAR"
    SBD = "SBD"
    SCR = "SCR"
    SDG = "SDG"
    SEK = "SEK"
    SGD = "SGD"
    SHP = "SHP"
    SLL = "SLL"
    SOS = "SOS"
    SRD = "SRD"
    SSP = "SSP"
    STN = "STN"
    SVC = "SVC"
    SYP = "SYP"
    SZL = "SZL"
    THB = "THB"
    TJS = "TJS"
    TMT = "TMT"
    TND = "TND"
    TOP = "TOP"
    TRY = "TRY"
    TTD = "TTD"
    TWD = "TWD"
    TZS = "TZS"
    UAH = "UAH"
    UGX = "UGX"
    USD = "USD"
    USN = "USN"
    UYI = "UYI"
    UYU = "UYU"
    UYW = "UYW"
    UZS = "UZS"
    VES = "VES"
    VND = "VND"
    VUV = "VUV"
    WST = "WST"
    XAF = "XAF"
    XAG = "XAG"
    XAU = "XAU"
    XBA = "XBA"
    XBB = "XBB"
    XBC = "XBC"
    XBD = "XBD"
    XCD = "XCD"
    XCG = "XCG"
    XDR = "XDR"
    XOF = "XOF"
    XPD = "XPD"
    XPF = "XPF"
    XPT = "XPT"
    XSU = "XSU"
    XUA = "XUA"
    XXX = "XXX"
    YER = "YER"
    ZAR = "ZAR"
    ZMW = "ZMW"
    ZWL = "ZWL"


class EntityAuthorizationPermissionType(Enum):
    SELFINVOICING = "SelfInvoicing"
    RRINVOICING = "RRInvoicing"
    TAXREPRESENTATIVE = "TaxRepresentative"
    PEFINVOICING = "PefInvoicing"


class EntityAuthorizationPermissionsSubjectIdentifierType(Enum):
    NIP = "Nip"
    PEPPOLID = "PeppolId"


class EntityAuthorizationsAuthorIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class EntityAuthorizationsAuthorizedEntityIdentifierType(Enum):
    NIP = "Nip"
    PEPPOLID = "PeppolId"


class EntityAuthorizationsAuthorizingEntityIdentifierType(Enum):
    NIP = "Nip"


class EntityPermissionType(Enum):
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"


class EntityPermissionsSubjectIdentifierType(Enum):
    NIP = "Nip"


class EntityPermissionsSubordinateEntityIdentifierType(Enum):
    NIP = "Nip"


class EntityRoleType(Enum):
    COURTBAILIFF = "CourtBailiff"
    ENFORCEMENTAUTHORITY = "EnforcementAuthority"
    LOCALGOVERNMENTUNIT = "LocalGovernmentUnit"
    LOCALGOVERNMENTSUBUNIT = "LocalGovernmentSubUnit"
    VATGROUPUNIT = "VatGroupUnit"
    VATGROUPSUBUNIT = "VatGroupSubUnit"


class EntityRolesParentEntityIdentifierType(Enum):
    NIP = "Nip"


class EntitySubjectByFingerprintDetailsType(Enum):
    ENTITYBYFINGERPRINT = "EntityByFingerprint"


class EntitySubjectByIdentifierDetailsType(Enum):
    ENTITYBYIDENTIFIER = "EntityByIdentifier"


class EntitySubjectDetailsType(Enum):
    ENTITYBYIDENTIFIER = "EntityByIdentifier"
    ENTITYBYFINGERPRINT = "EntityByFingerprint"


class EuEntityAdministrationPermissionsContextIdentifierType(Enum):
    NIPVATUE = "NipVatUe"


class EuEntityAdministrationPermissionsSubjectIdentifierType(Enum):
    FINGERPRINT = "Fingerprint"


class EuEntityPermissionSubjectDetailsType(Enum):
    PERSONBYFINGERPRINTWITHIDENTIFIER = "PersonByFingerprintWithIdentifier"
    PERSONBYFINGERPRINTWITHOUTIDENTIFIER = "PersonByFingerprintWithoutIdentifier"
    ENTITYBYFINGERPRINT = "EntityByFingerprint"


class EuEntityPermissionType(Enum):
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"


class EuEntityPermissionsAuthorIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class EuEntityPermissionsQueryPermissionType(Enum):
    VATUEMANAGE = "VatUeManage"
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"
    INTROSPECTION = "Introspection"


class EuEntityPermissionsSubjectIdentifierType(Enum):
    FINGERPRINT = "Fingerprint"


class IndirectPermissionType(Enum):
    INVOICEREAD = "InvoiceRead"
    INVOICEWRITE = "InvoiceWrite"


class IndirectPermissionsSubjectIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class IndirectPermissionsTargetIdentifierType(Enum):
    NIP = "Nip"
    ALLPARTNERS = "AllPartners"
    INTERNALID = "InternalId"


class InvoicePermissionType(Enum):
    SELFINVOICING = "SelfInvoicing"
    TAXREPRESENTATIVE = "TaxRepresentative"
    RRINVOICING = "RRInvoicing"
    PEFINVOICING = "PefInvoicing"


class InvoiceQueryDateType(Enum):
    ISSUE = "Issue"
    INVOICING = "Invoicing"
    PERMANENTSTORAGE = "PermanentStorage"


class InvoiceQueryFormType(Enum):
    FA = "FA"
    PEF = "PEF"
    RR = "RR"


class InvoiceQuerySubjectType(Enum):
    SUBJECT1 = "Subject1"
    SUBJECT2 = "Subject2"
    SUBJECT3 = "Subject3"
    SUBJECTAUTHORIZED = "SubjectAuthorized"


class InvoiceType(Enum):
    VAT = "Vat"
    ZAL = "Zal"
    KOR = "Kor"
    ROZ = "Roz"
    UPR = "Upr"
    KORZAL = "KorZal"
    KORROZ = "KorRoz"
    VATPEF = "VatPef"
    VATPEFSP = "VatPefSp"
    KORPEF = "KorPef"
    VATRR = "VatRr"
    KORVATRR = "KorVatRr"


class InvoicingMode(Enum):
    ONLINE = "Online"
    OFFLINE = "Offline"


class KsefCertificateType(Enum):
    AUTHENTICATION = "Authentication"
    OFFLINE = "Offline"


class PermissionState(Enum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"


class PersonIdentifierType(Enum):
    PESEL = "Pesel"
    NIP = "Nip"


class PersonPermissionScope(Enum):
    CREDENTIALSMANAGE = "CredentialsManage"
    CREDENTIALSREAD = "CredentialsRead"
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"
    INTROSPECTION = "Introspection"
    SUBUNITMANAGE = "SubunitManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"


class PersonPermissionSubjectDetailsType(Enum):
    PERSONBYIDENTIFIER = "PersonByIdentifier"
    PERSONBYFINGERPRINTWITHIDENTIFIER = "PersonByFingerprintWithIdentifier"
    PERSONBYFINGERPRINTWITHOUTIDENTIFIER = "PersonByFingerprintWithoutIdentifier"


class PersonPermissionType(Enum):
    CREDENTIALSMANAGE = "CredentialsManage"
    CREDENTIALSREAD = "CredentialsRead"
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"
    INTROSPECTION = "Introspection"
    SUBUNITMANAGE = "SubunitManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"


class PersonPermissionsAuthorIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"
    SYSTEM = "System"


class PersonPermissionsAuthorizedIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class PersonPermissionsContextIdentifierType(Enum):
    NIP = "Nip"
    INTERNALID = "InternalId"


class PersonPermissionsQueryType(Enum):
    PERMISSIONSINCURRENTCONTEXT = "PermissionsInCurrentContext"
    PERMISSIONSGRANTEDINCURRENTCONTEXT = "PermissionsGrantedInCurrentContext"


class PersonPermissionsSubjectIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class PersonPermissionsTargetIdentifierType(Enum):
    NIP = "Nip"
    ALLPARTNERS = "AllPartners"
    INTERNALID = "InternalId"


class PersonSubjectByFingerprintDetailsType(Enum):
    PERSONBYFINGERPRINTWITHIDENTIFIER = "PersonByFingerprintWithIdentifier"
    PERSONBYFINGERPRINTWITHOUTIDENTIFIER = "PersonByFingerprintWithoutIdentifier"


class PersonSubjectDetailsType(Enum):
    PERSONBYIDENTIFIER = "PersonByIdentifier"
    PERSONBYFINGERPRINTWITHIDENTIFIER = "PersonByFingerprintWithIdentifier"
    PERSONBYFINGERPRINTWITHOUTIDENTIFIER = "PersonByFingerprintWithoutIdentifier"


class PersonalPermissionScope(Enum):
    CREDENTIALSMANAGE = "CredentialsManage"
    CREDENTIALSREAD = "CredentialsRead"
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"
    INTROSPECTION = "Introspection"
    SUBUNITMANAGE = "SubunitManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"
    VATUEMANAGE = "VatUeManage"


class PersonalPermissionType(Enum):
    CREDENTIALSMANAGE = "CredentialsManage"
    CREDENTIALSREAD = "CredentialsRead"
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"
    INTROSPECTION = "Introspection"
    SUBUNITMANAGE = "SubunitManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"
    VATUEMANAGE = "VatUeManage"


class PersonalPermissionsAuthorizedIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class PersonalPermissionsContextIdentifierType(Enum):
    NIP = "Nip"
    INTERNALID = "InternalId"


class PersonalPermissionsTargetIdentifierType(Enum):
    NIP = "Nip"
    ALLPARTNERS = "AllPartners"
    INTERNALID = "InternalId"


class PublicKeyCertificateUsage(Enum):
    KSEFTOKENENCRYPTION = "KsefTokenEncryption"
    SYMMETRICKEYENCRYPTION = "SymmetricKeyEncryption"


class QueryType(Enum):
    GRANTED = "Granted"
    RECEIVED = "Received"


class SessionType(Enum):
    ONLINE = "Online"
    BATCH = "Batch"


class SortOrder(Enum):
    ASC = "Asc"
    DESC = "Desc"


class SubjectIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class SubjectType(Enum):
    ENFORCEMENTAUTHORITY = "EnforcementAuthority"
    VATGROUP = "VatGroup"
    JST = "JST"


class SubordinateEntityRoleType(Enum):
    LOCALGOVERNMENTSUBUNIT = "LocalGovernmentSubUnit"
    VATGROUPSUBUNIT = "VatGroupSubUnit"


class SubordinateRoleSubordinateEntityIdentifierType(Enum):
    NIP = "Nip"


class SubunitPermissionScope(Enum):
    CREDENTIALSMANAGE = "CredentialsManage"


class SubunitPermissionsAuthorIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class SubunitPermissionsContextIdentifierType(Enum):
    INTERNALID = "InternalId"
    NIP = "Nip"


class SubunitPermissionsSubjectIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class SubunitPermissionsSubunitIdentifierType(Enum):
    INTERNALID = "InternalId"
    NIP = "Nip"


class TestDataAuthorizedIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class TestDataContextIdentifierType(Enum):
    NIP = "Nip"


class TestDataPermissionType(Enum):
    INVOICEREAD = "InvoiceRead"
    INVOICEWRITE = "InvoiceWrite"
    INTROSPECTION = "Introspection"
    CREDENTIALSREAD = "CredentialsRead"
    CREDENTIALSMANAGE = "CredentialsManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"
    SUBUNITMANAGE = "SubunitManage"


class ThirdSubjectIdentifierType(Enum):
    NIP = "Nip"
    INTERNALID = "InternalId"
    VATUE = "VatUe"
    OTHER = "Other"
    NONE = "None"


class TokenAuthorIdentifierType(Enum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"


class TokenContextIdentifierType(Enum):
    NIP = "Nip"
    INTERNALID = "InternalId"
    NIPVATUE = "NipVatUe"
    PEPPOLID = "PeppolId"


class TokenPermissionType(Enum):
    INVOICEREAD = "InvoiceRead"
    INVOICEWRITE = "InvoiceWrite"
    CREDENTIALSREAD = "CredentialsRead"
    CREDENTIALSMANAGE = "CredentialsManage"
    SUBUNITMANAGE = "SubunitManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"


Challenge: TypeAlias = str

InternalId: TypeAlias = str

KsefNumber: TypeAlias = str

Nip: TypeAlias = str

NipVatUe: TypeAlias = str

PeppolId: TypeAlias = str

PermissionId: TypeAlias = str

Pesel: TypeAlias = str

ReferenceNumber: TypeAlias = str

RetryAfter: TypeAlias = int

Sha256HashBase64: TypeAlias = str


@dataclass(frozen=True)
class AllowedIps(OpenApiModel):
    ip4Addresses: list[str] | None = None
    ip4Masks: list[str] | None = None
    ip4Ranges: list[str] | None = None


@dataclass(frozen=True)
class ApiRateLimitValuesOverride(OpenApiModel):
    perHour: int
    perMinute: int
    perSecond: int


@dataclass(frozen=True)
class ApiRateLimitsOverride(OpenApiModel):
    batchSession: ApiRateLimitValuesOverride
    invoiceDownload: ApiRateLimitValuesOverride
    invoiceExport: ApiRateLimitValuesOverride
    invoiceExportStatus: ApiRateLimitValuesOverride
    invoiceMetadata: ApiRateLimitValuesOverride
    invoiceSend: ApiRateLimitValuesOverride
    invoiceStatus: ApiRateLimitValuesOverride
    onlineSession: ApiRateLimitValuesOverride
    other: ApiRateLimitValuesOverride
    sessionInvoiceList: ApiRateLimitValuesOverride
    sessionList: ApiRateLimitValuesOverride
    sessionMisc: ApiRateLimitValuesOverride


@dataclass(frozen=True)
class AttachmentPermissionGrantRequest(OpenApiModel):
    nip: Nip


@dataclass(frozen=True)
class AttachmentPermissionRevokeRequest(OpenApiModel):
    nip: Nip
    expectedEndDate: str | None = None


@dataclass(frozen=True)
class AuthenticationChallengeResponse(OpenApiModel):
    challenge: Challenge
    timestamp: str
    timestampMs: int


@dataclass(frozen=True)
class AuthenticationContextIdentifier(OpenApiModel):
    type: AuthenticationContextIdentifierType
    value: str


@dataclass(frozen=True)
class AuthenticationInitResponse(OpenApiModel):
    authenticationToken: TokenInfo
    referenceNumber: ReferenceNumber


@dataclass(frozen=True)
class AuthenticationListItem(OpenApiModel):
    authenticationMethod: AuthenticationMethod
    referenceNumber: ReferenceNumber
    startDate: str
    status: StatusInfo
    isCurrent: bool | None = None
    isTokenRedeemed: bool | None = None
    lastTokenRefreshDate: str | None = None
    refreshTokenValidUntil: str | None = None


@dataclass(frozen=True)
class AuthenticationListResponse(OpenApiModel):
    items: list[AuthenticationListItem]
    continuationToken: str | None = None


@dataclass(frozen=True)
class AuthenticationOperationStatusResponse(OpenApiModel):
    authenticationMethod: AuthenticationMethod
    startDate: str
    status: StatusInfo
    isTokenRedeemed: bool | None = None
    lastTokenRefreshDate: str | None = None
    refreshTokenValidUntil: str | None = None


@dataclass(frozen=True)
class AuthenticationTokenRefreshResponse(OpenApiModel):
    accessToken: TokenInfo


@dataclass(frozen=True)
class AuthenticationTokensResponse(OpenApiModel):
    accessToken: TokenInfo
    refreshToken: TokenInfo


@dataclass(frozen=True)
class AuthorizationPolicy(OpenApiModel):
    allowedIps: AllowedIps | None = None


@dataclass(frozen=True)
class BatchFileInfo(OpenApiModel):
    fileHash: Sha256HashBase64
    fileParts: list[BatchFilePartInfo]
    fileSize: int


@dataclass(frozen=True)
class BatchFilePartInfo(OpenApiModel):
    fileHash: Sha256HashBase64
    fileSize: int
    ordinalNumber: int


@dataclass(frozen=True)
class BatchSessionContextLimitsOverride(OpenApiModel):
    maxInvoiceSizeInMB: int
    maxInvoiceWithAttachmentSizeInMB: int
    maxInvoices: int


@dataclass(frozen=True)
class BatchSessionEffectiveContextLimits(OpenApiModel):
    maxInvoiceSizeInMB: int
    maxInvoiceWithAttachmentSizeInMB: int
    maxInvoices: int


@dataclass(frozen=True)
class CertificateEffectiveSubjectLimits(OpenApiModel):
    maxCertificates: int | None = None


@dataclass(frozen=True)
class CertificateEnrollmentDataResponse(OpenApiModel):
    commonName: str
    countryName: str
    givenName: str | None = None
    organizationIdentifier: str | None = None
    organizationName: str | None = None
    serialNumber: str | None = None
    surname: str | None = None
    uniqueIdentifier: str | None = None


@dataclass(frozen=True)
class CertificateEnrollmentStatusResponse(OpenApiModel):
    requestDate: str
    status: StatusInfo
    certificateSerialNumber: str | None = None


@dataclass(frozen=True)
class CertificateLimit(OpenApiModel):
    limit: int
    remaining: int


@dataclass(frozen=True)
class CertificateLimitsResponse(OpenApiModel):
    canRequest: bool
    certificate: CertificateLimit
    enrollment: CertificateLimit


@dataclass(frozen=True)
class CertificateListItem(OpenApiModel):
    certificateSerialNumber: str
    commonName: str
    name: str
    requestDate: str
    status: CertificateListItemStatus
    subjectIdentifier: CertificateSubjectIdentifier
    type: KsefCertificateType
    validFrom: str
    validTo: str
    lastUseDate: str | None = None


@dataclass(frozen=True)
class CertificateSubjectIdentifier(OpenApiModel):
    type: CertificateSubjectIdentifierType
    value: str


@dataclass(frozen=True)
class CertificateSubjectLimitsOverride(OpenApiModel):
    maxCertificates: int | None = None


@dataclass(frozen=True)
class CheckAttachmentPermissionStatusResponse(OpenApiModel):
    isAttachmentAllowed: bool | None = None
    revokedDate: str | None = None


@dataclass(frozen=True)
class EffectiveApiRateLimitValues(OpenApiModel):
    perHour: int
    perMinute: int
    perSecond: int


@dataclass(frozen=True)
class EffectiveApiRateLimits(OpenApiModel):
    batchSession: EffectiveApiRateLimitValues
    invoiceDownload: EffectiveApiRateLimitValues
    invoiceExport: EffectiveApiRateLimitValues
    invoiceExportStatus: EffectiveApiRateLimitValues
    invoiceMetadata: EffectiveApiRateLimitValues
    invoiceSend: EffectiveApiRateLimitValues
    invoiceStatus: EffectiveApiRateLimitValues
    onlineSession: EffectiveApiRateLimitValues
    other: EffectiveApiRateLimitValues
    sessionInvoiceList: EffectiveApiRateLimitValues
    sessionList: EffectiveApiRateLimitValues
    sessionMisc: EffectiveApiRateLimitValues


@dataclass(frozen=True)
class EffectiveContextLimits(OpenApiModel):
    batchSession: BatchSessionEffectiveContextLimits
    onlineSession: OnlineSessionEffectiveContextLimits


@dataclass(frozen=True)
class EffectiveSubjectLimits(OpenApiModel):
    certificate: CertificateEffectiveSubjectLimits | None = None
    enrollment: EnrollmentEffectiveSubjectLimits | None = None


@dataclass(frozen=True)
class EncryptionInfo(OpenApiModel):
    encryptedSymmetricKey: str
    initializationVector: str


@dataclass(frozen=True)
class EnrollCertificateRequest(OpenApiModel):
    certificateName: str
    certificateType: KsefCertificateType
    csr: str
    validFrom: str | None = None


@dataclass(frozen=True)
class EnrollCertificateResponse(OpenApiModel):
    referenceNumber: ReferenceNumber
    timestamp: str


@dataclass(frozen=True)
class EnrollmentEffectiveSubjectLimits(OpenApiModel):
    maxEnrollments: int | None = None


@dataclass(frozen=True)
class EnrollmentSubjectLimitsOverride(OpenApiModel):
    maxEnrollments: int | None = None


@dataclass(frozen=True)
class EntityAuthorizationGrant(OpenApiModel):
    authorizationScope: InvoicePermissionType
    authorizedEntityIdentifier: EntityAuthorizationsAuthorizedEntityIdentifier
    authorizingEntityIdentifier: EntityAuthorizationsAuthorizingEntityIdentifier
    description: str
    id: PermissionId
    startDate: str
    authorIdentifier: EntityAuthorizationsAuthorIdentifier | None = None
    subjectEntityDetails: PermissionsSubjectEntityByIdentifierDetails | None = None


@dataclass(frozen=True)
class EntityAuthorizationPermissionsGrantRequest(OpenApiModel):
    description: str
    permission: EntityAuthorizationPermissionType
    subjectDetails: EntityDetails
    subjectIdentifier: EntityAuthorizationPermissionsSubjectIdentifier


@dataclass(frozen=True)
class EntityAuthorizationPermissionsQueryRequest(OpenApiModel):
    queryType: QueryType
    authorizedIdentifier: EntityAuthorizationsAuthorizedEntityIdentifier | None = None
    authorizingIdentifier: EntityAuthorizationsAuthorizingEntityIdentifier | None = None
    permissionTypes: list[InvoicePermissionType] | None = None


@dataclass(frozen=True)
class EntityAuthorizationPermissionsSubjectIdentifier(OpenApiModel):
    type: EntityAuthorizationPermissionsSubjectIdentifierType
    value: str


@dataclass(frozen=True)
class EntityAuthorizationsAuthorIdentifier(OpenApiModel):
    type: EntityAuthorizationsAuthorIdentifierType
    value: str


@dataclass(frozen=True)
class EntityAuthorizationsAuthorizedEntityIdentifier(OpenApiModel):
    type: EntityAuthorizationsAuthorizedEntityIdentifierType
    value: str


@dataclass(frozen=True)
class EntityAuthorizationsAuthorizingEntityIdentifier(OpenApiModel):
    type: EntityAuthorizationsAuthorizingEntityIdentifierType
    value: str


@dataclass(frozen=True)
class EntityByFingerprintDetails(OpenApiModel):
    address: str
    fullName: str


@dataclass(frozen=True)
class EntityDetails(OpenApiModel):
    fullName: str


@dataclass(frozen=True)
class EntityPermission(OpenApiModel):
    type: EntityPermissionType
    canDelegate: bool | None = None


@dataclass(frozen=True)
class EntityPermissionsGrantRequest(OpenApiModel):
    description: str
    permissions: list[EntityPermission]
    subjectDetails: EntityDetails
    subjectIdentifier: EntityPermissionsSubjectIdentifier


@dataclass(frozen=True)
class EntityPermissionsSubjectIdentifier(OpenApiModel):
    type: EntityPermissionsSubjectIdentifierType
    value: str


@dataclass(frozen=True)
class EntityPermissionsSubordinateEntityIdentifier(OpenApiModel):
    type: EntityPermissionsSubordinateEntityIdentifierType
    value: str


@dataclass(frozen=True)
class EntityRole(OpenApiModel):
    description: str
    role: EntityRoleType
    startDate: str
    parentEntityIdentifier: EntityRolesParentEntityIdentifier | None = None


@dataclass(frozen=True)
class EntityRolesParentEntityIdentifier(OpenApiModel):
    type: EntityRolesParentEntityIdentifierType
    value: str


@dataclass(frozen=True)
class EuEntityAdministrationPermissionsContextIdentifier(OpenApiModel):
    type: EuEntityAdministrationPermissionsContextIdentifierType
    value: str


@dataclass(frozen=True)
class EuEntityAdministrationPermissionsGrantRequest(OpenApiModel):
    contextIdentifier: EuEntityAdministrationPermissionsContextIdentifier
    description: str
    euEntityDetails: EuEntityDetails
    euEntityName: str
    subjectDetails: EuEntityPermissionSubjectDetails
    subjectIdentifier: EuEntityAdministrationPermissionsSubjectIdentifier


@dataclass(frozen=True)
class EuEntityAdministrationPermissionsSubjectIdentifier(OpenApiModel):
    type: EuEntityAdministrationPermissionsSubjectIdentifierType
    value: str


@dataclass(frozen=True)
class EuEntityDetails(OpenApiModel):
    address: str
    fullName: str


@dataclass(frozen=True)
class EuEntityPermission(OpenApiModel):
    authorIdentifier: EuEntityPermissionsAuthorIdentifier
    authorizedFingerprintIdentifier: str
    description: str
    euEntityName: str
    id: PermissionId
    permissionScope: EuEntityPermissionsQueryPermissionType
    startDate: str
    vatUeIdentifier: str
    euEntityDetails: PermissionsEuEntityDetails | None = None
    subjectEntityDetails: PermissionsSubjectEntityByFingerprintDetails | None = None
    subjectPersonDetails: PermissionsSubjectPersonByFingerprintDetails | None = None


@dataclass(frozen=True)
class EuEntityPermissionSubjectDetails(OpenApiModel):
    subjectDetailsType: EuEntityPermissionSubjectDetailsType
    entityByFp: EntityByFingerprintDetails | None = None
    personByFpNoId: PersonByFingerprintWithoutIdentifierDetails | None = None
    personByFpWithId: PersonByFingerprintWithIdentifierDetails | None = None


@dataclass(frozen=True)
class EuEntityPermissionsAuthorIdentifier(OpenApiModel):
    type: EuEntityPermissionsAuthorIdentifierType
    value: str


@dataclass(frozen=True)
class EuEntityPermissionsGrantRequest(OpenApiModel):
    description: str
    permissions: list[EuEntityPermissionType]
    subjectDetails: EuEntityPermissionSubjectDetails
    subjectIdentifier: EuEntityPermissionsSubjectIdentifier


@dataclass(frozen=True)
class EuEntityPermissionsQueryRequest(OpenApiModel):
    authorizedFingerprintIdentifier: str | None = None
    permissionTypes: list[EuEntityPermissionsQueryPermissionType] | None = None
    vatUeIdentifier: str | None = None


@dataclass(frozen=True)
class EuEntityPermissionsSubjectIdentifier(OpenApiModel):
    type: EuEntityPermissionsSubjectIdentifierType
    value: str


@dataclass(frozen=True)
class ExceptionDetails(OpenApiModel):
    details: list[str] | None = None
    exceptionCode: int | None = None
    exceptionDescription: str | None = None


@dataclass(frozen=True)
class ExceptionInfo(OpenApiModel):
    exceptionDetailList: list[ExceptionDetails] | None = None
    referenceNumber: ReferenceNumber | None = None
    serviceCode: str | None = None
    serviceCtx: str | None = None
    serviceName: str | None = None
    timestamp: str | None = None


@dataclass(frozen=True)
class ExceptionResponse(OpenApiModel):
    exception: ExceptionInfo | None = None


@dataclass(frozen=True)
class ExportInvoicesResponse(OpenApiModel):
    referenceNumber: ReferenceNumber


@dataclass(frozen=True)
class FormCode(OpenApiModel):
    schemaVersion: str
    systemCode: str
    value: str


@dataclass(frozen=True)
class GenerateTokenRequest(OpenApiModel):
    description: str
    permissions: list[TokenPermissionType]


@dataclass(frozen=True)
class GenerateTokenResponse(OpenApiModel):
    referenceNumber: ReferenceNumber
    token: str


@dataclass(frozen=True)
class IdDocument(OpenApiModel):
    country: str
    number: str
    type: str


@dataclass(frozen=True)
class IndirectPermissionsGrantRequest(OpenApiModel):
    description: str
    permissions: list[IndirectPermissionType]
    subjectDetails: PersonPermissionSubjectDetails
    subjectIdentifier: IndirectPermissionsSubjectIdentifier
    targetIdentifier: IndirectPermissionsTargetIdentifier | None = None


@dataclass(frozen=True)
class IndirectPermissionsSubjectIdentifier(OpenApiModel):
    type: IndirectPermissionsSubjectIdentifierType
    value: str


@dataclass(frozen=True)
class IndirectPermissionsTargetIdentifier(OpenApiModel):
    type: IndirectPermissionsTargetIdentifierType
    value: str | None = None


@dataclass(frozen=True)
class InitTokenAuthenticationRequest(OpenApiModel):
    challenge: Challenge
    contextIdentifier: AuthenticationContextIdentifier
    encryptedToken: str
    authorizationPolicy: AuthorizationPolicy | None = None


@dataclass(frozen=True)
class InvoiceExportRequest(OpenApiModel):
    encryption: EncryptionInfo
    filters: InvoiceQueryFilters


@dataclass(frozen=True)
class InvoiceExportStatusResponse(OpenApiModel):
    status: StatusInfo
    completedDate: str | None = None
    package: InvoicePackage | None = None
    packageExpirationDate: str | None = None


@dataclass(frozen=True)
class InvoiceMetadata(OpenApiModel):
    acquisitionDate: str
    buyer: InvoiceMetadataBuyer
    currency: str
    formCode: FormCode
    grossAmount: float
    hasAttachment: bool
    invoiceHash: Sha256HashBase64
    invoiceNumber: str
    invoiceType: InvoiceType
    invoicingDate: str
    invoicingMode: InvoicingMode
    isSelfInvoicing: bool
    issueDate: str
    ksefNumber: KsefNumber
    netAmount: float
    permanentStorageDate: str
    seller: InvoiceMetadataSeller
    vatAmount: float
    authorizedSubject: InvoiceMetadataAuthorizedSubject | None = None
    hashOfCorrectedInvoice: Sha256HashBase64 | None = None
    thirdSubjects: list[InvoiceMetadataThirdSubject] | None = None


@dataclass(frozen=True)
class InvoiceMetadataAuthorizedSubject(OpenApiModel):
    nip: Nip
    role: int
    name: str | None = None


@dataclass(frozen=True)
class InvoiceMetadataBuyer(OpenApiModel):
    identifier: InvoiceMetadataBuyerIdentifier
    name: str | None = None


@dataclass(frozen=True)
class InvoiceMetadataBuyerIdentifier(OpenApiModel):
    type: BuyerIdentifierType
    value: str | None = None


@dataclass(frozen=True)
class InvoiceMetadataSeller(OpenApiModel):
    nip: Nip
    name: str | None = None


@dataclass(frozen=True)
class InvoiceMetadataThirdSubject(OpenApiModel):
    identifier: InvoiceMetadataThirdSubjectIdentifier
    role: int
    name: str | None = None


@dataclass(frozen=True)
class InvoiceMetadataThirdSubjectIdentifier(OpenApiModel):
    type: ThirdSubjectIdentifierType
    value: str | None = None


@dataclass(frozen=True)
class InvoicePackage(OpenApiModel):
    invoiceCount: int
    isTruncated: bool
    parts: list[InvoicePackagePart]
    size: int
    lastInvoicingDate: str | None = None
    lastIssueDate: str | None = None
    lastPermanentStorageDate: str | None = None
    permanentStorageHwmDate: str | None = None


@dataclass(frozen=True)
class InvoicePackagePart(OpenApiModel):
    encryptedPartHash: Sha256HashBase64
    encryptedPartSize: int
    expirationDate: str
    method: str
    ordinalNumber: int
    partHash: Sha256HashBase64
    partName: str
    partSize: int
    url: str


@dataclass(frozen=True)
class InvoiceQueryAmount(OpenApiModel):
    type: AmountType
    from_: float | None = field(default=None, metadata={"json_key": "from"})
    to: float | None = None


@dataclass(frozen=True)
class InvoiceQueryBuyerIdentifier(OpenApiModel):
    type: BuyerIdentifierType
    value: str | None = None


@dataclass(frozen=True)
class InvoiceQueryDateRange(OpenApiModel):
    dateType: InvoiceQueryDateType
    from_: str = field(metadata={"json_key": "from"})
    restrictToPermanentStorageHwmDate: bool | None = None
    to: str | None = None


@dataclass(frozen=True)
class InvoiceQueryFilters(OpenApiModel):
    dateRange: InvoiceQueryDateRange
    subjectType: InvoiceQuerySubjectType
    amount: InvoiceQueryAmount | None = None
    buyerIdentifier: InvoiceQueryBuyerIdentifier | None = None
    currencyCodes: list[CurrencyCode] | None = None
    formType: InvoiceQueryFormType | None = None
    hasAttachment: bool | None = None
    invoiceNumber: str | None = None
    invoiceTypes: list[InvoiceType] | None = None
    invoicingMode: InvoicingMode | None = None
    isSelfInvoicing: bool | None = None
    ksefNumber: KsefNumber | None = None
    sellerNip: Nip | None = None


@dataclass(frozen=True)
class InvoiceStatusInfo(OpenApiModel):
    code: int
    description: str
    details: list[str] | None = None
    extensions: dict[str, str | None] | None = None


@dataclass(frozen=True)
class OnlineSessionContextLimitsOverride(OpenApiModel):
    maxInvoiceSizeInMB: int
    maxInvoiceWithAttachmentSizeInMB: int
    maxInvoices: int


@dataclass(frozen=True)
class OnlineSessionEffectiveContextLimits(OpenApiModel):
    maxInvoiceSizeInMB: int
    maxInvoiceWithAttachmentSizeInMB: int
    maxInvoices: int


@dataclass(frozen=True)
class OpenBatchSessionRequest(OpenApiModel):
    batchFile: BatchFileInfo
    encryption: EncryptionInfo
    formCode: FormCode
    offlineMode: bool | None = None


@dataclass(frozen=True)
class OpenBatchSessionResponse(OpenApiModel):
    partUploadRequests: list[PartUploadRequest]
    referenceNumber: ReferenceNumber


@dataclass(frozen=True)
class OpenOnlineSessionRequest(OpenApiModel):
    encryption: EncryptionInfo
    formCode: FormCode


@dataclass(frozen=True)
class OpenOnlineSessionResponse(OpenApiModel):
    referenceNumber: ReferenceNumber
    validUntil: str


@dataclass(frozen=True)
class PartUploadRequest(OpenApiModel):
    headers: dict[str, str | None]
    method: str
    ordinalNumber: int
    url: str


@dataclass(frozen=True)
class PeppolProvider(OpenApiModel):
    dateCreated: str
    id: PeppolId
    name: str


@dataclass(frozen=True)
class PermissionsEuEntityDetails(OpenApiModel):
    address: str
    fullName: str


@dataclass(frozen=True)
class PermissionsOperationResponse(OpenApiModel):
    referenceNumber: ReferenceNumber


@dataclass(frozen=True)
class PermissionsOperationStatusResponse(OpenApiModel):
    status: StatusInfo


@dataclass(frozen=True)
class PermissionsSubjectEntityByFingerprintDetails(OpenApiModel):
    fullName: str
    subjectDetailsType: EntitySubjectByFingerprintDetailsType
    address: str | None = None


@dataclass(frozen=True)
class PermissionsSubjectEntityByIdentifierDetails(OpenApiModel):
    fullName: str
    subjectDetailsType: EntitySubjectByIdentifierDetailsType


@dataclass(frozen=True)
class PermissionsSubjectEntityDetails(OpenApiModel):
    fullName: str
    subjectDetailsType: EntitySubjectDetailsType
    address: str | None = None


@dataclass(frozen=True)
class PermissionsSubjectPersonByFingerprintDetails(OpenApiModel):
    firstName: str
    lastName: str
    subjectDetailsType: PersonSubjectByFingerprintDetailsType
    birthDate: str | None = None
    idDocument: IdDocument | None = None
    personIdentifier: PersonIdentifier | None = None


@dataclass(frozen=True)
class PermissionsSubjectPersonDetails(OpenApiModel):
    firstName: str
    lastName: str
    subjectDetailsType: PersonSubjectDetailsType
    birthDate: str | None = None
    idDocument: IdDocument | None = None
    personIdentifier: PersonIdentifier | None = None


@dataclass(frozen=True)
class PersonByFingerprintWithIdentifierDetails(OpenApiModel):
    firstName: str
    identifier: PersonIdentifier
    lastName: str


@dataclass(frozen=True)
class PersonByFingerprintWithoutIdentifierDetails(OpenApiModel):
    birthDate: str
    firstName: str
    idDocument: IdDocument
    lastName: str


@dataclass(frozen=True)
class PersonCreateRequest(OpenApiModel):
    description: str
    isBailiff: bool
    nip: Nip
    pesel: Pesel
    createdDate: str | None = None
    isDeceased: bool | None = None


@dataclass(frozen=True)
class PersonDetails(OpenApiModel):
    firstName: str
    lastName: str


@dataclass(frozen=True)
class PersonIdentifier(OpenApiModel):
    type: PersonIdentifierType
    value: str


@dataclass(frozen=True)
class PersonPermission(OpenApiModel):
    authorIdentifier: PersonPermissionsAuthorIdentifier
    authorizedIdentifier: PersonPermissionsAuthorizedIdentifier
    canDelegate: bool
    description: str
    id: PermissionId
    permissionScope: PersonPermissionScope
    permissionState: PermissionState
    startDate: str
    contextIdentifier: PersonPermissionsContextIdentifier | None = None
    subjectEntityDetails: PermissionsSubjectEntityDetails | None = None
    subjectPersonDetails: PermissionsSubjectPersonDetails | None = None
    targetIdentifier: PersonPermissionsTargetIdentifier | None = None


@dataclass(frozen=True)
class PersonPermissionSubjectDetails(OpenApiModel):
    subjectDetailsType: PersonPermissionSubjectDetailsType
    personByFpNoId: PersonByFingerprintWithoutIdentifierDetails | None = None
    personByFpWithId: PersonByFingerprintWithIdentifierDetails | None = None
    personById: PersonDetails | None = None


@dataclass(frozen=True)
class PersonPermissionsAuthorIdentifier(OpenApiModel):
    type: PersonPermissionsAuthorIdentifierType
    value: str | None = None


@dataclass(frozen=True)
class PersonPermissionsAuthorizedIdentifier(OpenApiModel):
    type: PersonPermissionsAuthorizedIdentifierType
    value: str


@dataclass(frozen=True)
class PersonPermissionsContextIdentifier(OpenApiModel):
    type: PersonPermissionsContextIdentifierType
    value: str


@dataclass(frozen=True)
class PersonPermissionsGrantRequest(OpenApiModel):
    description: str
    permissions: list[PersonPermissionType]
    subjectDetails: PersonPermissionSubjectDetails
    subjectIdentifier: PersonPermissionsSubjectIdentifier


@dataclass(frozen=True)
class PersonPermissionsQueryRequest(OpenApiModel):
    queryType: PersonPermissionsQueryType
    authorIdentifier: PersonPermissionsAuthorIdentifier | None = None
    authorizedIdentifier: PersonPermissionsAuthorizedIdentifier | None = None
    contextIdentifier: PersonPermissionsContextIdentifier | None = None
    permissionState: PermissionState | None = None
    permissionTypes: list[PersonPermissionType] | None = None
    targetIdentifier: PersonPermissionsTargetIdentifier | None = None


@dataclass(frozen=True)
class PersonPermissionsSubjectIdentifier(OpenApiModel):
    type: PersonPermissionsSubjectIdentifierType
    value: str


@dataclass(frozen=True)
class PersonPermissionsTargetIdentifier(OpenApiModel):
    type: PersonPermissionsTargetIdentifierType
    value: str | None = None


@dataclass(frozen=True)
class PersonRemoveRequest(OpenApiModel):
    nip: Nip


@dataclass(frozen=True)
class PersonalPermission(OpenApiModel):
    canDelegate: bool
    description: str
    id: PermissionId
    permissionScope: PersonalPermissionScope
    permissionState: PermissionState
    startDate: str
    authorizedIdentifier: PersonalPermissionsAuthorizedIdentifier | None = None
    contextIdentifier: PersonalPermissionsContextIdentifier | None = None
    subjectEntityDetails: PermissionsSubjectEntityDetails | None = None
    subjectPersonDetails: PermissionsSubjectPersonDetails | None = None
    targetIdentifier: PersonalPermissionsTargetIdentifier | None = None


@dataclass(frozen=True)
class PersonalPermissionsAuthorizedIdentifier(OpenApiModel):
    type: PersonalPermissionsAuthorizedIdentifierType
    value: str


@dataclass(frozen=True)
class PersonalPermissionsContextIdentifier(OpenApiModel):
    type: PersonalPermissionsContextIdentifierType
    value: str


@dataclass(frozen=True)
class PersonalPermissionsQueryRequest(OpenApiModel):
    contextIdentifier: PersonalPermissionsContextIdentifier | None = None
    permissionState: PermissionState | None = None
    permissionTypes: list[PersonalPermissionType] | None = None
    targetIdentifier: PersonalPermissionsTargetIdentifier | None = None


@dataclass(frozen=True)
class PersonalPermissionsTargetIdentifier(OpenApiModel):
    type: PersonalPermissionsTargetIdentifierType
    value: str | None = None


@dataclass(frozen=True)
class PublicKeyCertificate(OpenApiModel):
    certificate: str
    usage: list[PublicKeyCertificateUsage]
    validFrom: str
    validTo: str


@dataclass(frozen=True)
class QueryCertificatesRequest(OpenApiModel):
    certificateSerialNumber: str | None = None
    expiresAfter: str | None = None
    name: str | None = None
    status: CertificateListItemStatus | None = None
    type: KsefCertificateType | None = None


@dataclass(frozen=True)
class QueryCertificatesResponse(OpenApiModel):
    certificates: list[CertificateListItem]
    hasMore: bool


@dataclass(frozen=True)
class QueryEntityAuthorizationPermissionsResponse(OpenApiModel):
    authorizationGrants: list[EntityAuthorizationGrant]
    hasMore: bool


@dataclass(frozen=True)
class QueryEntityRolesResponse(OpenApiModel):
    hasMore: bool
    roles: list[EntityRole]


@dataclass(frozen=True)
class QueryEuEntityPermissionsResponse(OpenApiModel):
    hasMore: bool
    permissions: list[EuEntityPermission]


@dataclass(frozen=True)
class QueryInvoicesMetadataResponse(OpenApiModel):
    hasMore: bool
    invoices: list[InvoiceMetadata]
    isTruncated: bool
    permanentStorageHwmDate: str | None = None


@dataclass(frozen=True)
class QueryPeppolProvidersResponse(OpenApiModel):
    hasMore: bool
    peppolProviders: list[PeppolProvider]


@dataclass(frozen=True)
class QueryPersonPermissionsResponse(OpenApiModel):
    hasMore: bool
    permissions: list[PersonPermission]


@dataclass(frozen=True)
class QueryPersonalPermissionsResponse(OpenApiModel):
    hasMore: bool
    permissions: list[PersonalPermission]


@dataclass(frozen=True)
class QuerySubordinateEntityRolesResponse(OpenApiModel):
    hasMore: bool
    roles: list[SubordinateEntityRole]


@dataclass(frozen=True)
class QuerySubunitPermissionsResponse(OpenApiModel):
    hasMore: bool
    permissions: list[SubunitPermission]


@dataclass(frozen=True)
class QueryTokensResponse(OpenApiModel):
    tokens: list[QueryTokensResponseItem]
    continuationToken: str | None = None


@dataclass(frozen=True)
class QueryTokensResponseItem(OpenApiModel):
    authorIdentifier: TokenAuthorIdentifierTypeIdentifier
    contextIdentifier: TokenContextIdentifierTypeIdentifier
    dateCreated: str
    description: str
    referenceNumber: ReferenceNumber
    requestedPermissions: list[TokenPermissionType]
    status: AuthenticationTokenStatus
    lastUseDate: str | None = None
    statusDetails: list[str] | None = None


@dataclass(frozen=True)
class RetrieveCertificatesListItem(OpenApiModel):
    certificate: str
    certificateName: str
    certificateSerialNumber: str
    certificateType: KsefCertificateType


@dataclass(frozen=True)
class RetrieveCertificatesRequest(OpenApiModel):
    certificateSerialNumbers: list[str]


@dataclass(frozen=True)
class RetrieveCertificatesResponse(OpenApiModel):
    certificates: list[RetrieveCertificatesListItem]


@dataclass(frozen=True)
class RevokeCertificateRequest(OpenApiModel):
    revocationReason: CertificateRevocationReason | None = None


@dataclass(frozen=True)
class SendInvoiceRequest(OpenApiModel):
    encryptedInvoiceContent: str
    encryptedInvoiceHash: Sha256HashBase64
    encryptedInvoiceSize: int
    invoiceHash: Sha256HashBase64
    invoiceSize: int
    hashOfCorrectedInvoice: Sha256HashBase64 | None = None
    offlineMode: bool | None = None


@dataclass(frozen=True)
class SendInvoiceResponse(OpenApiModel):
    referenceNumber: ReferenceNumber


@dataclass(frozen=True)
class SessionInvoiceStatusResponse(OpenApiModel):
    invoiceHash: Sha256HashBase64
    invoicingDate: str
    ordinalNumber: int
    referenceNumber: ReferenceNumber
    status: InvoiceStatusInfo
    acquisitionDate: str | None = None
    invoiceFileName: str | None = None
    invoiceNumber: str | None = None
    invoicingMode: InvoicingMode | None = None
    ksefNumber: KsefNumber | None = None
    permanentStorageDate: str | None = None
    upoDownloadUrl: str | None = None
    upoDownloadUrlExpirationDate: str | None = None


@dataclass(frozen=True)
class SessionInvoicesResponse(OpenApiModel):
    invoices: list[SessionInvoiceStatusResponse]
    continuationToken: str | None = None


@dataclass(frozen=True)
class SessionStatusResponse(OpenApiModel):
    dateCreated: str
    dateUpdated: str
    status: StatusInfo
    failedInvoiceCount: int | None = None
    invoiceCount: int | None = None
    successfulInvoiceCount: int | None = None
    upo: UpoResponse | None = None
    validUntil: str | None = None


@dataclass(frozen=True)
class SessionsQueryResponse(OpenApiModel):
    sessions: list[SessionsQueryResponseItem]
    continuationToken: str | None = None


@dataclass(frozen=True)
class SessionsQueryResponseItem(OpenApiModel):
    dateCreated: str
    dateUpdated: str
    failedInvoiceCount: int
    referenceNumber: ReferenceNumber
    status: StatusInfo
    successfulInvoiceCount: int
    totalInvoiceCount: int
    validUntil: str | None = None


@dataclass(frozen=True)
class SetRateLimitsRequest(OpenApiModel):
    rateLimits: ApiRateLimitsOverride


@dataclass(frozen=True)
class SetSessionLimitsRequest(OpenApiModel):
    batchSession: BatchSessionContextLimitsOverride
    onlineSession: OnlineSessionContextLimitsOverride


@dataclass(frozen=True)
class SetSubjectLimitsRequest(OpenApiModel):
    certificate: CertificateSubjectLimitsOverride | None = None
    enrollment: EnrollmentSubjectLimitsOverride | None = None
    subjectIdentifierType: SubjectIdentifierType | None = None


@dataclass(frozen=True)
class StatusInfo(OpenApiModel):
    code: int
    description: str
    details: list[str] | None = None


@dataclass(frozen=True)
class SubjectCreateRequest(OpenApiModel):
    description: str
    subjectNip: Nip
    subjectType: SubjectType
    createdDate: str | None = None
    subunits: list[Subunit] | None = None


@dataclass(frozen=True)
class SubjectRemoveRequest(OpenApiModel):
    subjectNip: Nip


@dataclass(frozen=True)
class SubordinateEntityRole(OpenApiModel):
    description: str
    role: SubordinateEntityRoleType
    startDate: str
    subordinateEntityIdentifier: SubordinateRoleSubordinateEntityIdentifier


@dataclass(frozen=True)
class SubordinateEntityRolesQueryRequest(OpenApiModel):
    subordinateEntityIdentifier: EntityPermissionsSubordinateEntityIdentifier | None = None


@dataclass(frozen=True)
class SubordinateRoleSubordinateEntityIdentifier(OpenApiModel):
    type: SubordinateRoleSubordinateEntityIdentifierType
    value: str


@dataclass(frozen=True)
class Subunit(OpenApiModel):
    description: str
    subjectNip: Nip


@dataclass(frozen=True)
class SubunitPermission(OpenApiModel):
    authorIdentifier: SubunitPermissionsAuthorIdentifier
    authorizedIdentifier: SubunitPermissionsAuthorizedIdentifier
    description: str
    id: PermissionId
    permissionScope: SubunitPermissionScope
    startDate: str
    subunitIdentifier: SubunitPermissionsSubunitIdentifier
    subjectPersonDetails: PermissionsSubjectPersonDetails | None = None
    subunitName: str | None = None


@dataclass(frozen=True)
class SubunitPermissionsAuthorIdentifier(OpenApiModel):
    type: SubunitPermissionsAuthorIdentifierType
    value: str


@dataclass(frozen=True)
class SubunitPermissionsAuthorizedIdentifier(OpenApiModel):
    type: SubunitPermissionsSubjectIdentifierType
    value: str


@dataclass(frozen=True)
class SubunitPermissionsContextIdentifier(OpenApiModel):
    type: SubunitPermissionsContextIdentifierType
    value: str


@dataclass(frozen=True)
class SubunitPermissionsGrantRequest(OpenApiModel):
    contextIdentifier: SubunitPermissionsContextIdentifier
    description: str
    subjectDetails: PersonPermissionSubjectDetails
    subjectIdentifier: SubunitPermissionsSubjectIdentifier
    subunitName: str | None = None


@dataclass(frozen=True)
class SubunitPermissionsQueryRequest(OpenApiModel):
    subunitIdentifier: SubunitPermissionsSubunitIdentifier | None = None


@dataclass(frozen=True)
class SubunitPermissionsSubjectIdentifier(OpenApiModel):
    type: SubunitPermissionsSubjectIdentifierType
    value: str


@dataclass(frozen=True)
class SubunitPermissionsSubunitIdentifier(OpenApiModel):
    type: SubunitPermissionsSubunitIdentifierType
    value: str


@dataclass(frozen=True)
class TestDataAuthorizedIdentifier(OpenApiModel):
    type: TestDataAuthorizedIdentifierType
    value: str


@dataclass(frozen=True)
class TestDataContextIdentifier(OpenApiModel):
    type: TestDataContextIdentifierType
    value: str


@dataclass(frozen=True)
class TestDataPermission(OpenApiModel):
    description: str
    permissionType: TestDataPermissionType


@dataclass(frozen=True)
class TestDataPermissionsGrantRequest(OpenApiModel):
    authorizedIdentifier: TestDataAuthorizedIdentifier
    contextIdentifier: TestDataContextIdentifier
    permissions: list[TestDataPermission]


@dataclass(frozen=True)
class TestDataPermissionsRevokeRequest(OpenApiModel):
    authorizedIdentifier: TestDataAuthorizedIdentifier
    contextIdentifier: TestDataContextIdentifier


@dataclass(frozen=True)
class TokenAuthorIdentifierTypeIdentifier(OpenApiModel):
    type: TokenAuthorIdentifierType
    value: str


@dataclass(frozen=True)
class TokenContextIdentifierTypeIdentifier(OpenApiModel):
    type: TokenContextIdentifierType
    value: str


@dataclass(frozen=True)
class TokenInfo(OpenApiModel):
    token: str
    validUntil: str


@dataclass(frozen=True)
class TokenStatusResponse(OpenApiModel):
    authorIdentifier: TokenAuthorIdentifierTypeIdentifier
    contextIdentifier: TokenContextIdentifierTypeIdentifier
    dateCreated: str
    description: str
    referenceNumber: ReferenceNumber
    requestedPermissions: list[TokenPermissionType]
    status: AuthenticationTokenStatus
    lastUseDate: str | None = None
    statusDetails: list[str] | None = None


@dataclass(frozen=True)
class TooManyRequestsResponse(OpenApiModel):
    status: dict[str, Any]


@dataclass(frozen=True)
class UpoPageResponse(OpenApiModel):
    downloadUrl: str
    downloadUrlExpirationDate: str
    referenceNumber: ReferenceNumber


@dataclass(frozen=True)
class UpoResponse(OpenApiModel):
    pages: list[UpoPageResponse]
