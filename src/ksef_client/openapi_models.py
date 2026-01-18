# Generated from ksef-docs/open-api.json. Do not edit manually.
from __future__ import annotations

from dataclasses import MISSING, dataclass, field, fields
from enum import Enum
import sys
from typing import Any, Optional, TypeAlias, TypeVar
from typing import get_args, get_origin, get_type_hints

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
    if isinstance(type_hint, type) and issubclass(type_hint, OpenApiModel):
        if isinstance(value, dict):
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
        for model_field in fields(cls):
            json_key = model_field.metadata.get("json_key", model_field.name)
            if json_key in data:
                type_hint = type_map.get(model_field.name, Any)
                kwargs[model_field.name] = _convert_value(type_hint, data[json_key])
        return cls(**kwargs)

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for model_field in fields(self):
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
    ip4Addresses: Optional[list[str]] = None
    ip4Masks: Optional[list[str]] = None
    ip4Ranges: Optional[list[str]] = None

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
    expectedEndDate: Optional[str] = None

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
    isCurrent: Optional[bool] = None
    isTokenRedeemed: Optional[bool] = None
    lastTokenRefreshDate: Optional[str] = None
    refreshTokenValidUntil: Optional[str] = None

@dataclass(frozen=True)
class AuthenticationListResponse(OpenApiModel):
    items: list[AuthenticationListItem]
    continuationToken: Optional[str] = None

@dataclass(frozen=True)
class AuthenticationOperationStatusResponse(OpenApiModel):
    authenticationMethod: AuthenticationMethod
    startDate: str
    status: StatusInfo
    isTokenRedeemed: Optional[bool] = None
    lastTokenRefreshDate: Optional[str] = None
    refreshTokenValidUntil: Optional[str] = None

@dataclass(frozen=True)
class AuthenticationTokenRefreshResponse(OpenApiModel):
    accessToken: TokenInfo

@dataclass(frozen=True)
class AuthenticationTokensResponse(OpenApiModel):
    accessToken: TokenInfo
    refreshToken: TokenInfo

@dataclass(frozen=True)
class AuthorizationPolicy(OpenApiModel):
    allowedIps: Optional[AllowedIps] = None

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
    maxCertificates: Optional[int] = None

@dataclass(frozen=True)
class CertificateEnrollmentDataResponse(OpenApiModel):
    commonName: str
    countryName: str
    givenName: Optional[str] = None
    organizationIdentifier: Optional[str] = None
    organizationName: Optional[str] = None
    serialNumber: Optional[str] = None
    surname: Optional[str] = None
    uniqueIdentifier: Optional[str] = None

@dataclass(frozen=True)
class CertificateEnrollmentStatusResponse(OpenApiModel):
    requestDate: str
    status: StatusInfo
    certificateSerialNumber: Optional[str] = None

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
    lastUseDate: Optional[str] = None

@dataclass(frozen=True)
class CertificateSubjectIdentifier(OpenApiModel):
    type: CertificateSubjectIdentifierType
    value: str

@dataclass(frozen=True)
class CertificateSubjectLimitsOverride(OpenApiModel):
    maxCertificates: Optional[int] = None

@dataclass(frozen=True)
class CheckAttachmentPermissionStatusResponse(OpenApiModel):
    isAttachmentAllowed: Optional[bool] = None
    revokedDate: Optional[str] = None

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
    certificate: Optional[CertificateEffectiveSubjectLimits] = None
    enrollment: Optional[EnrollmentEffectiveSubjectLimits] = None

@dataclass(frozen=True)
class EncryptionInfo(OpenApiModel):
    encryptedSymmetricKey: str
    initializationVector: str

@dataclass(frozen=True)
class EnrollCertificateRequest(OpenApiModel):
    certificateName: str
    certificateType: KsefCertificateType
    csr: str
    validFrom: Optional[str] = None

@dataclass(frozen=True)
class EnrollCertificateResponse(OpenApiModel):
    referenceNumber: ReferenceNumber
    timestamp: str

@dataclass(frozen=True)
class EnrollmentEffectiveSubjectLimits(OpenApiModel):
    maxEnrollments: Optional[int] = None

@dataclass(frozen=True)
class EnrollmentSubjectLimitsOverride(OpenApiModel):
    maxEnrollments: Optional[int] = None

@dataclass(frozen=True)
class EntityAuthorizationGrant(OpenApiModel):
    authorizationScope: InvoicePermissionType
    authorizedEntityIdentifier: EntityAuthorizationsAuthorizedEntityIdentifier
    authorizingEntityIdentifier: EntityAuthorizationsAuthorizingEntityIdentifier
    description: str
    id: PermissionId
    startDate: str
    authorIdentifier: Optional[EntityAuthorizationsAuthorIdentifier] = None
    subjectEntityDetails: Optional[PermissionsSubjectEntityByIdentifierDetails] = None

@dataclass(frozen=True)
class EntityAuthorizationPermissionsGrantRequest(OpenApiModel):
    description: str
    permission: EntityAuthorizationPermissionType
    subjectDetails: EntityDetails
    subjectIdentifier: EntityAuthorizationPermissionsSubjectIdentifier

@dataclass(frozen=True)
class EntityAuthorizationPermissionsQueryRequest(OpenApiModel):
    queryType: QueryType
    authorizedIdentifier: Optional[EntityAuthorizationsAuthorizedEntityIdentifier] = None
    authorizingIdentifier: Optional[EntityAuthorizationsAuthorizingEntityIdentifier] = None
    permissionTypes: Optional[list[InvoicePermissionType]] = None

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
    canDelegate: Optional[bool] = None

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
    parentEntityIdentifier: Optional[EntityRolesParentEntityIdentifier] = None

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
    euEntityDetails: Optional[PermissionsEuEntityDetails] = None
    subjectEntityDetails: Optional[PermissionsSubjectEntityByFingerprintDetails] = None
    subjectPersonDetails: Optional[PermissionsSubjectPersonByFingerprintDetails] = None

@dataclass(frozen=True)
class EuEntityPermissionSubjectDetails(OpenApiModel):
    subjectDetailsType: EuEntityPermissionSubjectDetailsType
    entityByFp: Optional[EntityByFingerprintDetails] = None
    personByFpNoId: Optional[PersonByFingerprintWithoutIdentifierDetails] = None
    personByFpWithId: Optional[PersonByFingerprintWithIdentifierDetails] = None

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
    authorizedFingerprintIdentifier: Optional[str] = None
    permissionTypes: Optional[list[EuEntityPermissionsQueryPermissionType]] = None
    vatUeIdentifier: Optional[str] = None

@dataclass(frozen=True)
class EuEntityPermissionsSubjectIdentifier(OpenApiModel):
    type: EuEntityPermissionsSubjectIdentifierType
    value: str

@dataclass(frozen=True)
class ExceptionDetails(OpenApiModel):
    details: Optional[list[str]] = None
    exceptionCode: Optional[int] = None
    exceptionDescription: Optional[str] = None

@dataclass(frozen=True)
class ExceptionInfo(OpenApiModel):
    exceptionDetailList: Optional[list[ExceptionDetails]] = None
    referenceNumber: Optional[ReferenceNumber] = None
    serviceCode: Optional[str] = None
    serviceCtx: Optional[str] = None
    serviceName: Optional[str] = None
    timestamp: Optional[str] = None

@dataclass(frozen=True)
class ExceptionResponse(OpenApiModel):
    exception: Optional[ExceptionInfo] = None

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
    targetIdentifier: Optional[IndirectPermissionsTargetIdentifier] = None

@dataclass(frozen=True)
class IndirectPermissionsSubjectIdentifier(OpenApiModel):
    type: IndirectPermissionsSubjectIdentifierType
    value: str

@dataclass(frozen=True)
class IndirectPermissionsTargetIdentifier(OpenApiModel):
    type: IndirectPermissionsTargetIdentifierType
    value: Optional[str] = None

@dataclass(frozen=True)
class InitTokenAuthenticationRequest(OpenApiModel):
    challenge: Challenge
    contextIdentifier: AuthenticationContextIdentifier
    encryptedToken: str
    authorizationPolicy: Optional[AuthorizationPolicy] = None

@dataclass(frozen=True)
class InvoiceExportRequest(OpenApiModel):
    encryption: EncryptionInfo
    filters: InvoiceQueryFilters

@dataclass(frozen=True)
class InvoiceExportStatusResponse(OpenApiModel):
    status: StatusInfo
    completedDate: Optional[str] = None
    package: Optional[InvoicePackage] = None
    packageExpirationDate: Optional[str] = None

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
    authorizedSubject: Optional[InvoiceMetadataAuthorizedSubject] = None
    hashOfCorrectedInvoice: Optional[Sha256HashBase64] = None
    thirdSubjects: Optional[list[InvoiceMetadataThirdSubject]] = None

@dataclass(frozen=True)
class InvoiceMetadataAuthorizedSubject(OpenApiModel):
    nip: Nip
    role: int
    name: Optional[str] = None

@dataclass(frozen=True)
class InvoiceMetadataBuyer(OpenApiModel):
    identifier: InvoiceMetadataBuyerIdentifier
    name: Optional[str] = None

@dataclass(frozen=True)
class InvoiceMetadataBuyerIdentifier(OpenApiModel):
    type: BuyerIdentifierType
    value: Optional[str] = None

@dataclass(frozen=True)
class InvoiceMetadataSeller(OpenApiModel):
    nip: Nip
    name: Optional[str] = None

@dataclass(frozen=True)
class InvoiceMetadataThirdSubject(OpenApiModel):
    identifier: InvoiceMetadataThirdSubjectIdentifier
    role: int
    name: Optional[str] = None

@dataclass(frozen=True)
class InvoiceMetadataThirdSubjectIdentifier(OpenApiModel):
    type: ThirdSubjectIdentifierType
    value: Optional[str] = None

@dataclass(frozen=True)
class InvoicePackage(OpenApiModel):
    invoiceCount: int
    isTruncated: bool
    parts: list[InvoicePackagePart]
    size: int
    lastInvoicingDate: Optional[str] = None
    lastIssueDate: Optional[str] = None
    lastPermanentStorageDate: Optional[str] = None
    permanentStorageHwmDate: Optional[str] = None

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
    from_: Optional[float] = field(default=None, metadata={"json_key": "from"})
    to: Optional[float] = None

@dataclass(frozen=True)
class InvoiceQueryBuyerIdentifier(OpenApiModel):
    type: BuyerIdentifierType
    value: Optional[str] = None

@dataclass(frozen=True)
class InvoiceQueryDateRange(OpenApiModel):
    dateType: InvoiceQueryDateType
    from_: str = field(metadata={"json_key": "from"})
    restrictToPermanentStorageHwmDate: Optional[bool] = None
    to: Optional[str] = None

@dataclass(frozen=True)
class InvoiceQueryFilters(OpenApiModel):
    dateRange: InvoiceQueryDateRange
    subjectType: InvoiceQuerySubjectType
    amount: Optional[InvoiceQueryAmount] = None
    buyerIdentifier: Optional[InvoiceQueryBuyerIdentifier] = None
    currencyCodes: Optional[list[CurrencyCode]] = None
    formType: Optional[InvoiceQueryFormType] = None
    hasAttachment: Optional[bool] = None
    invoiceNumber: Optional[str] = None
    invoiceTypes: Optional[list[InvoiceType]] = None
    invoicingMode: Optional[InvoicingMode] = None
    isSelfInvoicing: Optional[bool] = None
    ksefNumber: Optional[KsefNumber] = None
    sellerNip: Optional[Nip] = None

@dataclass(frozen=True)
class InvoiceStatusInfo(OpenApiModel):
    code: int
    description: str
    details: Optional[list[str]] = None
    extensions: Optional[dict[str, Optional[str]]] = None

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
    offlineMode: Optional[bool] = None

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
    headers: dict[str, Optional[str]]
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
    address: Optional[str] = None

@dataclass(frozen=True)
class PermissionsSubjectEntityByIdentifierDetails(OpenApiModel):
    fullName: str
    subjectDetailsType: EntitySubjectByIdentifierDetailsType

@dataclass(frozen=True)
class PermissionsSubjectEntityDetails(OpenApiModel):
    fullName: str
    subjectDetailsType: EntitySubjectDetailsType
    address: Optional[str] = None

@dataclass(frozen=True)
class PermissionsSubjectPersonByFingerprintDetails(OpenApiModel):
    firstName: str
    lastName: str
    subjectDetailsType: PersonSubjectByFingerprintDetailsType
    birthDate: Optional[str] = None
    idDocument: Optional[IdDocument] = None
    personIdentifier: Optional[PersonIdentifier] = None

@dataclass(frozen=True)
class PermissionsSubjectPersonDetails(OpenApiModel):
    firstName: str
    lastName: str
    subjectDetailsType: PersonSubjectDetailsType
    birthDate: Optional[str] = None
    idDocument: Optional[IdDocument] = None
    personIdentifier: Optional[PersonIdentifier] = None

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
    createdDate: Optional[str] = None
    isDeceased: Optional[bool] = None

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
    contextIdentifier: Optional[PersonPermissionsContextIdentifier] = None
    subjectEntityDetails: Optional[PermissionsSubjectEntityDetails] = None
    subjectPersonDetails: Optional[PermissionsSubjectPersonDetails] = None
    targetIdentifier: Optional[PersonPermissionsTargetIdentifier] = None

@dataclass(frozen=True)
class PersonPermissionSubjectDetails(OpenApiModel):
    subjectDetailsType: PersonPermissionSubjectDetailsType
    personByFpNoId: Optional[PersonByFingerprintWithoutIdentifierDetails] = None
    personByFpWithId: Optional[PersonByFingerprintWithIdentifierDetails] = None
    personById: Optional[PersonDetails] = None

@dataclass(frozen=True)
class PersonPermissionsAuthorIdentifier(OpenApiModel):
    type: PersonPermissionsAuthorIdentifierType
    value: Optional[str] = None

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
    authorIdentifier: Optional[PersonPermissionsAuthorIdentifier] = None
    authorizedIdentifier: Optional[PersonPermissionsAuthorizedIdentifier] = None
    contextIdentifier: Optional[PersonPermissionsContextIdentifier] = None
    permissionState: Optional[PermissionState] = None
    permissionTypes: Optional[list[PersonPermissionType]] = None
    targetIdentifier: Optional[PersonPermissionsTargetIdentifier] = None

@dataclass(frozen=True)
class PersonPermissionsSubjectIdentifier(OpenApiModel):
    type: PersonPermissionsSubjectIdentifierType
    value: str

@dataclass(frozen=True)
class PersonPermissionsTargetIdentifier(OpenApiModel):
    type: PersonPermissionsTargetIdentifierType
    value: Optional[str] = None

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
    authorizedIdentifier: Optional[PersonalPermissionsAuthorizedIdentifier] = None
    contextIdentifier: Optional[PersonalPermissionsContextIdentifier] = None
    subjectEntityDetails: Optional[PermissionsSubjectEntityDetails] = None
    subjectPersonDetails: Optional[PermissionsSubjectPersonDetails] = None
    targetIdentifier: Optional[PersonalPermissionsTargetIdentifier] = None

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
    contextIdentifier: Optional[PersonalPermissionsContextIdentifier] = None
    permissionState: Optional[PermissionState] = None
    permissionTypes: Optional[list[PersonalPermissionType]] = None
    targetIdentifier: Optional[PersonalPermissionsTargetIdentifier] = None

@dataclass(frozen=True)
class PersonalPermissionsTargetIdentifier(OpenApiModel):
    type: PersonalPermissionsTargetIdentifierType
    value: Optional[str] = None

@dataclass(frozen=True)
class PublicKeyCertificate(OpenApiModel):
    certificate: str
    usage: list[PublicKeyCertificateUsage]
    validFrom: str
    validTo: str

@dataclass(frozen=True)
class QueryCertificatesRequest(OpenApiModel):
    certificateSerialNumber: Optional[str] = None
    expiresAfter: Optional[str] = None
    name: Optional[str] = None
    status: Optional[CertificateListItemStatus] = None
    type: Optional[KsefCertificateType] = None

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
    permanentStorageHwmDate: Optional[str] = None

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
    continuationToken: Optional[str] = None

@dataclass(frozen=True)
class QueryTokensResponseItem(OpenApiModel):
    authorIdentifier: TokenAuthorIdentifierTypeIdentifier
    contextIdentifier: TokenContextIdentifierTypeIdentifier
    dateCreated: str
    description: str
    referenceNumber: ReferenceNumber
    requestedPermissions: list[TokenPermissionType]
    status: AuthenticationTokenStatus
    lastUseDate: Optional[str] = None
    statusDetails: Optional[list[str]] = None

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
    revocationReason: Optional[CertificateRevocationReason] = None

@dataclass(frozen=True)
class SendInvoiceRequest(OpenApiModel):
    encryptedInvoiceContent: str
    encryptedInvoiceHash: Sha256HashBase64
    encryptedInvoiceSize: int
    invoiceHash: Sha256HashBase64
    invoiceSize: int
    hashOfCorrectedInvoice: Optional[Sha256HashBase64] = None
    offlineMode: Optional[bool] = None

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
    acquisitionDate: Optional[str] = None
    invoiceFileName: Optional[str] = None
    invoiceNumber: Optional[str] = None
    invoicingMode: Optional[InvoicingMode] = None
    ksefNumber: Optional[KsefNumber] = None
    permanentStorageDate: Optional[str] = None
    upoDownloadUrl: Optional[str] = None
    upoDownloadUrlExpirationDate: Optional[str] = None

@dataclass(frozen=True)
class SessionInvoicesResponse(OpenApiModel):
    invoices: list[SessionInvoiceStatusResponse]
    continuationToken: Optional[str] = None

@dataclass(frozen=True)
class SessionStatusResponse(OpenApiModel):
    dateCreated: str
    dateUpdated: str
    status: StatusInfo
    failedInvoiceCount: Optional[int] = None
    invoiceCount: Optional[int] = None
    successfulInvoiceCount: Optional[int] = None
    upo: Optional[UpoResponse] = None
    validUntil: Optional[str] = None

@dataclass(frozen=True)
class SessionsQueryResponse(OpenApiModel):
    sessions: list[SessionsQueryResponseItem]
    continuationToken: Optional[str] = None

@dataclass(frozen=True)
class SessionsQueryResponseItem(OpenApiModel):
    dateCreated: str
    dateUpdated: str
    failedInvoiceCount: int
    referenceNumber: ReferenceNumber
    status: StatusInfo
    successfulInvoiceCount: int
    totalInvoiceCount: int
    validUntil: Optional[str] = None

@dataclass(frozen=True)
class SetRateLimitsRequest(OpenApiModel):
    rateLimits: ApiRateLimitsOverride

@dataclass(frozen=True)
class SetSessionLimitsRequest(OpenApiModel):
    batchSession: BatchSessionContextLimitsOverride
    onlineSession: OnlineSessionContextLimitsOverride

@dataclass(frozen=True)
class SetSubjectLimitsRequest(OpenApiModel):
    certificate: Optional[CertificateSubjectLimitsOverride] = None
    enrollment: Optional[EnrollmentSubjectLimitsOverride] = None
    subjectIdentifierType: Optional[SubjectIdentifierType] = None

@dataclass(frozen=True)
class StatusInfo(OpenApiModel):
    code: int
    description: str
    details: Optional[list[str]] = None

@dataclass(frozen=True)
class SubjectCreateRequest(OpenApiModel):
    description: str
    subjectNip: Nip
    subjectType: SubjectType
    createdDate: Optional[str] = None
    subunits: Optional[list[Subunit]] = None

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
    subordinateEntityIdentifier: Optional[EntityPermissionsSubordinateEntityIdentifier] = None

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
    subjectPersonDetails: Optional[PermissionsSubjectPersonDetails] = None
    subunitName: Optional[str] = None

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
    subunitName: Optional[str] = None

@dataclass(frozen=True)
class SubunitPermissionsQueryRequest(OpenApiModel):
    subunitIdentifier: Optional[SubunitPermissionsSubunitIdentifier] = None

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
    lastUseDate: Optional[str] = None
    statusDetails: Optional[list[str]] = None

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
