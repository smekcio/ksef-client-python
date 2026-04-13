# ruff: noqa
# Generated from the official KSeF OpenAPI spec. Do not edit manually.
from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import Enum
import sys
from typing import Any, Optional, TypeAlias, TypeVar, cast
from typing import get_args, get_origin, get_type_hints

JsonValue: TypeAlias = Any

T = TypeVar("T", bound="OpenApiModel")
_TYPE_CACHE: dict[type, dict[str, Any]] = {}

class OpenApiEnum(str, Enum):
    @classmethod
    def _missing_(cls, value: object) -> OpenApiEnum:
        if not isinstance(value, str):
            raise ValueError(f"{value!r} is not a valid {cls.__name__}")
        existing = cast(OpenApiEnum | None, cls._value2member_map_.get(value))
        if existing is not None:
            return existing
        pseudo_member = str.__new__(cls, value)
        pseudo_member._name_ = f"UNKNOWN__{len(cls._value2member_map_) + 1}"
        pseudo_member._value_ = value
        cls._value2member_map_[value] = pseudo_member
        return pseudo_member

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
        for model_field in fields(cls):  # type: ignore
            json_key = model_field.metadata.get("json_key", model_field.name)
            if json_key in data:
                type_hint = type_map.get(model_field.name, Any)
                kwargs[model_field.name] = _convert_value(type_hint, data[json_key])
        return cls(**kwargs)

    def to_dict(self, omit_none: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for model_field in fields(self):  # type: ignore
            json_key = model_field.metadata.get("json_key", model_field.name)
            value = getattr(self, model_field.name)
            if omit_none and value is None:
                continue
            result[json_key] = _serialize_value(value)
        return result

class AmountType(OpenApiEnum):
    BRUTTO = "Brutto"
    NETTO = "Netto"
    VAT = "Vat"

class AuthenticationContextIdentifierType(OpenApiEnum):
    NIP = "Nip"
    INTERNALID = "InternalId"
    NIPVATUE = "NipVatUe"
    PEPPOLID = "PeppolId"

class AuthenticationMethod(OpenApiEnum):
    TOKEN = "Token"
    TRUSTEDPROFILE = "TrustedProfile"
    INTERNALCERTIFICATE = "InternalCertificate"
    QUALIFIEDSIGNATURE = "QualifiedSignature"
    QUALIFIEDSEAL = "QualifiedSeal"
    PERSONALSIGNATURE = "PersonalSignature"
    PEPPOLSIGNATURE = "PeppolSignature"

class AuthenticationMethodCategory(OpenApiEnum):
    XADESSIGNATURE = "XadesSignature"
    NATIONALNODE = "NationalNode"
    TOKEN = "Token"
    OTHER = "Other"

class AuthenticationTokenStatus(OpenApiEnum):
    PENDING = "Pending"
    ACTIVE = "Active"
    REVOKING = "Revoking"
    REVOKED = "Revoked"
    FAILED = "Failed"

class BuyerIdentifierType(OpenApiEnum):
    NIP = "Nip"
    VATUE = "VatUe"
    OTHER = "Other"
    NONE = "None"

class CertificateListItemStatus(OpenApiEnum):
    ACTIVE = "Active"
    BLOCKED = "Blocked"
    REVOKED = "Revoked"
    EXPIRED = "Expired"

class CertificateRevocationReason(OpenApiEnum):
    UNSPECIFIED = "Unspecified"
    SUPERSEDED = "Superseded"
    KEYCOMPROMISE = "KeyCompromise"

class CertificateSubjectIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class CommonSessionStatus(OpenApiEnum):
    INPROGRESS = "InProgress"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELLED = "Cancelled"

class CurrencyCode(OpenApiEnum):
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

class EntityAuthorizationPermissionType(OpenApiEnum):
    SELFINVOICING = "SelfInvoicing"
    RRINVOICING = "RRInvoicing"
    TAXREPRESENTATIVE = "TaxRepresentative"
    PEFINVOICING = "PefInvoicing"

class EntityAuthorizationPermissionsSubjectIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PEPPOLID = "PeppolId"

class EntityAuthorizationsAuthorIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class EntityAuthorizationsAuthorizedEntityIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PEPPOLID = "PeppolId"

class EntityAuthorizationsAuthorizingEntityIdentifierType(OpenApiEnum):
    NIP = "Nip"

class EntityPermissionItemScope(OpenApiEnum):
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"

class EntityPermissionType(OpenApiEnum):
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"

class EntityPermissionsContextIdentifierType(OpenApiEnum):
    NIP = "Nip"
    INTERNALID = "InternalId"

class EntityPermissionsSubjectIdentifierType(OpenApiEnum):
    NIP = "Nip"

class EntityPermissionsSubordinateEntityIdentifierType(OpenApiEnum):
    NIP = "Nip"

class EntityRoleType(OpenApiEnum):
    COURTBAILIFF = "CourtBailiff"
    ENFORCEMENTAUTHORITY = "EnforcementAuthority"
    LOCALGOVERNMENTUNIT = "LocalGovernmentUnit"
    LOCALGOVERNMENTSUBUNIT = "LocalGovernmentSubUnit"
    VATGROUPUNIT = "VatGroupUnit"
    VATGROUPSUBUNIT = "VatGroupSubUnit"

class EntityRolesParentEntityIdentifierType(OpenApiEnum):
    NIP = "Nip"

class EntitySubjectByFingerprintDetailsType(OpenApiEnum):
    ENTITYBYFINGERPRINT = "EntityByFingerprint"

class EntitySubjectByIdentifierDetailsType(OpenApiEnum):
    ENTITYBYIDENTIFIER = "EntityByIdentifier"

class EntitySubjectDetailsType(OpenApiEnum):
    ENTITYBYIDENTIFIER = "EntityByIdentifier"
    ENTITYBYFINGERPRINT = "EntityByFingerprint"

class EuEntityAdministrationPermissionsContextIdentifierType(OpenApiEnum):
    NIPVATUE = "NipVatUe"

class EuEntityAdministrationPermissionsSubjectIdentifierType(OpenApiEnum):
    FINGERPRINT = "Fingerprint"

class EuEntityPermissionSubjectDetailsType(OpenApiEnum):
    PERSONBYFINGERPRINTWITHIDENTIFIER = "PersonByFingerprintWithIdentifier"
    PERSONBYFINGERPRINTWITHOUTIDENTIFIER = "PersonByFingerprintWithoutIdentifier"
    ENTITYBYFINGERPRINT = "EntityByFingerprint"

class EuEntityPermissionType(OpenApiEnum):
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"

class EuEntityPermissionsAuthorIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class EuEntityPermissionsQueryPermissionType(OpenApiEnum):
    VATUEMANAGE = "VatUeManage"
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"
    INTROSPECTION = "Introspection"

class EuEntityPermissionsSubjectIdentifierType(OpenApiEnum):
    FINGERPRINT = "Fingerprint"

class IndirectPermissionType(OpenApiEnum):
    INVOICEREAD = "InvoiceRead"
    INVOICEWRITE = "InvoiceWrite"

class IndirectPermissionsSubjectIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class IndirectPermissionsTargetIdentifierType(OpenApiEnum):
    NIP = "Nip"
    ALLPARTNERS = "AllPartners"
    INTERNALID = "InternalId"

class InvoicePermissionType(OpenApiEnum):
    SELFINVOICING = "SelfInvoicing"
    TAXREPRESENTATIVE = "TaxRepresentative"
    RRINVOICING = "RRInvoicing"
    PEFINVOICING = "PefInvoicing"

class InvoiceQueryDateType(OpenApiEnum):
    ISSUE = "Issue"
    INVOICING = "Invoicing"
    PERMANENTSTORAGE = "PermanentStorage"

class InvoiceQueryFormType(OpenApiEnum):
    FA = "FA"
    PEF = "PEF"
    RR = "RR"
    FA_RR = "FA_RR"

class InvoiceQuerySubjectType(OpenApiEnum):
    SUBJECT1 = "Subject1"
    SUBJECT2 = "Subject2"
    SUBJECT3 = "Subject3"
    SUBJECTAUTHORIZED = "SubjectAuthorized"

class InvoiceType(OpenApiEnum):
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

class InvoicingMode(OpenApiEnum):
    ONLINE = "Online"
    OFFLINE = "Offline"

class KsefCertificateType(OpenApiEnum):
    AUTHENTICATION = "Authentication"
    OFFLINE = "Offline"

class PermissionState(OpenApiEnum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"

class PersonIdentifierType(OpenApiEnum):
    PESEL = "Pesel"
    NIP = "Nip"

class PersonPermissionScope(OpenApiEnum):
    CREDENTIALSMANAGE = "CredentialsManage"
    CREDENTIALSREAD = "CredentialsRead"
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"
    INTROSPECTION = "Introspection"
    SUBUNITMANAGE = "SubunitManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"

class PersonPermissionSubjectDetailsType(OpenApiEnum):
    PERSONBYIDENTIFIER = "PersonByIdentifier"
    PERSONBYFINGERPRINTWITHIDENTIFIER = "PersonByFingerprintWithIdentifier"
    PERSONBYFINGERPRINTWITHOUTIDENTIFIER = "PersonByFingerprintWithoutIdentifier"

class PersonPermissionType(OpenApiEnum):
    CREDENTIALSMANAGE = "CredentialsManage"
    CREDENTIALSREAD = "CredentialsRead"
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"
    INTROSPECTION = "Introspection"
    SUBUNITMANAGE = "SubunitManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"

class PersonPermissionsAuthorIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"
    SYSTEM = "System"

class PersonPermissionsAuthorizedIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class PersonPermissionsContextIdentifierType(OpenApiEnum):
    NIP = "Nip"
    INTERNALID = "InternalId"

class PersonPermissionsQueryType(OpenApiEnum):
    PERMISSIONSINCURRENTCONTEXT = "PermissionsInCurrentContext"
    PERMISSIONSGRANTEDINCURRENTCONTEXT = "PermissionsGrantedInCurrentContext"

class PersonPermissionsSubjectIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class PersonPermissionsTargetIdentifierType(OpenApiEnum):
    NIP = "Nip"
    ALLPARTNERS = "AllPartners"
    INTERNALID = "InternalId"

class PersonSubjectByFingerprintDetailsType(OpenApiEnum):
    PERSONBYFINGERPRINTWITHIDENTIFIER = "PersonByFingerprintWithIdentifier"
    PERSONBYFINGERPRINTWITHOUTIDENTIFIER = "PersonByFingerprintWithoutIdentifier"

class PersonSubjectDetailsType(OpenApiEnum):
    PERSONBYIDENTIFIER = "PersonByIdentifier"
    PERSONBYFINGERPRINTWITHIDENTIFIER = "PersonByFingerprintWithIdentifier"
    PERSONBYFINGERPRINTWITHOUTIDENTIFIER = "PersonByFingerprintWithoutIdentifier"

class PersonalPermissionScope(OpenApiEnum):
    CREDENTIALSMANAGE = "CredentialsManage"
    CREDENTIALSREAD = "CredentialsRead"
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"
    INTROSPECTION = "Introspection"
    SUBUNITMANAGE = "SubunitManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"
    VATUEMANAGE = "VatUeManage"

class PersonalPermissionType(OpenApiEnum):
    CREDENTIALSMANAGE = "CredentialsManage"
    CREDENTIALSREAD = "CredentialsRead"
    INVOICEWRITE = "InvoiceWrite"
    INVOICEREAD = "InvoiceRead"
    INTROSPECTION = "Introspection"
    SUBUNITMANAGE = "SubunitManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"
    VATUEMANAGE = "VatUeManage"

class PersonalPermissionsAuthorizedIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class PersonalPermissionsContextIdentifierType(OpenApiEnum):
    NIP = "Nip"
    INTERNALID = "InternalId"

class PersonalPermissionsTargetIdentifierType(OpenApiEnum):
    NIP = "Nip"
    ALLPARTNERS = "AllPartners"
    INTERNALID = "InternalId"

class PublicKeyCertificateUsage(OpenApiEnum):
    KSEFTOKENENCRYPTION = "KsefTokenEncryption"
    SYMMETRICKEYENCRYPTION = "SymmetricKeyEncryption"

class QueryType(OpenApiEnum):
    GRANTED = "Granted"
    RECEIVED = "Received"

class SessionType(OpenApiEnum):
    ONLINE = "Online"
    BATCH = "Batch"

class SortOrder(OpenApiEnum):
    ASC = "Asc"
    DESC = "Desc"

class SubjectIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class SubjectType(OpenApiEnum):
    ENFORCEMENTAUTHORITY = "EnforcementAuthority"
    VATGROUP = "VatGroup"
    JST = "JST"

class SubordinateEntityRoleType(OpenApiEnum):
    LOCALGOVERNMENTSUBUNIT = "LocalGovernmentSubUnit"
    VATGROUPSUBUNIT = "VatGroupSubUnit"

class SubordinateRoleSubordinateEntityIdentifierType(OpenApiEnum):
    NIP = "Nip"

class SubunitPermissionScope(OpenApiEnum):
    CREDENTIALSMANAGE = "CredentialsManage"

class SubunitPermissionsAuthorIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class SubunitPermissionsContextIdentifierType(OpenApiEnum):
    INTERNALID = "InternalId"
    NIP = "Nip"

class SubunitPermissionsSubjectIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class SubunitPermissionsSubunitIdentifierType(OpenApiEnum):
    INTERNALID = "InternalId"
    NIP = "Nip"

class TestDataAuthenticationContextIdentifierType(OpenApiEnum):
    NIP = "Nip"
    INTERNALID = "InternalId"
    NIPVATUE = "NipVatUe"
    PEPPOLID = "PeppolId"

class TestDataAuthorizedIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class TestDataContextIdentifierType(OpenApiEnum):
    NIP = "Nip"

class TestDataPermissionType(OpenApiEnum):
    INVOICEREAD = "InvoiceRead"
    INVOICEWRITE = "InvoiceWrite"
    INTROSPECTION = "Introspection"
    CREDENTIALSREAD = "CredentialsRead"
    CREDENTIALSMANAGE = "CredentialsManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"
    SUBUNITMANAGE = "SubunitManage"

class ThirdSubjectIdentifierType(OpenApiEnum):
    NIP = "Nip"
    INTERNALID = "InternalId"
    VATUE = "VatUe"
    OTHER = "Other"
    NONE = "None"

class TokenAuthorIdentifierType(OpenApiEnum):
    NIP = "Nip"
    PESEL = "Pesel"
    FINGERPRINT = "Fingerprint"

class TokenContextIdentifierType(OpenApiEnum):
    NIP = "Nip"
    INTERNALID = "InternalId"
    NIPVATUE = "NipVatUe"
    PEPPOLID = "PeppolId"

class TokenPermissionType(OpenApiEnum):
    INVOICEREAD = "InvoiceRead"
    INVOICEWRITE = "InvoiceWrite"
    CREDENTIALSREAD = "CredentialsRead"
    CREDENTIALSMANAGE = "CredentialsManage"
    SUBUNITMANAGE = "SubunitManage"
    ENFORCEMENTOPERATIONS = "EnforcementOperations"
    INTROSPECTION = "Introspection"

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
    ip4_addresses: Optional[list[str]] = field(default=None, metadata={"json_key": "ip4Addresses"})
    ip4_masks: Optional[list[str]] = field(default=None, metadata={"json_key": "ip4Masks"})
    ip4_ranges: Optional[list[str]] = field(default=None, metadata={"json_key": "ip4Ranges"})

@dataclass(frozen=True)
class ApiError(OpenApiModel):
    code: int
    description: str
    details: Optional[list[str]] = None

@dataclass(frozen=True)
class ApiRateLimitValuesOverride(OpenApiModel):
    per_hour: int = field(metadata={"json_key": "perHour"})
    per_minute: int = field(metadata={"json_key": "perMinute"})
    per_second: int = field(metadata={"json_key": "perSecond"})

@dataclass(frozen=True)
class ApiRateLimitsOverride(OpenApiModel):
    batch_session: ApiRateLimitValuesOverride = field(metadata={"json_key": "batchSession"})
    invoice_download: ApiRateLimitValuesOverride = field(metadata={"json_key": "invoiceDownload"})
    invoice_export: ApiRateLimitValuesOverride = field(metadata={"json_key": "invoiceExport"})
    invoice_export_status: ApiRateLimitValuesOverride = field(metadata={"json_key": "invoiceExportStatus"})
    invoice_metadata: ApiRateLimitValuesOverride = field(metadata={"json_key": "invoiceMetadata"})
    invoice_send: ApiRateLimitValuesOverride = field(metadata={"json_key": "invoiceSend"})
    invoice_status: ApiRateLimitValuesOverride = field(metadata={"json_key": "invoiceStatus"})
    online_session: ApiRateLimitValuesOverride = field(metadata={"json_key": "onlineSession"})
    other: ApiRateLimitValuesOverride
    session_invoice_list: ApiRateLimitValuesOverride = field(metadata={"json_key": "sessionInvoiceList"})
    session_list: ApiRateLimitValuesOverride = field(metadata={"json_key": "sessionList"})
    session_misc: ApiRateLimitValuesOverride = field(metadata={"json_key": "sessionMisc"})

@dataclass(frozen=True)
class AttachmentPermissionGrantRequest(OpenApiModel):
    nip: Nip

@dataclass(frozen=True)
class AttachmentPermissionRevokeRequest(OpenApiModel):
    nip: Nip
    expected_end_date: Optional[str] = field(default=None, metadata={"json_key": "expectedEndDate"})

@dataclass(frozen=True)
class AuthenticationChallengeResponse(OpenApiModel):
    challenge: Challenge
    client_ip: str = field(metadata={"json_key": "clientIp"})
    timestamp: str
    timestamp_ms: int = field(metadata={"json_key": "timestampMs"})

@dataclass(frozen=True)
class AuthenticationContextIdentifier(OpenApiModel):
    type: AuthenticationContextIdentifierType
    value: str

@dataclass(frozen=True)
class AuthenticationInitResponse(OpenApiModel):
    authentication_token: TokenInfo = field(metadata={"json_key": "authenticationToken"})
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})

@dataclass(frozen=True)
class AuthenticationListItem(OpenApiModel):
    authentication_method: AuthenticationMethod = field(metadata={"json_key": "authenticationMethod"})
    authentication_method_info: AuthenticationMethodInfo = field(metadata={"json_key": "authenticationMethodInfo"})
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})
    start_date: str = field(metadata={"json_key": "startDate"})
    status: StatusInfo
    is_current: Optional[bool] = field(default=None, metadata={"json_key": "isCurrent"})
    is_token_redeemed: Optional[bool] = field(default=None, metadata={"json_key": "isTokenRedeemed"})
    last_token_refresh_date: Optional[str] = field(default=None, metadata={"json_key": "lastTokenRefreshDate"})
    refresh_token_valid_until: Optional[str] = field(default=None, metadata={"json_key": "refreshTokenValidUntil"})

@dataclass(frozen=True)
class AuthenticationListResponse(OpenApiModel):
    items: list[AuthenticationListItem]
    continuation_token: Optional[str] = field(default=None, metadata={"json_key": "continuationToken"})

@dataclass(frozen=True)
class AuthenticationMethodInfo(OpenApiModel):
    category: AuthenticationMethodCategory
    code: str
    display_name: str = field(metadata={"json_key": "displayName"})

@dataclass(frozen=True)
class AuthenticationOperationStatusResponse(OpenApiModel):
    authentication_method: AuthenticationMethod = field(metadata={"json_key": "authenticationMethod"})
    authentication_method_info: AuthenticationMethodInfo = field(metadata={"json_key": "authenticationMethodInfo"})
    start_date: str = field(metadata={"json_key": "startDate"})
    status: StatusInfo
    is_token_redeemed: Optional[bool] = field(default=None, metadata={"json_key": "isTokenRedeemed"})
    last_token_refresh_date: Optional[str] = field(default=None, metadata={"json_key": "lastTokenRefreshDate"})
    refresh_token_valid_until: Optional[str] = field(default=None, metadata={"json_key": "refreshTokenValidUntil"})

@dataclass(frozen=True)
class AuthenticationTokenRefreshResponse(OpenApiModel):
    access_token: TokenInfo = field(metadata={"json_key": "accessToken"})

@dataclass(frozen=True)
class AuthenticationTokensResponse(OpenApiModel):
    access_token: TokenInfo = field(metadata={"json_key": "accessToken"})
    refresh_token: TokenInfo = field(metadata={"json_key": "refreshToken"})

@dataclass(frozen=True)
class AuthorizationPolicy(OpenApiModel):
    allowed_ips: Optional[AllowedIps] = field(default=None, metadata={"json_key": "allowedIps"})

@dataclass(frozen=True)
class BadRequestProblemDetails(OpenApiModel):
    detail: str
    errors: list[ApiError]
    instance: str
    status: int
    timestamp: str
    title: str
    trace_id: str = field(metadata={"json_key": "traceId"})

@dataclass(frozen=True)
class BatchFileInfo(OpenApiModel):
    file_hash: Sha256HashBase64 = field(metadata={"json_key": "fileHash"})
    file_parts: list[BatchFilePartInfo] = field(metadata={"json_key": "fileParts"})
    file_size: int = field(metadata={"json_key": "fileSize"})

@dataclass(frozen=True)
class BatchFilePartInfo(OpenApiModel):
    file_hash: Sha256HashBase64 = field(metadata={"json_key": "fileHash"})
    file_size: int = field(metadata={"json_key": "fileSize"})
    ordinal_number: int = field(metadata={"json_key": "ordinalNumber"})

@dataclass(frozen=True)
class BatchSessionContextLimitsOverride(OpenApiModel):
    max_invoice_size_in_mb: int = field(metadata={"json_key": "maxInvoiceSizeInMB"})
    max_invoice_with_attachment_size_in_mb: int = field(metadata={"json_key": "maxInvoiceWithAttachmentSizeInMB"})
    max_invoices: int = field(metadata={"json_key": "maxInvoices"})

@dataclass(frozen=True)
class BatchSessionEffectiveContextLimits(OpenApiModel):
    max_invoice_size_in_mb: int = field(metadata={"json_key": "maxInvoiceSizeInMB"})
    max_invoice_with_attachment_size_in_mb: int = field(metadata={"json_key": "maxInvoiceWithAttachmentSizeInMB"})
    max_invoices: int = field(metadata={"json_key": "maxInvoices"})

@dataclass(frozen=True)
class BlockContextAuthenticationRequest(OpenApiModel):
    context_identifier: Optional[TestDataAuthenticationContextIdentifier] = field(default=None, metadata={"json_key": "contextIdentifier"})

@dataclass(frozen=True)
class CertificateEffectiveSubjectLimits(OpenApiModel):
    max_certificates: Optional[int] = field(default=None, metadata={"json_key": "maxCertificates"})

@dataclass(frozen=True)
class CertificateEnrollmentDataResponse(OpenApiModel):
    common_name: str = field(metadata={"json_key": "commonName"})
    country_name: str = field(metadata={"json_key": "countryName"})
    given_name: Optional[str] = field(default=None, metadata={"json_key": "givenName"})
    organization_identifier: Optional[str] = field(default=None, metadata={"json_key": "organizationIdentifier"})
    organization_name: Optional[str] = field(default=None, metadata={"json_key": "organizationName"})
    serial_number: Optional[str] = field(default=None, metadata={"json_key": "serialNumber"})
    surname: Optional[str] = None
    unique_identifier: Optional[str] = field(default=None, metadata={"json_key": "uniqueIdentifier"})

@dataclass(frozen=True)
class CertificateEnrollmentStatusResponse(OpenApiModel):
    request_date: str = field(metadata={"json_key": "requestDate"})
    status: StatusInfo
    certificate_serial_number: Optional[str] = field(default=None, metadata={"json_key": "certificateSerialNumber"})

@dataclass(frozen=True)
class CertificateLimit(OpenApiModel):
    limit: int
    remaining: int

@dataclass(frozen=True)
class CertificateLimitsResponse(OpenApiModel):
    can_request: bool = field(metadata={"json_key": "canRequest"})
    certificate: CertificateLimit
    enrollment: CertificateLimit

@dataclass(frozen=True)
class CertificateListItem(OpenApiModel):
    certificate_serial_number: str = field(metadata={"json_key": "certificateSerialNumber"})
    common_name: str = field(metadata={"json_key": "commonName"})
    name: str
    request_date: str = field(metadata={"json_key": "requestDate"})
    status: CertificateListItemStatus
    subject_identifier: CertificateSubjectIdentifier = field(metadata={"json_key": "subjectIdentifier"})
    type: KsefCertificateType
    valid_from: str = field(metadata={"json_key": "validFrom"})
    valid_to: str = field(metadata={"json_key": "validTo"})
    last_use_date: Optional[str] = field(default=None, metadata={"json_key": "lastUseDate"})

@dataclass(frozen=True)
class CertificateSubjectIdentifier(OpenApiModel):
    type: CertificateSubjectIdentifierType
    value: str

@dataclass(frozen=True)
class CertificateSubjectLimitsOverride(OpenApiModel):
    max_certificates: Optional[int] = field(default=None, metadata={"json_key": "maxCertificates"})

@dataclass(frozen=True)
class CheckAttachmentPermissionStatusResponse(OpenApiModel):
    is_attachment_allowed: Optional[bool] = field(default=None, metadata={"json_key": "isAttachmentAllowed"})
    revoked_date: Optional[str] = field(default=None, metadata={"json_key": "revokedDate"})

@dataclass(frozen=True)
class EffectiveApiRateLimitValues(OpenApiModel):
    per_hour: int = field(metadata={"json_key": "perHour"})
    per_minute: int = field(metadata={"json_key": "perMinute"})
    per_second: int = field(metadata={"json_key": "perSecond"})

@dataclass(frozen=True)
class EffectiveApiRateLimits(OpenApiModel):
    batch_session: EffectiveApiRateLimitValues = field(metadata={"json_key": "batchSession"})
    invoice_download: EffectiveApiRateLimitValues = field(metadata={"json_key": "invoiceDownload"})
    invoice_export: EffectiveApiRateLimitValues = field(metadata={"json_key": "invoiceExport"})
    invoice_export_status: EffectiveApiRateLimitValues = field(metadata={"json_key": "invoiceExportStatus"})
    invoice_metadata: EffectiveApiRateLimitValues = field(metadata={"json_key": "invoiceMetadata"})
    invoice_send: EffectiveApiRateLimitValues = field(metadata={"json_key": "invoiceSend"})
    invoice_status: EffectiveApiRateLimitValues = field(metadata={"json_key": "invoiceStatus"})
    online_session: EffectiveApiRateLimitValues = field(metadata={"json_key": "onlineSession"})
    other: EffectiveApiRateLimitValues
    session_invoice_list: EffectiveApiRateLimitValues = field(metadata={"json_key": "sessionInvoiceList"})
    session_list: EffectiveApiRateLimitValues = field(metadata={"json_key": "sessionList"})
    session_misc: EffectiveApiRateLimitValues = field(metadata={"json_key": "sessionMisc"})

@dataclass(frozen=True)
class EffectiveContextLimits(OpenApiModel):
    batch_session: BatchSessionEffectiveContextLimits = field(metadata={"json_key": "batchSession"})
    online_session: OnlineSessionEffectiveContextLimits = field(metadata={"json_key": "onlineSession"})

@dataclass(frozen=True)
class EffectiveSubjectLimits(OpenApiModel):
    certificate: Optional[CertificateEffectiveSubjectLimits] = None
    enrollment: Optional[EnrollmentEffectiveSubjectLimits] = None

@dataclass(frozen=True)
class EncryptionInfo(OpenApiModel):
    encrypted_symmetric_key: str = field(metadata={"json_key": "encryptedSymmetricKey"})
    initialization_vector: str = field(metadata={"json_key": "initializationVector"})

@dataclass(frozen=True)
class EnrollCertificateRequest(OpenApiModel):
    certificate_name: str = field(metadata={"json_key": "certificateName"})
    certificate_type: KsefCertificateType = field(metadata={"json_key": "certificateType"})
    csr: str
    valid_from: Optional[str] = field(default=None, metadata={"json_key": "validFrom"})

@dataclass(frozen=True)
class EnrollCertificateResponse(OpenApiModel):
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})
    timestamp: str

@dataclass(frozen=True)
class EnrollmentEffectiveSubjectLimits(OpenApiModel):
    max_enrollments: Optional[int] = field(default=None, metadata={"json_key": "maxEnrollments"})

@dataclass(frozen=True)
class EnrollmentSubjectLimitsOverride(OpenApiModel):
    max_enrollments: Optional[int] = field(default=None, metadata={"json_key": "maxEnrollments"})

@dataclass(frozen=True)
class EntityAuthorizationGrant(OpenApiModel):
    authorization_scope: InvoicePermissionType = field(metadata={"json_key": "authorizationScope"})
    authorized_entity_identifier: EntityAuthorizationsAuthorizedEntityIdentifier = field(metadata={"json_key": "authorizedEntityIdentifier"})
    authorizing_entity_identifier: EntityAuthorizationsAuthorizingEntityIdentifier = field(metadata={"json_key": "authorizingEntityIdentifier"})
    description: str
    id: PermissionId
    start_date: str = field(metadata={"json_key": "startDate"})
    author_identifier: Optional[EntityAuthorizationsAuthorIdentifier] = field(default=None, metadata={"json_key": "authorIdentifier"})
    subject_entity_details: Optional[PermissionsSubjectEntityByIdentifierDetails] = field(default=None, metadata={"json_key": "subjectEntityDetails"})

@dataclass(frozen=True)
class EntityAuthorizationPermissionsGrantRequest(OpenApiModel):
    description: str
    permission: EntityAuthorizationPermissionType
    subject_details: EntityDetails = field(metadata={"json_key": "subjectDetails"})
    subject_identifier: EntityAuthorizationPermissionsSubjectIdentifier = field(metadata={"json_key": "subjectIdentifier"})

@dataclass(frozen=True)
class EntityAuthorizationPermissionsQueryRequest(OpenApiModel):
    query_type: QueryType = field(metadata={"json_key": "queryType"})
    authorized_identifier: Optional[EntityAuthorizationsAuthorizedEntityIdentifier] = field(default=None, metadata={"json_key": "authorizedIdentifier"})
    authorizing_identifier: Optional[EntityAuthorizationsAuthorizingEntityIdentifier] = field(default=None, metadata={"json_key": "authorizingIdentifier"})
    permission_types: Optional[list[InvoicePermissionType]] = field(default=None, metadata={"json_key": "permissionTypes"})

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
    full_name: str = field(metadata={"json_key": "fullName"})

@dataclass(frozen=True)
class EntityDetails(OpenApiModel):
    full_name: str = field(metadata={"json_key": "fullName"})

@dataclass(frozen=True)
class EntityPermission(OpenApiModel):
    type: EntityPermissionType
    can_delegate: Optional[bool] = field(default=None, metadata={"json_key": "canDelegate"})

@dataclass(frozen=True)
class EntityPermissionItem(OpenApiModel):
    can_delegate: bool = field(metadata={"json_key": "canDelegate"})
    context_identifier: EntityPermissionsContextIdentifier = field(metadata={"json_key": "contextIdentifier"})
    description: str
    id: PermissionId
    permission_scope: EntityPermissionItemScope = field(metadata={"json_key": "permissionScope"})
    start_date: str = field(metadata={"json_key": "startDate"})

@dataclass(frozen=True)
class EntityPermissionsContextIdentifier(OpenApiModel):
    type: EntityPermissionsContextIdentifierType
    value: str

@dataclass(frozen=True)
class EntityPermissionsGrantRequest(OpenApiModel):
    description: str
    permissions: list[EntityPermission]
    subject_details: EntityDetails = field(metadata={"json_key": "subjectDetails"})
    subject_identifier: EntityPermissionsSubjectIdentifier = field(metadata={"json_key": "subjectIdentifier"})

@dataclass(frozen=True)
class EntityPermissionsQueryRequest(OpenApiModel):
    context_identifier: Optional[EntityPermissionsContextIdentifier] = field(default=None, metadata={"json_key": "contextIdentifier"})

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
    start_date: str = field(metadata={"json_key": "startDate"})
    parent_entity_identifier: Optional[EntityRolesParentEntityIdentifier] = field(default=None, metadata={"json_key": "parentEntityIdentifier"})

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
    context_identifier: EuEntityAdministrationPermissionsContextIdentifier = field(metadata={"json_key": "contextIdentifier"})
    description: str
    eu_entity_details: EuEntityDetails = field(metadata={"json_key": "euEntityDetails"})
    eu_entity_name: str = field(metadata={"json_key": "euEntityName"})
    subject_details: EuEntityPermissionSubjectDetails = field(metadata={"json_key": "subjectDetails"})
    subject_identifier: EuEntityAdministrationPermissionsSubjectIdentifier = field(metadata={"json_key": "subjectIdentifier"})

@dataclass(frozen=True)
class EuEntityAdministrationPermissionsSubjectIdentifier(OpenApiModel):
    type: EuEntityAdministrationPermissionsSubjectIdentifierType
    value: str

@dataclass(frozen=True)
class EuEntityDetails(OpenApiModel):
    address: str
    full_name: str = field(metadata={"json_key": "fullName"})

@dataclass(frozen=True)
class EuEntityPermission(OpenApiModel):
    author_identifier: EuEntityPermissionsAuthorIdentifier = field(metadata={"json_key": "authorIdentifier"})
    authorized_fingerprint_identifier: str = field(metadata={"json_key": "authorizedFingerprintIdentifier"})
    description: str
    eu_entity_name: str = field(metadata={"json_key": "euEntityName"})
    id: PermissionId
    permission_scope: EuEntityPermissionsQueryPermissionType = field(metadata={"json_key": "permissionScope"})
    start_date: str = field(metadata={"json_key": "startDate"})
    vat_ue_identifier: str = field(metadata={"json_key": "vatUeIdentifier"})
    eu_entity_details: Optional[PermissionsEuEntityDetails] = field(default=None, metadata={"json_key": "euEntityDetails"})
    subject_entity_details: Optional[PermissionsSubjectEntityByFingerprintDetails] = field(default=None, metadata={"json_key": "subjectEntityDetails"})
    subject_person_details: Optional[PermissionsSubjectPersonByFingerprintDetails] = field(default=None, metadata={"json_key": "subjectPersonDetails"})

@dataclass(frozen=True)
class EuEntityPermissionSubjectDetails(OpenApiModel):
    subject_details_type: EuEntityPermissionSubjectDetailsType = field(metadata={"json_key": "subjectDetailsType"})
    entity_by_fp: Optional[EntityByFingerprintDetails] = field(default=None, metadata={"json_key": "entityByFp"})
    person_by_fp_no_id: Optional[PersonByFingerprintWithoutIdentifierDetails] = field(default=None, metadata={"json_key": "personByFpNoId"})
    person_by_fp_with_id: Optional[PersonByFingerprintWithIdentifierDetails] = field(default=None, metadata={"json_key": "personByFpWithId"})

@dataclass(frozen=True)
class EuEntityPermissionsAuthorIdentifier(OpenApiModel):
    type: EuEntityPermissionsAuthorIdentifierType
    value: str

@dataclass(frozen=True)
class EuEntityPermissionsGrantRequest(OpenApiModel):
    description: str
    permissions: list[EuEntityPermissionType]
    subject_details: EuEntityPermissionSubjectDetails = field(metadata={"json_key": "subjectDetails"})
    subject_identifier: EuEntityPermissionsSubjectIdentifier = field(metadata={"json_key": "subjectIdentifier"})

@dataclass(frozen=True)
class EuEntityPermissionsQueryRequest(OpenApiModel):
    authorized_fingerprint_identifier: Optional[str] = field(default=None, metadata={"json_key": "authorizedFingerprintIdentifier"})
    permission_types: Optional[list[EuEntityPermissionsQueryPermissionType]] = field(default=None, metadata={"json_key": "permissionTypes"})
    vat_ue_identifier: Optional[str] = field(default=None, metadata={"json_key": "vatUeIdentifier"})

@dataclass(frozen=True)
class EuEntityPermissionsSubjectIdentifier(OpenApiModel):
    type: EuEntityPermissionsSubjectIdentifierType
    value: str

@dataclass(frozen=True)
class ExceptionDetails(OpenApiModel):
    details: Optional[list[str]] = None
    exception_code: Optional[int] = field(default=None, metadata={"json_key": "exceptionCode"})
    exception_description: Optional[str] = field(default=None, metadata={"json_key": "exceptionDescription"})

@dataclass(frozen=True)
class ExceptionInfo(OpenApiModel):
    exception_detail_list: Optional[list[ExceptionDetails]] = field(default=None, metadata={"json_key": "exceptionDetailList"})
    reference_number: Optional[ReferenceNumber] = field(default=None, metadata={"json_key": "referenceNumber"})
    service_code: Optional[str] = field(default=None, metadata={"json_key": "serviceCode"})
    service_ctx: Optional[str] = field(default=None, metadata={"json_key": "serviceCtx"})
    service_name: Optional[str] = field(default=None, metadata={"json_key": "serviceName"})
    timestamp: Optional[str] = None

@dataclass(frozen=True)
class ExceptionResponse(OpenApiModel):
    exception: Optional[ExceptionInfo] = None

@dataclass(frozen=True)
class ExportInvoicesResponse(OpenApiModel):
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})

@dataclass(frozen=True)
class ForbiddenProblemDetails(OpenApiModel):
    detail: str
    reason_code: str = field(metadata={"json_key": "reasonCode"})
    status: int
    timestamp: str
    title: str
    instance: Optional[str] = None
    security: Optional[dict[str, Optional[Any]]] = None
    trace_id: Optional[str] = field(default=None, metadata={"json_key": "traceId"})

@dataclass(frozen=True)
class FormCode(OpenApiModel):
    schema_version: str = field(metadata={"json_key": "schemaVersion"})
    system_code: str = field(metadata={"json_key": "systemCode"})
    value: str

@dataclass(frozen=True)
class GenerateTokenRequest(OpenApiModel):
    description: str
    permissions: list[TokenPermissionType]

@dataclass(frozen=True)
class GenerateTokenResponse(OpenApiModel):
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})
    token: str

@dataclass(frozen=True)
class GoneProblemDetails(OpenApiModel):
    detail: str
    instance: str
    status: int
    timestamp: str
    title: str
    trace_id: str = field(metadata={"json_key": "traceId"})

@dataclass(frozen=True)
class IdDocument(OpenApiModel):
    country: str
    number: str
    type: str

@dataclass(frozen=True)
class IndirectPermissionsGrantRequest(OpenApiModel):
    description: str
    permissions: list[IndirectPermissionType]
    subject_details: PersonPermissionSubjectDetails = field(metadata={"json_key": "subjectDetails"})
    subject_identifier: IndirectPermissionsSubjectIdentifier = field(metadata={"json_key": "subjectIdentifier"})
    target_identifier: Optional[IndirectPermissionsTargetIdentifier] = field(default=None, metadata={"json_key": "targetIdentifier"})

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
    context_identifier: AuthenticationContextIdentifier = field(metadata={"json_key": "contextIdentifier"})
    encrypted_token: str = field(metadata={"json_key": "encryptedToken"})
    authorization_policy: Optional[AuthorizationPolicy] = field(default=None, metadata={"json_key": "authorizationPolicy"})

@dataclass(frozen=True)
class InvoiceExportRequest(OpenApiModel):
    encryption: EncryptionInfo
    filters: InvoiceQueryFilters
    only_metadata: Optional[bool] = field(default=None, metadata={"json_key": "onlyMetadata"})

@dataclass(frozen=True)
class InvoiceExportStatusResponse(OpenApiModel):
    status: StatusInfo
    completed_date: Optional[str] = field(default=None, metadata={"json_key": "completedDate"})
    package: Optional[InvoicePackage] = None
    package_expiration_date: Optional[str] = field(default=None, metadata={"json_key": "packageExpirationDate"})

@dataclass(frozen=True)
class InvoiceMetadata(OpenApiModel):
    acquisition_date: str = field(metadata={"json_key": "acquisitionDate"})
    buyer: InvoiceMetadataBuyer
    currency: str
    form_code: FormCode = field(metadata={"json_key": "formCode"})
    gross_amount: float = field(metadata={"json_key": "grossAmount"})
    has_attachment: bool = field(metadata={"json_key": "hasAttachment"})
    invoice_hash: Sha256HashBase64 = field(metadata={"json_key": "invoiceHash"})
    invoice_number: str = field(metadata={"json_key": "invoiceNumber"})
    invoice_type: InvoiceType = field(metadata={"json_key": "invoiceType"})
    invoicing_date: str = field(metadata={"json_key": "invoicingDate"})
    invoicing_mode: InvoicingMode = field(metadata={"json_key": "invoicingMode"})
    is_self_invoicing: bool = field(metadata={"json_key": "isSelfInvoicing"})
    issue_date: str = field(metadata={"json_key": "issueDate"})
    ksef_number: KsefNumber = field(metadata={"json_key": "ksefNumber"})
    net_amount: float = field(metadata={"json_key": "netAmount"})
    permanent_storage_date: str = field(metadata={"json_key": "permanentStorageDate"})
    seller: InvoiceMetadataSeller
    vat_amount: float = field(metadata={"json_key": "vatAmount"})
    authorized_subject: Optional[InvoiceMetadataAuthorizedSubject] = field(default=None, metadata={"json_key": "authorizedSubject"})
    hash_of_corrected_invoice: Optional[Sha256HashBase64] = field(default=None, metadata={"json_key": "hashOfCorrectedInvoice"})
    third_subjects: Optional[list[InvoiceMetadataThirdSubject]] = field(default=None, metadata={"json_key": "thirdSubjects"})

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
    invoice_count: int = field(metadata={"json_key": "invoiceCount"})
    is_truncated: bool = field(metadata={"json_key": "isTruncated"})
    parts: list[InvoicePackagePart]
    size: int
    last_invoicing_date: Optional[str] = field(default=None, metadata={"json_key": "lastInvoicingDate"})
    last_issue_date: Optional[str] = field(default=None, metadata={"json_key": "lastIssueDate"})
    last_permanent_storage_date: Optional[str] = field(default=None, metadata={"json_key": "lastPermanentStorageDate"})
    permanent_storage_hwm_date: Optional[str] = field(default=None, metadata={"json_key": "permanentStorageHwmDate"})

@dataclass(frozen=True)
class InvoicePackagePart(OpenApiModel):
    encrypted_part_hash: Sha256HashBase64 = field(metadata={"json_key": "encryptedPartHash"})
    encrypted_part_size: int = field(metadata={"json_key": "encryptedPartSize"})
    expiration_date: str = field(metadata={"json_key": "expirationDate"})
    method: str
    ordinal_number: int = field(metadata={"json_key": "ordinalNumber"})
    part_hash: Sha256HashBase64 = field(metadata={"json_key": "partHash"})
    part_name: str = field(metadata={"json_key": "partName"})
    part_size: int = field(metadata={"json_key": "partSize"})
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
    date_type: InvoiceQueryDateType = field(metadata={"json_key": "dateType"})
    from_: str = field(metadata={"json_key": "from"})
    restrict_to_permanent_storage_hwm_date: Optional[bool] = field(default=None, metadata={"json_key": "restrictToPermanentStorageHwmDate"})
    to: Optional[str] = None

@dataclass(frozen=True)
class InvoiceQueryFilters(OpenApiModel):
    date_range: InvoiceQueryDateRange = field(metadata={"json_key": "dateRange"})
    subject_type: InvoiceQuerySubjectType = field(metadata={"json_key": "subjectType"})
    amount: Optional[InvoiceQueryAmount] = None
    buyer_identifier: Optional[InvoiceQueryBuyerIdentifier] = field(default=None, metadata={"json_key": "buyerIdentifier"})
    currency_codes: Optional[list[CurrencyCode]] = field(default=None, metadata={"json_key": "currencyCodes"})
    form_type: Optional[InvoiceQueryFormType] = field(default=None, metadata={"json_key": "formType"})
    has_attachment: Optional[bool] = field(default=None, metadata={"json_key": "hasAttachment"})
    invoice_number: Optional[str] = field(default=None, metadata={"json_key": "invoiceNumber"})
    invoice_types: Optional[list[InvoiceType]] = field(default=None, metadata={"json_key": "invoiceTypes"})
    invoicing_mode: Optional[InvoicingMode] = field(default=None, metadata={"json_key": "invoicingMode"})
    is_self_invoicing: Optional[bool] = field(default=None, metadata={"json_key": "isSelfInvoicing"})
    ksef_number: Optional[KsefNumber] = field(default=None, metadata={"json_key": "ksefNumber"})
    seller_nip: Optional[Nip] = field(default=None, metadata={"json_key": "sellerNip"})

@dataclass(frozen=True)
class InvoiceStatusInfo(OpenApiModel):
    code: int
    description: str
    details: Optional[list[str]] = None
    extensions: Optional[dict[str, Optional[str]]] = None

@dataclass(frozen=True)
class OnlineSessionContextLimitsOverride(OpenApiModel):
    max_invoice_size_in_mb: int = field(metadata={"json_key": "maxInvoiceSizeInMB"})
    max_invoice_with_attachment_size_in_mb: int = field(metadata={"json_key": "maxInvoiceWithAttachmentSizeInMB"})
    max_invoices: int = field(metadata={"json_key": "maxInvoices"})

@dataclass(frozen=True)
class OnlineSessionEffectiveContextLimits(OpenApiModel):
    max_invoice_size_in_mb: int = field(metadata={"json_key": "maxInvoiceSizeInMB"})
    max_invoice_with_attachment_size_in_mb: int = field(metadata={"json_key": "maxInvoiceWithAttachmentSizeInMB"})
    max_invoices: int = field(metadata={"json_key": "maxInvoices"})

@dataclass(frozen=True)
class OpenBatchSessionRequest(OpenApiModel):
    batch_file: BatchFileInfo = field(metadata={"json_key": "batchFile"})
    encryption: EncryptionInfo
    form_code: FormCode = field(metadata={"json_key": "formCode"})
    offline_mode: Optional[bool] = field(default=None, metadata={"json_key": "offlineMode"})

@dataclass(frozen=True)
class OpenBatchSessionResponse(OpenApiModel):
    part_upload_requests: list[PartUploadRequest] = field(metadata={"json_key": "partUploadRequests"})
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})

@dataclass(frozen=True)
class OpenOnlineSessionRequest(OpenApiModel):
    encryption: EncryptionInfo
    form_code: FormCode = field(metadata={"json_key": "formCode"})

@dataclass(frozen=True)
class OpenOnlineSessionResponse(OpenApiModel):
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})
    valid_until: str = field(metadata={"json_key": "validUntil"})

@dataclass(frozen=True)
class PartUploadRequest(OpenApiModel):
    headers: dict[str, Optional[str]]
    method: str
    ordinal_number: int = field(metadata={"json_key": "ordinalNumber"})
    url: str

@dataclass(frozen=True)
class PeppolProvider(OpenApiModel):
    date_created: str = field(metadata={"json_key": "dateCreated"})
    id: PeppolId
    name: str

@dataclass(frozen=True)
class PermissionsEuEntityDetails(OpenApiModel):
    address: str
    full_name: str = field(metadata={"json_key": "fullName"})

@dataclass(frozen=True)
class PermissionsOperationResponse(OpenApiModel):
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})

@dataclass(frozen=True)
class PermissionsOperationStatusResponse(OpenApiModel):
    status: StatusInfo

@dataclass(frozen=True)
class PermissionsSubjectEntityByFingerprintDetails(OpenApiModel):
    full_name: str = field(metadata={"json_key": "fullName"})
    subject_details_type: EntitySubjectByFingerprintDetailsType = field(metadata={"json_key": "subjectDetailsType"})
    address: Optional[str] = None

@dataclass(frozen=True)
class PermissionsSubjectEntityByIdentifierDetails(OpenApiModel):
    full_name: str = field(metadata={"json_key": "fullName"})
    subject_details_type: EntitySubjectByIdentifierDetailsType = field(metadata={"json_key": "subjectDetailsType"})

@dataclass(frozen=True)
class PermissionsSubjectEntityDetails(OpenApiModel):
    full_name: str = field(metadata={"json_key": "fullName"})
    subject_details_type: EntitySubjectDetailsType = field(metadata={"json_key": "subjectDetailsType"})
    address: Optional[str] = None

@dataclass(frozen=True)
class PermissionsSubjectPersonByFingerprintDetails(OpenApiModel):
    first_name: str = field(metadata={"json_key": "firstName"})
    last_name: str = field(metadata={"json_key": "lastName"})
    subject_details_type: PersonSubjectByFingerprintDetailsType = field(metadata={"json_key": "subjectDetailsType"})
    birth_date: Optional[str] = field(default=None, metadata={"json_key": "birthDate"})
    id_document: Optional[IdDocument] = field(default=None, metadata={"json_key": "idDocument"})
    person_identifier: Optional[PersonIdentifier] = field(default=None, metadata={"json_key": "personIdentifier"})

@dataclass(frozen=True)
class PermissionsSubjectPersonDetails(OpenApiModel):
    first_name: str = field(metadata={"json_key": "firstName"})
    last_name: str = field(metadata={"json_key": "lastName"})
    subject_details_type: PersonSubjectDetailsType = field(metadata={"json_key": "subjectDetailsType"})
    birth_date: Optional[str] = field(default=None, metadata={"json_key": "birthDate"})
    id_document: Optional[IdDocument] = field(default=None, metadata={"json_key": "idDocument"})
    person_identifier: Optional[PersonIdentifier] = field(default=None, metadata={"json_key": "personIdentifier"})

@dataclass(frozen=True)
class PersonByFingerprintWithIdentifierDetails(OpenApiModel):
    first_name: str = field(metadata={"json_key": "firstName"})
    identifier: PersonIdentifier
    last_name: str = field(metadata={"json_key": "lastName"})

@dataclass(frozen=True)
class PersonByFingerprintWithoutIdentifierDetails(OpenApiModel):
    birth_date: str = field(metadata={"json_key": "birthDate"})
    first_name: str = field(metadata={"json_key": "firstName"})
    id_document: IdDocument = field(metadata={"json_key": "idDocument"})
    last_name: str = field(metadata={"json_key": "lastName"})

@dataclass(frozen=True)
class PersonCreateRequest(OpenApiModel):
    description: str
    is_bailiff: bool = field(metadata={"json_key": "isBailiff"})
    nip: Nip
    pesel: Pesel
    created_date: Optional[str] = field(default=None, metadata={"json_key": "createdDate"})
    is_deceased: Optional[bool] = field(default=None, metadata={"json_key": "isDeceased"})

@dataclass(frozen=True)
class PersonDetails(OpenApiModel):
    first_name: str = field(metadata={"json_key": "firstName"})
    last_name: str = field(metadata={"json_key": "lastName"})

@dataclass(frozen=True)
class PersonIdentifier(OpenApiModel):
    type: PersonIdentifierType
    value: str

@dataclass(frozen=True)
class PersonPermission(OpenApiModel):
    author_identifier: PersonPermissionsAuthorIdentifier = field(metadata={"json_key": "authorIdentifier"})
    authorized_identifier: PersonPermissionsAuthorizedIdentifier = field(metadata={"json_key": "authorizedIdentifier"})
    can_delegate: bool = field(metadata={"json_key": "canDelegate"})
    description: str
    id: PermissionId
    permission_scope: PersonPermissionScope = field(metadata={"json_key": "permissionScope"})
    permission_state: PermissionState = field(metadata={"json_key": "permissionState"})
    start_date: str = field(metadata={"json_key": "startDate"})
    context_identifier: Optional[PersonPermissionsContextIdentifier] = field(default=None, metadata={"json_key": "contextIdentifier"})
    subject_entity_details: Optional[PermissionsSubjectEntityDetails] = field(default=None, metadata={"json_key": "subjectEntityDetails"})
    subject_person_details: Optional[PermissionsSubjectPersonDetails] = field(default=None, metadata={"json_key": "subjectPersonDetails"})
    target_identifier: Optional[PersonPermissionsTargetIdentifier] = field(default=None, metadata={"json_key": "targetIdentifier"})

@dataclass(frozen=True)
class PersonPermissionSubjectDetails(OpenApiModel):
    subject_details_type: PersonPermissionSubjectDetailsType = field(metadata={"json_key": "subjectDetailsType"})
    person_by_fp_no_id: Optional[PersonByFingerprintWithoutIdentifierDetails] = field(default=None, metadata={"json_key": "personByFpNoId"})
    person_by_fp_with_id: Optional[PersonByFingerprintWithIdentifierDetails] = field(default=None, metadata={"json_key": "personByFpWithId"})
    person_by_id: Optional[PersonDetails] = field(default=None, metadata={"json_key": "personById"})

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
    subject_details: PersonPermissionSubjectDetails = field(metadata={"json_key": "subjectDetails"})
    subject_identifier: PersonPermissionsSubjectIdentifier = field(metadata={"json_key": "subjectIdentifier"})

@dataclass(frozen=True)
class PersonPermissionsQueryRequest(OpenApiModel):
    query_type: PersonPermissionsQueryType = field(metadata={"json_key": "queryType"})
    author_identifier: Optional[PersonPermissionsAuthorIdentifier] = field(default=None, metadata={"json_key": "authorIdentifier"})
    authorized_identifier: Optional[PersonPermissionsAuthorizedIdentifier] = field(default=None, metadata={"json_key": "authorizedIdentifier"})
    context_identifier: Optional[PersonPermissionsContextIdentifier] = field(default=None, metadata={"json_key": "contextIdentifier"})
    permission_state: Optional[PermissionState] = field(default=None, metadata={"json_key": "permissionState"})
    permission_types: Optional[list[PersonPermissionType]] = field(default=None, metadata={"json_key": "permissionTypes"})
    target_identifier: Optional[PersonPermissionsTargetIdentifier] = field(default=None, metadata={"json_key": "targetIdentifier"})

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
    can_delegate: bool = field(metadata={"json_key": "canDelegate"})
    description: str
    id: PermissionId
    permission_scope: PersonalPermissionScope = field(metadata={"json_key": "permissionScope"})
    permission_state: PermissionState = field(metadata={"json_key": "permissionState"})
    start_date: str = field(metadata={"json_key": "startDate"})
    authorized_identifier: Optional[PersonalPermissionsAuthorizedIdentifier] = field(default=None, metadata={"json_key": "authorizedIdentifier"})
    context_identifier: Optional[PersonalPermissionsContextIdentifier] = field(default=None, metadata={"json_key": "contextIdentifier"})
    subject_entity_details: Optional[PermissionsSubjectEntityDetails] = field(default=None, metadata={"json_key": "subjectEntityDetails"})
    subject_person_details: Optional[PermissionsSubjectPersonDetails] = field(default=None, metadata={"json_key": "subjectPersonDetails"})
    target_identifier: Optional[PersonalPermissionsTargetIdentifier] = field(default=None, metadata={"json_key": "targetIdentifier"})

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
    context_identifier: Optional[PersonalPermissionsContextIdentifier] = field(default=None, metadata={"json_key": "contextIdentifier"})
    permission_state: Optional[PermissionState] = field(default=None, metadata={"json_key": "permissionState"})
    permission_types: Optional[list[PersonalPermissionType]] = field(default=None, metadata={"json_key": "permissionTypes"})
    target_identifier: Optional[PersonalPermissionsTargetIdentifier] = field(default=None, metadata={"json_key": "targetIdentifier"})

@dataclass(frozen=True)
class PersonalPermissionsTargetIdentifier(OpenApiModel):
    type: PersonalPermissionsTargetIdentifierType
    value: Optional[str] = None

@dataclass(frozen=True)
class PublicKeyCertificate(OpenApiModel):
    certificate: str
    usage: list[PublicKeyCertificateUsage]
    valid_from: str = field(metadata={"json_key": "validFrom"})
    valid_to: str = field(metadata={"json_key": "validTo"})

@dataclass(frozen=True)
class QueryCertificatesRequest(OpenApiModel):
    certificate_serial_number: Optional[str] = field(default=None, metadata={"json_key": "certificateSerialNumber"})
    expires_after: Optional[str] = field(default=None, metadata={"json_key": "expiresAfter"})
    name: Optional[str] = None
    status: Optional[CertificateListItemStatus] = None
    type: Optional[KsefCertificateType] = None

@dataclass(frozen=True)
class QueryCertificatesResponse(OpenApiModel):
    certificates: list[CertificateListItem]
    has_more: bool = field(metadata={"json_key": "hasMore"})

@dataclass(frozen=True)
class QueryEntityAuthorizationPermissionsResponse(OpenApiModel):
    authorization_grants: list[EntityAuthorizationGrant] = field(metadata={"json_key": "authorizationGrants"})
    has_more: bool = field(metadata={"json_key": "hasMore"})

@dataclass(frozen=True)
class QueryEntityPermissionsResponse(OpenApiModel):
    has_more: bool = field(metadata={"json_key": "hasMore"})
    permissions: list[EntityPermissionItem]

@dataclass(frozen=True)
class QueryEntityRolesResponse(OpenApiModel):
    has_more: bool = field(metadata={"json_key": "hasMore"})
    roles: list[EntityRole]

@dataclass(frozen=True)
class QueryEuEntityPermissionsResponse(OpenApiModel):
    has_more: bool = field(metadata={"json_key": "hasMore"})
    permissions: list[EuEntityPermission]

@dataclass(frozen=True)
class QueryInvoicesMetadataResponse(OpenApiModel):
    has_more: bool = field(metadata={"json_key": "hasMore"})
    invoices: list[InvoiceMetadata]
    is_truncated: bool = field(metadata={"json_key": "isTruncated"})
    permanent_storage_hwm_date: Optional[str] = field(default=None, metadata={"json_key": "permanentStorageHwmDate"})

@dataclass(frozen=True)
class QueryPeppolProvidersResponse(OpenApiModel):
    has_more: bool = field(metadata={"json_key": "hasMore"})
    peppol_providers: list[PeppolProvider] = field(metadata={"json_key": "peppolProviders"})

@dataclass(frozen=True)
class QueryPersonPermissionsResponse(OpenApiModel):
    has_more: bool = field(metadata={"json_key": "hasMore"})
    permissions: list[PersonPermission]

@dataclass(frozen=True)
class QueryPersonalPermissionsResponse(OpenApiModel):
    has_more: bool = field(metadata={"json_key": "hasMore"})
    permissions: list[PersonalPermission]

@dataclass(frozen=True)
class QuerySubordinateEntityRolesResponse(OpenApiModel):
    has_more: bool = field(metadata={"json_key": "hasMore"})
    roles: list[SubordinateEntityRole]

@dataclass(frozen=True)
class QuerySubunitPermissionsResponse(OpenApiModel):
    has_more: bool = field(metadata={"json_key": "hasMore"})
    permissions: list[SubunitPermission]

@dataclass(frozen=True)
class QueryTokensResponse(OpenApiModel):
    tokens: list[QueryTokensResponseItem]
    continuation_token: Optional[str] = field(default=None, metadata={"json_key": "continuationToken"})

@dataclass(frozen=True)
class QueryTokensResponseItem(OpenApiModel):
    author_identifier: TokenAuthorIdentifierTypeIdentifier = field(metadata={"json_key": "authorIdentifier"})
    context_identifier: TokenContextIdentifierTypeIdentifier = field(metadata={"json_key": "contextIdentifier"})
    date_created: str = field(metadata={"json_key": "dateCreated"})
    description: str
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})
    requested_permissions: list[TokenPermissionType] = field(metadata={"json_key": "requestedPermissions"})
    status: AuthenticationTokenStatus
    last_use_date: Optional[str] = field(default=None, metadata={"json_key": "lastUseDate"})
    status_details: Optional[list[str]] = field(default=None, metadata={"json_key": "statusDetails"})

@dataclass(frozen=True)
class RetrieveCertificatesListItem(OpenApiModel):
    certificate: str
    certificate_name: str = field(metadata={"json_key": "certificateName"})
    certificate_serial_number: str = field(metadata={"json_key": "certificateSerialNumber"})
    certificate_type: KsefCertificateType = field(metadata={"json_key": "certificateType"})

@dataclass(frozen=True)
class RetrieveCertificatesRequest(OpenApiModel):
    certificate_serial_numbers: list[str] = field(metadata={"json_key": "certificateSerialNumbers"})

@dataclass(frozen=True)
class RetrieveCertificatesResponse(OpenApiModel):
    certificates: list[RetrieveCertificatesListItem]

@dataclass(frozen=True)
class RevokeCertificateRequest(OpenApiModel):
    revocation_reason: Optional[CertificateRevocationReason] = field(default=None, metadata={"json_key": "revocationReason"})

@dataclass(frozen=True)
class SendInvoiceRequest(OpenApiModel):
    encrypted_invoice_content: str = field(metadata={"json_key": "encryptedInvoiceContent"})
    encrypted_invoice_hash: Sha256HashBase64 = field(metadata={"json_key": "encryptedInvoiceHash"})
    encrypted_invoice_size: int = field(metadata={"json_key": "encryptedInvoiceSize"})
    invoice_hash: Sha256HashBase64 = field(metadata={"json_key": "invoiceHash"})
    invoice_size: int = field(metadata={"json_key": "invoiceSize"})
    hash_of_corrected_invoice: Optional[Sha256HashBase64] = field(default=None, metadata={"json_key": "hashOfCorrectedInvoice"})
    offline_mode: Optional[bool] = field(default=None, metadata={"json_key": "offlineMode"})

@dataclass(frozen=True)
class SendInvoiceResponse(OpenApiModel):
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})

@dataclass(frozen=True)
class SessionInvoiceStatusResponse(OpenApiModel):
    invoice_hash: Sha256HashBase64 = field(metadata={"json_key": "invoiceHash"})
    invoicing_date: str = field(metadata={"json_key": "invoicingDate"})
    ordinal_number: int = field(metadata={"json_key": "ordinalNumber"})
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})
    status: InvoiceStatusInfo
    acquisition_date: Optional[str] = field(default=None, metadata={"json_key": "acquisitionDate"})
    invoice_file_name: Optional[str] = field(default=None, metadata={"json_key": "invoiceFileName"})
    invoice_number: Optional[str] = field(default=None, metadata={"json_key": "invoiceNumber"})
    invoicing_mode: Optional[InvoicingMode] = field(default=None, metadata={"json_key": "invoicingMode"})
    ksef_number: Optional[KsefNumber] = field(default=None, metadata={"json_key": "ksefNumber"})
    permanent_storage_date: Optional[str] = field(default=None, metadata={"json_key": "permanentStorageDate"})
    upo_download_url: Optional[str] = field(default=None, metadata={"json_key": "upoDownloadUrl"})
    upo_download_url_expiration_date: Optional[str] = field(default=None, metadata={"json_key": "upoDownloadUrlExpirationDate"})

@dataclass(frozen=True)
class SessionInvoicesResponse(OpenApiModel):
    invoices: list[SessionInvoiceStatusResponse]
    continuation_token: Optional[str] = field(default=None, metadata={"json_key": "continuationToken"})

@dataclass(frozen=True)
class SessionStatusResponse(OpenApiModel):
    date_created: str = field(metadata={"json_key": "dateCreated"})
    date_updated: str = field(metadata={"json_key": "dateUpdated"})
    status: StatusInfo
    failed_invoice_count: Optional[int] = field(default=None, metadata={"json_key": "failedInvoiceCount"})
    invoice_count: Optional[int] = field(default=None, metadata={"json_key": "invoiceCount"})
    successful_invoice_count: Optional[int] = field(default=None, metadata={"json_key": "successfulInvoiceCount"})
    upo: Optional[UpoResponse] = None
    valid_until: Optional[str] = field(default=None, metadata={"json_key": "validUntil"})

@dataclass(frozen=True)
class SessionsQueryResponse(OpenApiModel):
    sessions: list[SessionsQueryResponseItem]
    continuation_token: Optional[str] = field(default=None, metadata={"json_key": "continuationToken"})

@dataclass(frozen=True)
class SessionsQueryResponseItem(OpenApiModel):
    date_created: str = field(metadata={"json_key": "dateCreated"})
    date_updated: str = field(metadata={"json_key": "dateUpdated"})
    failed_invoice_count: int = field(metadata={"json_key": "failedInvoiceCount"})
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})
    status: StatusInfo
    successful_invoice_count: int = field(metadata={"json_key": "successfulInvoiceCount"})
    total_invoice_count: int = field(metadata={"json_key": "totalInvoiceCount"})
    valid_until: Optional[str] = field(default=None, metadata={"json_key": "validUntil"})

@dataclass(frozen=True)
class SetRateLimitsRequest(OpenApiModel):
    rate_limits: ApiRateLimitsOverride = field(metadata={"json_key": "rateLimits"})

@dataclass(frozen=True)
class SetSessionLimitsRequest(OpenApiModel):
    batch_session: BatchSessionContextLimitsOverride = field(metadata={"json_key": "batchSession"})
    online_session: OnlineSessionContextLimitsOverride = field(metadata={"json_key": "onlineSession"})

@dataclass(frozen=True)
class SetSubjectLimitsRequest(OpenApiModel):
    certificate: Optional[CertificateSubjectLimitsOverride] = None
    enrollment: Optional[EnrollmentSubjectLimitsOverride] = None
    subject_identifier_type: Optional[SubjectIdentifierType] = field(default=None, metadata={"json_key": "subjectIdentifierType"})

@dataclass(frozen=True)
class StatusInfo(OpenApiModel):
    code: int
    description: str
    details: Optional[list[str]] = None

@dataclass(frozen=True)
class SubjectCreateRequest(OpenApiModel):
    description: str
    subject_nip: Nip = field(metadata={"json_key": "subjectNip"})
    subject_type: SubjectType = field(metadata={"json_key": "subjectType"})
    created_date: Optional[str] = field(default=None, metadata={"json_key": "createdDate"})
    subunits: Optional[list[Subunit]] = None

@dataclass(frozen=True)
class SubjectRemoveRequest(OpenApiModel):
    subject_nip: Nip = field(metadata={"json_key": "subjectNip"})

@dataclass(frozen=True)
class SubordinateEntityRole(OpenApiModel):
    description: str
    role: SubordinateEntityRoleType
    start_date: str = field(metadata={"json_key": "startDate"})
    subordinate_entity_identifier: SubordinateRoleSubordinateEntityIdentifier = field(metadata={"json_key": "subordinateEntityIdentifier"})

@dataclass(frozen=True)
class SubordinateEntityRolesQueryRequest(OpenApiModel):
    subordinate_entity_identifier: Optional[EntityPermissionsSubordinateEntityIdentifier] = field(default=None, metadata={"json_key": "subordinateEntityIdentifier"})

@dataclass(frozen=True)
class SubordinateRoleSubordinateEntityIdentifier(OpenApiModel):
    type: SubordinateRoleSubordinateEntityIdentifierType
    value: str

@dataclass(frozen=True)
class Subunit(OpenApiModel):
    description: str
    subject_nip: Nip = field(metadata={"json_key": "subjectNip"})

@dataclass(frozen=True)
class SubunitPermission(OpenApiModel):
    author_identifier: SubunitPermissionsAuthorIdentifier = field(metadata={"json_key": "authorIdentifier"})
    authorized_identifier: SubunitPermissionsAuthorizedIdentifier = field(metadata={"json_key": "authorizedIdentifier"})
    description: str
    id: PermissionId
    permission_scope: SubunitPermissionScope = field(metadata={"json_key": "permissionScope"})
    start_date: str = field(metadata={"json_key": "startDate"})
    subunit_identifier: SubunitPermissionsSubunitIdentifier = field(metadata={"json_key": "subunitIdentifier"})
    subject_person_details: Optional[PermissionsSubjectPersonDetails] = field(default=None, metadata={"json_key": "subjectPersonDetails"})
    subunit_name: Optional[str] = field(default=None, metadata={"json_key": "subunitName"})

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
    context_identifier: SubunitPermissionsContextIdentifier = field(metadata={"json_key": "contextIdentifier"})
    description: str
    subject_details: PersonPermissionSubjectDetails = field(metadata={"json_key": "subjectDetails"})
    subject_identifier: SubunitPermissionsSubjectIdentifier = field(metadata={"json_key": "subjectIdentifier"})
    subunit_name: Optional[str] = field(default=None, metadata={"json_key": "subunitName"})

@dataclass(frozen=True)
class SubunitPermissionsQueryRequest(OpenApiModel):
    subunit_identifier: Optional[SubunitPermissionsSubunitIdentifier] = field(default=None, metadata={"json_key": "subunitIdentifier"})

@dataclass(frozen=True)
class SubunitPermissionsSubjectIdentifier(OpenApiModel):
    type: SubunitPermissionsSubjectIdentifierType
    value: str

@dataclass(frozen=True)
class SubunitPermissionsSubunitIdentifier(OpenApiModel):
    type: SubunitPermissionsSubunitIdentifierType
    value: str

@dataclass(frozen=True)
class TestDataAuthenticationContextIdentifier(OpenApiModel):
    type: TestDataAuthenticationContextIdentifierType
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
    permission_type: TestDataPermissionType = field(metadata={"json_key": "permissionType"})

@dataclass(frozen=True)
class TestDataPermissionsGrantRequest(OpenApiModel):
    authorized_identifier: TestDataAuthorizedIdentifier = field(metadata={"json_key": "authorizedIdentifier"})
    context_identifier: TestDataContextIdentifier = field(metadata={"json_key": "contextIdentifier"})
    permissions: list[TestDataPermission]

@dataclass(frozen=True)
class TestDataPermissionsRevokeRequest(OpenApiModel):
    authorized_identifier: TestDataAuthorizedIdentifier = field(metadata={"json_key": "authorizedIdentifier"})
    context_identifier: TestDataContextIdentifier = field(metadata={"json_key": "contextIdentifier"})

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
    valid_until: str = field(metadata={"json_key": "validUntil"})

@dataclass(frozen=True)
class TokenStatusResponse(OpenApiModel):
    author_identifier: TokenAuthorIdentifierTypeIdentifier = field(metadata={"json_key": "authorIdentifier"})
    context_identifier: TokenContextIdentifierTypeIdentifier = field(metadata={"json_key": "contextIdentifier"})
    date_created: str = field(metadata={"json_key": "dateCreated"})
    description: str
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})
    requested_permissions: list[TokenPermissionType] = field(metadata={"json_key": "requestedPermissions"})
    status: AuthenticationTokenStatus
    last_use_date: Optional[str] = field(default=None, metadata={"json_key": "lastUseDate"})
    status_details: Optional[list[str]] = field(default=None, metadata={"json_key": "statusDetails"})

@dataclass(frozen=True)
class TooManyRequestsProblemDetails(OpenApiModel):
    detail: str
    instance: str
    status: int
    timestamp: str
    title: str
    trace_id: str = field(metadata={"json_key": "traceId"})

@dataclass(frozen=True)
class TooManyRequestsResponse(OpenApiModel):
    status: dict[str, Any]

@dataclass(frozen=True)
class UnauthorizedProblemDetails(OpenApiModel):
    detail: str
    status: int
    timestamp: str
    title: str
    instance: Optional[str] = None
    trace_id: Optional[str] = field(default=None, metadata={"json_key": "traceId"})

@dataclass(frozen=True)
class UnblockContextAuthenticationRequest(OpenApiModel):
    context_identifier: Optional[TestDataAuthenticationContextIdentifier] = field(default=None, metadata={"json_key": "contextIdentifier"})

@dataclass(frozen=True)
class UpoPageResponse(OpenApiModel):
    download_url: str = field(metadata={"json_key": "downloadUrl"})
    download_url_expiration_date: str = field(metadata={"json_key": "downloadUrlExpirationDate"})
    reference_number: ReferenceNumber = field(metadata={"json_key": "referenceNumber"})

@dataclass(frozen=True)
class UpoResponse(OpenApiModel):
    pages: list[UpoPageResponse]
