from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING, Any

from typing_extensions import Self

from .models import (
    FA3InvoiceKind,
    FA3ValidationIssue,
    decimal_from_value,
    money,
    parse_vat_rate,
)

if TYPE_CHECKING:
    from .builders import (
        AdvanceCorrectionInvoiceBuilder,
        AdvanceInvoiceBuilder,
        BasicInvoiceBuilder,
        CorrectionInvoiceBuilder,
        SettlementCorrectionInvoiceBuilder,
        SettlementInvoiceBuilder,
        SimplifiedInvoiceBuilder,
    )
    from .sections import (
        AdditionalDescription,
        AdvancePayment,
        CorrectedAdvanceState,
        ExciseRefund,
        Footer,
        LineIdentifiers,
        NewTransportMeans,
        Order,
        PaymentDue,
        TransactionTerms,
    )


class PartyIdentifierKind(str, Enum):
    NIP = "NIP"
    EU_VAT = "EU_VAT"
    FOREIGN = "FOREIGN"
    INTERNAL = "INTERNAL"
    NONE = "NONE"


@dataclass(frozen=True)
class FA3ValidationResult:
    errors: tuple[FA3ValidationIssue, ...] = ()
    warnings: tuple[FA3ValidationIssue, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.errors

    def raise_for_errors(self) -> None:
        if self.errors:
            raise ValueError("; ".join(issue.message for issue in self.errors))


@dataclass(frozen=True)
class PartyIdentifier:
    kind: PartyIdentifierKind
    value: str | None = None
    country_code: str | None = None

    @classmethod
    def polish_nip(cls, value: str) -> PartyIdentifier:
        return cls(PartyIdentifierKind.NIP, value=value)

    @classmethod
    def eu_vat(cls, country_code: str, value: str) -> PartyIdentifier:
        return cls(PartyIdentifierKind.EU_VAT, value=value, country_code=country_code.upper())

    @classmethod
    def foreign(cls, value: str, *, country_code: str | None = None) -> PartyIdentifier:
        return cls(
            PartyIdentifierKind.FOREIGN,
            value=value,
            country_code=country_code.upper() if country_code else None,
        )

    @classmethod
    def internal(cls, value: str) -> PartyIdentifier:
        return cls(PartyIdentifierKind.INTERNAL, value=value)

    @classmethod
    def none(cls) -> PartyIdentifier:
        return cls(PartyIdentifierKind.NONE)

    def validate(self, path: str) -> list[FA3ValidationIssue]:
        if self.kind is PartyIdentifierKind.NONE:
            return []
        if not str(self.value or "").strip():
            return [
                FA3ValidationIssue(
                    f"{path}: identyfikator jest wymagany.",
                    column=path,
                )
            ]
        if self.kind is PartyIdentifierKind.EU_VAT and not str(self.country_code or "").strip():
            return [
                FA3ValidationIssue(
                    f"{path}: kod kraju UE jest wymagany dla numeru VAT UE.",
                    column=path,
                )
            ]
        return []


@dataclass(frozen=True)
class Address:
    line1: str
    country_code: str = "PL"
    line2: str | None = None
    gln: str | None = None

    @classmethod
    def polish(cls, line1: str, line2: str | None = None, *, gln: str | None = None) -> Address:
        return cls(line1=line1, country_code="PL", line2=line2, gln=gln)

    @classmethod
    def foreign(
        cls,
        country_code: str,
        line1: str,
        line2: str | None = None,
        *,
        gln: str | None = None,
    ) -> Address:
        return cls(line1=line1, country_code=country_code.upper(), line2=line2, gln=gln)

    def validate(self, path: str) -> list[FA3ValidationIssue]:
        issues: list[FA3ValidationIssue] = []
        if not self.country_code.strip():
            issues.append(FA3ValidationIssue(f"{path}: kod kraju jest wymagany.", column=path))
        if not self.line1.strip():
            issues.append(FA3ValidationIssue(f"{path}: adres jest wymagany.", column=path))
        return issues


@dataclass(frozen=True)
class Contact:
    email: str | None = None
    phone: str | None = None

    def validate(self, path: str) -> list[FA3ValidationIssue]:
        if not (self.email or self.phone):
            return [FA3ValidationIssue(f"{path}: podaj email albo telefon.", column=path)]
        return []


class ThirdPartyRole(str, Enum):
    ORIGINAL_ENTITY = "1"
    ADDITIONAL_BUYER = "2"
    RECIPIENT = "3"
    PAYER = "4"
    JST_SUBUNIT = "8"
    VAT_GROUP_MEMBER = "10"
    OTHER = "11"


class AuthorizedPartyRole(str, Enum):
    REPRESENTATIVE = "1"
    BAILIFF = "2"
    ENFORCEMENT_AUTHORITY = "3"


@dataclass(frozen=True)
class InvoiceParty:
    name: str
    identifier: PartyIdentifier
    address: Address | None = None
    taxpayer_prefix: str | None = None
    taxpayer_status: str | None = None
    correspondence_address: Address | None = None
    contacts: tuple[Contact, ...] = ()
    eori: str | None = None
    customer_number: str | None = None
    buyer_id: str | None = None
    role: ThirdPartyRole | str | None = None
    authorized_role: AuthorizedPartyRole | str | None = None
    share: Decimal | None = None
    is_jst_subunit: bool = False
    is_vat_group_member: bool = False
    other_role_description: str | None = None

    @classmethod
    def polish_company(
        cls,
        *,
        nip: str,
        name: str,
        address: Address | str | None = None,
        contacts: tuple[Contact, ...] = (),
    ) -> InvoiceParty:
        return cls(
            name=name,
            identifier=PartyIdentifier.polish_nip(nip),
            address=_coerce_address(address),
            contacts=contacts,
        )

    @classmethod
    def eu_company(
        cls,
        *,
        vat_id: str,
        country_code: str,
        name: str,
        address: Address | str | None = None,
        contacts: tuple[Contact, ...] = (),
    ) -> InvoiceParty:
        return cls(
            name=name,
            identifier=PartyIdentifier.eu_vat(country_code, vat_id),
            address=_coerce_address(address, country_code=country_code),
            contacts=contacts,
        )

    @classmethod
    def foreign_company(
        cls,
        *,
        identifier: str,
        country_code: str,
        name: str,
        address: Address | str | None = None,
    ) -> InvoiceParty:
        return cls(
            name=name,
            identifier=PartyIdentifier.foreign(identifier, country_code=country_code),
            address=_coerce_address(address, country_code=country_code),
        )

    @classmethod
    def without_tax_id(
        cls,
        *,
        name: str,
        address: Address | str | None = None,
        country_code: str = "PL",
    ) -> InvoiceParty:
        return cls(
            name=name,
            identifier=PartyIdentifier.none(),
            address=_coerce_address(address, country_code=country_code),
        )

    def validate(self, path: str, *, address_required: bool = False) -> list[FA3ValidationIssue]:
        issues: list[FA3ValidationIssue] = []
        if not self.name.strip():
            issues.append(FA3ValidationIssue(f"{path}: nazwa jest wymagana.", column=path))
        issues.extend(self.identifier.validate(f"{path}.identifier"))
        if address_required and self.address is None:
            issues.append(FA3ValidationIssue(f"{path}: adres jest wymagany.", column=path))
        if self.address is not None:
            issues.extend(self.address.validate(f"{path}.address"))
        if self.correspondence_address is not None:
            issues.extend(self.correspondence_address.validate(f"{path}.correspondence_address"))
        for index, contact in enumerate(self.contacts, start=1):
            issues.extend(contact.validate(f"{path}.contacts[{index}]"))
        if self.share is not None and not (Decimal("0") < self.share <= Decimal("100")):
            issues.append(FA3ValidationIssue(f"{path}: udział musi być z zakresu 0-100."))
        return issues


Party = InvoiceParty


class DiscountKind(str, Enum):
    AMOUNT = "amount"
    PERCENT = "percent"


@dataclass(frozen=True)
class Discount:
    kind: DiscountKind
    value: Decimal
    reason: str | None = None

    @classmethod
    def amount(cls, value: Decimal | str | int | float, reason: str | None = None) -> Discount:
        return cls(DiscountKind.AMOUNT, decimal_from_value(value, field_name="discount"), reason)

    @classmethod
    def percent(cls, value: Decimal | str | int | float, reason: str | None = None) -> Discount:
        return cls(DiscountKind.PERCENT, decimal_from_value(value, field_name="discount"), reason)

    def amount_for(self, base: Decimal) -> Decimal:
        if self.kind is DiscountKind.PERCENT:
            return money(base * self.value / Decimal("100"))
        return money(self.value)

    def validate(self, path: str) -> list[FA3ValidationIssue]:
        if self.value < 0:
            return [FA3ValidationIssue(f"{path}: rabat nie może być ujemny.")]
        if self.kind is DiscountKind.PERCENT and self.value > Decimal("100"):
            return [FA3ValidationIssue(f"{path}: rabat procentowy nie może przekraczać 100%.")]
        return []


class TaxCategoryKind(str, Enum):
    STANDARD_23 = "standard_23"
    STANDARD_22 = "standard_22"
    REDUCED_8 = "reduced_8"
    REDUCED_7 = "reduced_7"
    REDUCED_5 = "reduced_5"
    TAXI_FLAT_RATE = "taxi_flat_rate"
    XII = "xii"
    ZERO_DOMESTIC = "zero_domestic"
    ZERO_WDT = "zero_wdt"
    ZERO_EXPORT = "zero_export"
    EXEMPT = "exempt"
    OUTSIDE_COUNTRY = "outside_country"
    SERVICE_ARTICLE_100 = "service_article_100"
    REVERSE_CHARGE = "reverse_charge"
    MARGIN = "margin"


_TAX_SUMMARY_FIELDS: dict[TaxCategoryKind, tuple[str, str | None, str | None]] = {
    TaxCategoryKind.STANDARD_23: ("P_13_1", "P_14_1", "P_14_1W"),
    TaxCategoryKind.STANDARD_22: ("P_13_1", "P_14_1", "P_14_1W"),
    TaxCategoryKind.REDUCED_8: ("P_13_2", "P_14_2", "P_14_2W"),
    TaxCategoryKind.REDUCED_7: ("P_13_2", "P_14_2", "P_14_2W"),
    TaxCategoryKind.REDUCED_5: ("P_13_3", "P_14_3", "P_14_3W"),
    TaxCategoryKind.TAXI_FLAT_RATE: ("P_13_4", "P_14_4", "P_14_4W"),
    TaxCategoryKind.XII: ("P_13_5", "P_14_5", None),
    TaxCategoryKind.ZERO_DOMESTIC: ("P_13_6_1", None, None),
    TaxCategoryKind.ZERO_WDT: ("P_13_6_2", None, None),
    TaxCategoryKind.ZERO_EXPORT: ("P_13_6_3", None, None),
    TaxCategoryKind.EXEMPT: ("P_13_7", None, None),
    TaxCategoryKind.OUTSIDE_COUNTRY: ("P_13_8", None, None),
    TaxCategoryKind.SERVICE_ARTICLE_100: ("P_13_9", None, None),
    TaxCategoryKind.REVERSE_CHARGE: ("P_13_10", None, None),
    TaxCategoryKind.MARGIN: ("P_13_11", None, None),
}


@dataclass(frozen=True)
class TaxCategory:
    kind: TaxCategoryKind
    vat_rate: Decimal | None
    xml_rate: str | None
    exemption_basis: str | None = None
    exemption_basis_type: str = "law"
    xii_rate: Decimal | None = None

    @classmethod
    def standard_23(cls) -> TaxCategory:
        return cls(TaxCategoryKind.STANDARD_23, Decimal("23"), "23")

    @classmethod
    def standard_22(cls) -> TaxCategory:
        return cls(TaxCategoryKind.STANDARD_22, Decimal("22"), "22")

    @classmethod
    def reduced_8(cls) -> TaxCategory:
        return cls(TaxCategoryKind.REDUCED_8, Decimal("8"), "8")

    @classmethod
    def reduced_7(cls) -> TaxCategory:
        return cls(TaxCategoryKind.REDUCED_7, Decimal("7"), "7")

    @classmethod
    def reduced_5(cls) -> TaxCategory:
        return cls(TaxCategoryKind.REDUCED_5, Decimal("5"), "5")

    @classmethod
    def zero_domestic(cls) -> TaxCategory:
        return cls(TaxCategoryKind.ZERO_DOMESTIC, Decimal("0"), "0 KR")

    @classmethod
    def zero_wdt(cls) -> TaxCategory:
        return cls(TaxCategoryKind.ZERO_WDT, Decimal("0"), "0 WDT")

    @classmethod
    def zero_export(cls) -> TaxCategory:
        return cls(TaxCategoryKind.ZERO_EXPORT, Decimal("0"), "0 EX")

    @classmethod
    def exempt(cls, basis: str, *, basis_type: str = "law") -> TaxCategory:
        return cls(TaxCategoryKind.EXEMPT, None, "zw", basis, basis_type)

    @classmethod
    def outside_country(cls) -> TaxCategory:
        return cls(TaxCategoryKind.OUTSIDE_COUNTRY, None, "np I")

    @classmethod
    def outside_country_2(cls) -> TaxCategory:
        return cls(TaxCategoryKind.OUTSIDE_COUNTRY, None, "np II")

    @classmethod
    def reverse_charge(cls) -> TaxCategory:
        return cls(TaxCategoryKind.REVERSE_CHARGE, None, "oo")

    @classmethod
    def margin(cls) -> TaxCategory:
        return cls(TaxCategoryKind.MARGIN, None, "np I")

    @classmethod
    def xii(cls, rate: Decimal | str | int | float) -> TaxCategory:
        parsed = decimal_from_value(rate, field_name="xii_rate")
        return cls(TaxCategoryKind.XII, parsed, None, xii_rate=parsed)

    @classmethod
    def from_vat_rate(cls, value: Decimal | str | int | float | None) -> TaxCategory:
        parsed = parse_vat_rate(value)
        if parsed is None:
            return cls.exempt("zwolnienie")
        if parsed == Decimal("23"):
            return cls.standard_23()
        if parsed == Decimal("22"):
            return cls.standard_22()
        if parsed == Decimal("8"):
            return cls.reduced_8()
        if parsed == Decimal("7"):
            return cls.reduced_7()
        if parsed == Decimal("5"):
            return cls.reduced_5()
        if parsed == Decimal("0"):
            return cls.zero_domestic()
        return cls(TaxCategoryKind.STANDARD_23, parsed, format(parsed.normalize(), "f"))

    @classmethod
    def from_rate_code(cls, value: Any) -> TaxCategory:
        code = str(getattr(value, "value", value))
        mapping = {
            "23": cls.standard_23,
            "22": cls.standard_22,
            "8": cls.reduced_8,
            "7": cls.reduced_7,
            "5": cls.reduced_5,
            "0 KR": cls.zero_domestic,
            "0 WDT": cls.zero_wdt,
            "0 EX": cls.zero_export,
            "zw": lambda: cls.exempt("zwolnienie"),
            "oo": cls.reverse_charge,
            "np I": cls.outside_country,
            "np II": cls.outside_country_2,
        }
        if code in {"4", "3"}:
            parsed = Decimal(code)
            return cls(TaxCategoryKind.TAXI_FLAT_RATE, parsed, code)
        try:
            return mapping[code]()
        except KeyError as exc:
            raise ValueError(f"Nieobsługiwana stawka VAT FA(3): {code}") from exc

    @property
    def summary_fields(self) -> tuple[str, str | None, str | None]:
        return _TAX_SUMMARY_FIELDS[self.kind]


VatClass = TaxCategory


@dataclass(frozen=True)
class Annotation:
    key: str
    value: Any = True

    @classmethod
    def cash_method(cls, required: bool = True) -> Annotation:
        return cls("cash_method", required)

    @classmethod
    def self_billing(cls, required: bool = True) -> Annotation:
        return cls("self_billing", required)

    @classmethod
    def reverse_charge(cls, required: bool = True) -> Annotation:
        return cls("reverse_charge", required)

    @classmethod
    def split_payment(cls, required: bool = True) -> Annotation:
        return cls("split_payment", required)

    @classmethod
    def simplified_triangular(cls, required: bool = True) -> Annotation:
        return cls("simplified_triangular", required)

    @classmethod
    def margin(cls, procedure: str = "used_goods") -> Annotation:
        return cls("margin_procedure", procedure)


@dataclass(frozen=True)
class AnnotationSet:
    cash_method: bool = False
    self_billing: bool = False
    reverse_charge: bool = False
    split_payment: bool = False
    simplified_triangular: bool = False
    exemption_basis: str | None = None
    exemption_basis_type: str = "law"
    new_transport: bool = False
    new_transport_intra_eu: bool = False
    new_transport_means: tuple[NewTransportMeans, ...] = ()
    margin_procedure: str | None = None

    @classmethod
    def default(cls) -> AnnotationSet:
        return cls()

    @classmethod
    def from_annotations(cls, annotations: tuple[Annotation, ...]) -> AnnotationSet:
        values: dict[str, Any] = {}
        for annotation in annotations:
            values[annotation.key] = annotation.value
        return cls(**values)

    def merge_tax_categories(self, categories: list[TaxCategory]) -> AnnotationSet:
        exemption = next((category for category in categories if category.exemption_basis), None)
        margin = any(category.kind is TaxCategoryKind.MARGIN for category in categories)
        reverse = any(category.kind is TaxCategoryKind.REVERSE_CHARGE for category in categories)
        return AnnotationSet(
            cash_method=self.cash_method,
            self_billing=self.self_billing,
            reverse_charge=self.reverse_charge or reverse,
            split_payment=self.split_payment,
            simplified_triangular=self.simplified_triangular,
            exemption_basis=(
                self.exemption_basis or (exemption.exemption_basis if exemption else None)
            ),
            exemption_basis_type=(
                self.exemption_basis_type
                if self.exemption_basis
                else (exemption.exemption_basis_type if exemption else self.exemption_basis_type)
            ),
            new_transport=self.new_transport,
            new_transport_intra_eu=self.new_transport_intra_eu,
            new_transport_means=self.new_transport_means,
            margin_procedure=self.margin_procedure or ("used_goods" if margin else None),
        )


@dataclass(frozen=True)
class InvoiceLine:
    description: str
    quantity: Decimal
    unit_net_price: Decimal
    tax: TaxCategory
    unit: str = "szt"
    discount: Discount | None = None
    unique_id: str | None = None
    service_date: date | None = None
    period_from: date | None = None
    period_to: date | None = None
    additional_description: dict[str, str] = field(default_factory=dict)
    identifiers: LineIdentifiers | None = None
    unit_gross_price: Decimal | None = None
    net_amount: Decimal | None = None
    gross_amount: Decimal | None = None
    vat_amount: Decimal | None = None
    excise_amount: Decimal | None = None
    gtu: str | None = None
    procedure: str | None = None
    currency_rate: Decimal | None = None
    annex_15: bool = False
    before_correction: bool = False

    @classmethod
    def create(
        cls,
        description: str,
        *,
        quantity: Decimal | str | int | float,
        unit_net_price: Decimal | str | int | float,
        tax: TaxCategory | None = None,
        unit: str = "szt",
        discount: Discount | None = None,
        **kwargs: Any,
    ) -> InvoiceLine:
        return cls(
            description=description,
            quantity=decimal_from_value(quantity, field_name="quantity"),
            unit_net_price=decimal_from_value(unit_net_price, field_name="unit_net_price"),
            tax=tax or TaxCategory.standard_23(),
            unit=unit,
            discount=discount,
            **kwargs,
        )

    @classmethod
    def goods(cls, description: str, **kwargs: Any) -> InvoiceLine:
        return cls.create(description, **_coerce_line_kwargs(kwargs))

    @classmethod
    def service(cls, description: str, **kwargs: Any) -> InvoiceLine:
        return cls.create(description, **_coerce_line_kwargs(kwargs))

    @classmethod
    def corrected_before(cls, description: str, **kwargs: Any) -> InvoiceLine:
        values = _coerce_line_kwargs(kwargs)
        values["before_correction"] = True
        return cls.create(description, **values)

    @classmethod
    def corrected_after(cls, description: str, **kwargs: Any) -> InvoiceLine:
        values = _coerce_line_kwargs(kwargs)
        values["before_correction"] = False
        return cls.create(description, **values)

    @property
    def base_net_amount(self) -> Decimal:
        return money(self.quantity * self.unit_net_price)

    @property
    def discount_amount(self) -> Decimal:
        if self.discount is None:
            return Decimal("0.00")
        return min(self.discount.amount_for(self.base_net_amount), self.base_net_amount)

    @property
    def computed_net_amount(self) -> Decimal:
        return money(self.base_net_amount - self.discount_amount)

    @property
    def effective_net_amount(self) -> Decimal:
        return money(self.net_amount) if self.net_amount is not None else self.computed_net_amount

    @property
    def computed_vat_amount(self) -> Decimal:
        if self.tax.vat_rate is None:
            return Decimal("0.00")
        return money(self.effective_net_amount * self.tax.vat_rate / Decimal("100"))

    @property
    def effective_vat_amount(self) -> Decimal:
        return money(self.vat_amount) if self.vat_amount is not None else self.computed_vat_amount

    @property
    def effective_gross_amount(self) -> Decimal:
        if self.gross_amount is not None:
            return money(self.gross_amount)
        return money(self.effective_net_amount + self.effective_vat_amount)

    def validate(self, path: str) -> list[FA3ValidationIssue]:
        issues: list[FA3ValidationIssue] = []
        if not self.description.strip():
            issues.append(FA3ValidationIssue(f"{path}: opis pozycji jest wymagany."))
        if self.quantity <= 0:
            issues.append(FA3ValidationIssue(f"{path}: ilość musi być większa od zera."))
        if self.unit_net_price < 0:
            issues.append(FA3ValidationIssue(f"{path}: cena netto nie może być ujemna."))
        if self.discount is not None:
            issues.extend(self.discount.validate(f"{path}.discount"))
        return issues


@dataclass(frozen=True)
class CorrectionReference:
    invoice_number: str
    issue_date: date
    ksef_number: str | None = None


@dataclass(frozen=True)
class SettlementAdjustment:
    amount: Decimal
    reason: str

    @classmethod
    def create(cls, amount: Decimal | str | int | float, reason: str) -> SettlementAdjustment:
        return cls(decimal_from_value(amount, field_name="amount"), reason)


@dataclass(frozen=True)
class Settlement:
    charges: tuple[SettlementAdjustment, ...] = ()
    deductions: tuple[SettlementAdjustment, ...] = ()
    amount_due: Decimal | None = None
    amount_to_settle: Decimal | None = None


@dataclass(frozen=True)
class BankAccount:
    number: str
    swift: str | None = None
    own_bank_account: str | None = None
    bank_name: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class PartialPayment:
    amount: Decimal
    payment_date: date
    method: str | None = None
    other_method_description: str | None = None

    @classmethod
    def create(
        cls,
        amount: Decimal | str | int | float,
        payment_date: date,
        *,
        method: str | None = None,
        other_method_description: str | None = None,
    ) -> PartialPayment:
        return cls(
            decimal_from_value(amount, field_name="partial_payment"),
            payment_date,
            method,
            other_method_description,
        )


@dataclass(frozen=True)
class PaymentTerms:
    due_dates: tuple[date, ...] = ()
    due_terms: tuple[PaymentDue, ...] = ()
    method: str | None = None
    other_method_description: str | None = None
    paid_date: date | None = None
    partial_payments: tuple[PartialPayment, ...] = ()
    bank_accounts: tuple[BankAccount, ...] = ()
    factor_accounts: tuple[BankAccount, ...] = ()
    cash_discount_terms: str | None = None
    cash_discount_amount: str | None = None
    payment_link: str | None = None
    ipksef: str | None = None

    @classmethod
    def transfer(
        cls,
        *,
        due_date: date | None = None,
        bank_account: BankAccount | None = None,
    ) -> PaymentTerms:
        return cls(
            due_dates=(due_date,) if due_date else (),
            method="przelew",
            bank_accounts=(bank_account,) if bank_account else (),
        )

@dataclass(frozen=True)
class AttachmentTable:
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    column_types: tuple[str, ...] = ()
    metadata: tuple[tuple[str, str], ...] = ()
    description: str | None = None
    footer: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttachmentBlock:
    header: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()
    paragraphs: tuple[str, ...] = ()
    tables: tuple[AttachmentTable, ...] = ()


@dataclass(frozen=True)
class Attachment:
    blocks: tuple[AttachmentBlock, ...]

    @classmethod
    def text(cls, header: str, *paragraphs: str) -> Attachment:
        return cls((AttachmentBlock(header=header, paragraphs=tuple(paragraphs)),))


@dataclass(frozen=True)
class RawXmlExtension:
    path: str
    xml: str


@dataclass(frozen=True)
class AdvanceInvoiceReference:
    invoice_number: str | None = None
    ksef_number: str | None = None


@dataclass(frozen=True)
class FA3Invoice:
    invoice_number: str
    issue_date: date
    seller: InvoiceParty
    buyer: InvoiceParty
    lines: tuple[InvoiceLine, ...]
    kind: FA3InvoiceKind = FA3InvoiceKind.BASIC
    currency: str = "PLN"
    issue_place: str | None = None
    sale_date: date | None = None
    period_from: date | None = None
    period_to: date | None = None
    additional_parties: tuple[InvoiceParty, ...] = ()
    authorized_party: InvoiceParty | None = None
    annotations: AnnotationSet = field(default_factory=AnnotationSet.default)
    payment_terms: PaymentTerms | None = None
    settlement_data: Settlement | None = None
    correction_reason: str | None = None
    correction_type: str | None = None
    corrected_invoices: tuple[CorrectionReference, ...] = ()
    corrected_seller: InvoiceParty | None = None
    corrected_buyers: tuple[InvoiceParty, ...] = ()
    advance_invoices: tuple[AdvanceInvoiceReference, ...] = ()
    advance_payments: tuple[AdvancePayment, ...] = ()
    corrected_advance_state: CorrectedAdvanceState | None = None
    order: Order | None = None
    transaction_terms: TransactionTerms | None = None
    warehouse_documents: tuple[str, ...] = ()
    additional_descriptions: tuple[AdditionalDescription, ...] = ()
    foreign_currency_rate: Decimal | None = None
    fp: bool = False
    tp: bool = False
    excise_refund: ExciseRefund | None = None
    footer: Footer | None = None
    attachment: Attachment | None = None
    raw_extensions: tuple[RawXmlExtension, ...] = ()
    warnings: tuple[FA3ValidationIssue, ...] = ()

    @classmethod
    def basic(cls, invoice_number: str) -> BasicInvoiceBuilder:
        from .builders import BasicInvoiceBuilder

        return BasicInvoiceBuilder(invoice_number=invoice_number)

    @classmethod
    def simplified(cls, invoice_number: str) -> SimplifiedInvoiceBuilder:
        from .builders import SimplifiedInvoiceBuilder

        return SimplifiedInvoiceBuilder(invoice_number=invoice_number)

    @classmethod
    def correction(cls, invoice_number: str) -> CorrectionInvoiceBuilder:
        from .builders import CorrectionInvoiceBuilder

        return CorrectionInvoiceBuilder(invoice_number=invoice_number)

    @classmethod
    def advance(cls, invoice_number: str) -> AdvanceInvoiceBuilder:
        from .builders import AdvanceInvoiceBuilder

        return AdvanceInvoiceBuilder(invoice_number=invoice_number)

    @classmethod
    def settlement(cls, invoice_number: str) -> SettlementInvoiceBuilder:
        from .builders import SettlementInvoiceBuilder

        return SettlementInvoiceBuilder(invoice_number=invoice_number)

    @classmethod
    def advance_correction(cls, invoice_number: str) -> AdvanceCorrectionInvoiceBuilder:
        from .builders import AdvanceCorrectionInvoiceBuilder

        return AdvanceCorrectionInvoiceBuilder(invoice_number=invoice_number)

    @classmethod
    def settlement_correction(cls, invoice_number: str) -> SettlementCorrectionInvoiceBuilder:
        from .builders import SettlementCorrectionInvoiceBuilder

        return SettlementCorrectionInvoiceBuilder(invoice_number=invoice_number)

    @property
    def total_net(self) -> Decimal:
        return money(sum((line.effective_net_amount for line in self.lines), Decimal("0.00")))

    @property
    def total_vat(self) -> Decimal:
        return money(sum((line.effective_vat_amount for line in self.lines), Decimal("0.00")))

    @property
    def total_gross(self) -> Decimal:
        return money(sum((line.effective_gross_amount for line in self.lines), Decimal("0.00")))

    def validate(self) -> FA3ValidationResult:
        errors: list[FA3ValidationIssue] = []
        warnings = list(self.warnings)
        if not self.invoice_number.strip():
            errors.append(FA3ValidationIssue("invoice.invoice_number: numer jest wymagany."))
        if self.issue_date is None:
            errors.append(FA3ValidationIssue("invoice.issue_date: data jest wymagana."))
        errors.extend(self.seller.validate("invoice.seller", address_required=True))
        errors.extend(self.buyer.validate("invoice.buyer"))
        line_optional_kinds = {FA3InvoiceKind.ADVANCE, FA3InvoiceKind.ADVANCE_CORRECTION}
        if not self.lines and self.kind not in line_optional_kinds:
            errors.append(
                FA3ValidationIssue("invoice.lines: faktura wymaga co najmniej jednej pozycji.")
            )
        for index, line in enumerate(self.lines, start=1):
            errors.extend(line.validate(f"invoice.lines[{index}]"))
        for index, party in enumerate(self.additional_parties, start=1):
            if party.role is None:
                errors.append(
                    FA3ValidationIssue(
                        f"invoice.additional_parties[{index}].role: rola jest wymagana."
                    )
                )
            errors.extend(party.validate(f"invoice.additional_parties[{index}]"))
        if self.authorized_party is not None:
            if self.authorized_party.authorized_role is None:
                errors.append(
                    FA3ValidationIssue("invoice.authorized_party.role: rola jest wymagana.")
                )
            errors.extend(
                self.authorized_party.validate(
                    "invoice.authorized_party",
                    address_required=True,
                )
            )
        correction_kinds = {
            FA3InvoiceKind.CORRECTION,
            FA3InvoiceKind.ADVANCE_CORRECTION,
            FA3InvoiceKind.SETTLEMENT_CORRECTION,
        }
        if self.kind in correction_kinds:
            if not self.correction_reason:
                errors.append(
                    FA3ValidationIssue(
                        "invoice.correction_reason: przyczyna korekty jest wymagana."
                    )
                )
            if not self.corrected_invoices:
                errors.append(
                    FA3ValidationIssue("invoice.corrected_invoices: podaj fakturę korygowaną.")
                )
        settlement_kinds = {FA3InvoiceKind.SETTLEMENT, FA3InvoiceKind.SETTLEMENT_CORRECTION}
        if self.kind in settlement_kinds and not self.advance_invoices:
            errors.append(FA3ValidationIssue("invoice.advance_invoices: podaj fakturę zaliczkową."))
        if self.buyer.is_jst_subunit and not any(
            str(getattr(party.role, "value", party.role)) == ThirdPartyRole.JST_SUBUNIT.value
            for party in self.additional_parties
        ):
            errors.append(
                FA3ValidationIssue("invoice.additional_parties: JST wymaga podmiotu Podmiot3.")
            )
        if self.buyer.is_vat_group_member and not any(
            str(getattr(party.role, "value", party.role)) == ThirdPartyRole.VAT_GROUP_MEMBER.value
            for party in self.additional_parties
        ):
            errors.append(
                FA3ValidationIssue("invoice.additional_parties: GV wymaga podmiotu Podmiot3.")
            )
        if self.raw_extensions:
            errors.append(
                FA3ValidationIssue(
                    "invoice.raw_extensions: RawXmlExtension nie jest wspierany w typed FA(3) SDK."
                )
            )
        errors.extend(self._validate_xml_shape())
        return FA3ValidationResult(tuple(errors), tuple(warnings))

    def to_xml(self, *, validate: bool = True, xsd_validate: bool = False) -> bytes:
        from .xml import invoice_to_xml

        return invoice_to_xml(self, validate=validate, xsd_validate=xsd_validate)

    def _validate_xml_shape(self) -> list[FA3ValidationIssue]:
        issues: list[FA3ValidationIssue] = []
        if self.sale_date is not None and (self.period_from is not None or self.period_to is not None):
            issues.append(
                FA3ValidationIssue(
                    "invoice.sale_date: podaj date sprzedazy albo okres faktury, nie oba."
                )
            )
        if (self.period_from is None) ^ (self.period_to is None):
            issues.append(
                FA3ValidationIssue(
                    "invoice.period: okres faktury wymaga obu dat: od i do."
                )
            )
        if (
            self.payment_terms is not None
            and self.payment_terms.paid_date is not None
            and self.payment_terms.partial_payments
        ):
            issues.append(
                FA3ValidationIssue(
                    "invoice.payment_terms: podaj date zaplaty albo platnosci czesciowe, nie oba."
                )
            )
        for index, advance_invoice in enumerate(self.advance_invoices, start=1):
            has_invoice_number = bool(str(advance_invoice.invoice_number or "").strip())
            has_ksef_number = bool(str(advance_invoice.ksef_number or "").strip())
            if not has_invoice_number and not has_ksef_number:
                issues.append(
                    FA3ValidationIssue(
                        f"invoice.advance_invoices[{index}]: podaj numer faktury zaliczkowej albo numer KSeF."
                    )
                )
            if has_invoice_number and has_ksef_number:
                issues.append(
                    FA3ValidationIssue(
                        f"invoice.advance_invoices[{index}]: podaj numer faktury zaliczkowej albo numer KSeF, nie oba."
                    )
                )
        return issues


@dataclass
class FA3InvoiceBuilderV2:
    invoice_number: str
    kind: FA3InvoiceKind
    _issue_date: date | None = None
    _seller: InvoiceParty | None = None
    _buyer: InvoiceParty | None = None
    _lines: list[InvoiceLine] = field(default_factory=list)
    _currency: str = "PLN"
    _issue_place: str | None = None
    _sale_date: date | None = None
    _period_from: date | None = None
    _period_to: date | None = None
    _additional_parties: list[InvoiceParty] = field(default_factory=list)
    _authorized_party: InvoiceParty | None = None
    _annotations: AnnotationSet = field(default_factory=AnnotationSet.default)
    _payment_terms: PaymentTerms | None = None
    _settlement: Settlement | None = None
    _correction_reason: str | None = None
    _correction_type: str | None = None
    _corrected_invoices: list[CorrectionReference] = field(default_factory=list)
    _advance_invoices: list[AdvanceInvoiceReference] = field(default_factory=list)
    _attachment: Attachment | None = None
    _raw_extensions: list[RawXmlExtension] = field(default_factory=list)

    def issued_on(self, value: date) -> Self:
        self._issue_date = value
        return self

    def currency(self, value: str) -> Self:
        self._currency = value.upper()
        return self

    def issue_place(self, value: str) -> Self:
        self._issue_place = value
        return self

    def sale_date(self, value: date) -> Self:
        self._sale_date = value
        return self

    def period(self, date_from: date, date_to: date) -> Self:
        self._period_from = date_from
        self._period_to = date_to
        return self

    def seller(self, party: InvoiceParty) -> Self:
        self._seller = party
        return self

    def buyer(self, party: InvoiceParty) -> Self:
        self._buyer = party
        return self

    def add_party(self, party: InvoiceParty, role: ThirdPartyRole | str) -> Self:
        self._additional_parties.append(_replace_party_role(party, role=role))
        return self

    def authorized_party(
        self,
        party: InvoiceParty,
        role: AuthorizedPartyRole | str,
    ) -> Self:
        self._authorized_party = _replace_party_role(party, authorized_role=role)
        return self

    def add_line(
        self,
        description: str,
        *,
        quantity: Decimal | str | int | float,
        unit_net_price: Decimal | str | int | float,
        tax: TaxCategory | None = None,
        unit: str = "szt",
        discount: Discount | None = None,
        **kwargs: Any,
    ) -> Self:
        self._lines.append(
            InvoiceLine.create(
                description,
                quantity=quantity,
                unit_net_price=unit_net_price,
                tax=tax,
                unit=unit,
                discount=discount,
                **kwargs,
            )
        )
        return self

    def annotations(self, *annotations: Annotation) -> Self:
        self._annotations = AnnotationSet.from_annotations(tuple(annotations))
        return self

    def annotation_set(self, annotations: AnnotationSet) -> Self:
        self._annotations = annotations
        return self

    def payment(self, terms: PaymentTerms) -> Self:
        self._payment_terms = terms
        return self

    def settlement_details(self, settlement: Settlement) -> Self:
        self._settlement = settlement
        return self

    def corrects(
        self,
        invoice_number: str,
        issue_date: date,
        *,
        reason: str,
        ksef_number: str | None = None,
        correction_type: str | None = None,
    ) -> Self:
        self._correction_reason = reason
        self._correction_type = correction_type
        self._corrected_invoices.append(
            CorrectionReference(invoice_number, issue_date, ksef_number)
        )
        return self

    def settles_advance(
        self,
        *,
        invoice_number: str | None = None,
        ksef_number: str | None = None,
    ) -> Self:
        self._advance_invoices.append(AdvanceInvoiceReference(invoice_number, ksef_number))
        return self

    def attachment(self, attachment: Attachment) -> Self:
        self._attachment = attachment
        return self

    def raw_extension(self, path: str, xml: str) -> Self:
        self._raw_extensions.append(RawXmlExtension(path, xml))
        return self

    def build(self) -> FA3Invoice:
        invoice = FA3Invoice(
            invoice_number=self.invoice_number,
            issue_date=self._issue_date or date.today(),
            seller=self._seller or InvoiceParty.polish_company(nip="", name="", address=""),
            buyer=self._buyer or InvoiceParty.without_tax_id(name=""),
            lines=tuple(self._lines),
            kind=self.kind,
            currency=self._currency,
            issue_place=self._issue_place,
            sale_date=self._sale_date,
            period_from=self._period_from,
            period_to=self._period_to,
            additional_parties=tuple(self._additional_parties),
            authorized_party=self._authorized_party,
            annotations=self._annotations.merge_tax_categories([line.tax for line in self._lines]),
            payment_terms=self._payment_terms,
            settlement_data=self._settlement,
            correction_reason=self._correction_reason,
            correction_type=self._correction_type,
            corrected_invoices=tuple(self._corrected_invoices),
            advance_invoices=tuple(self._advance_invoices),
            attachment=self._attachment,
            raw_extensions=tuple(self._raw_extensions),
        )
        invoice.validate().raise_for_errors()
        return invoice

    def validate(self) -> FA3ValidationResult:
        try:
            invoice = self.build()
        except ValueError as exc:
            return FA3ValidationResult((FA3ValidationIssue(str(exc)),), ())
        return invoice.validate()

    def to_xml(self, *, validate: bool = True, xsd_validate: bool = False) -> bytes:
        return self.build().to_xml(validate=validate, xsd_validate=xsd_validate)


def _coerce_address(
    value: Address | str | None,
    *,
    country_code: str = "PL",
) -> Address | None:
    if value is None:
        return None
    if isinstance(value, Address):
        return value
    return Address(line1=value, country_code=country_code.upper())


def _coerce_line_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    values = dict(kwargs)
    for field_name in ("gtu", "procedure"):
        if values.get(field_name) is not None:
            values[field_name] = str(getattr(values[field_name], "value", values[field_name]))
    return values


def _replace_party_role(
    party: InvoiceParty,
    *,
    role: ThirdPartyRole | str | None = None,
    authorized_role: AuthorizedPartyRole | str | None = None,
) -> InvoiceParty:
    return InvoiceParty(
        name=party.name,
        identifier=party.identifier,
        address=party.address,
        taxpayer_prefix=party.taxpayer_prefix,
        taxpayer_status=party.taxpayer_status,
        correspondence_address=party.correspondence_address,
        contacts=party.contacts,
        eori=party.eori,
        customer_number=party.customer_number,
        buyer_id=party.buyer_id,
        role=role if role is not None else party.role,
        authorized_role=authorized_role if authorized_role is not None else party.authorized_role,
        share=party.share,
        is_jst_subunit=party.is_jst_subunit,
        is_vat_group_member=party.is_vat_group_member,
        other_role_description=party.other_role_description,
    )
