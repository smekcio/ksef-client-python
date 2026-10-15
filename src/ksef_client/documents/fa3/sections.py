from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from .domain import Address, Discount, InvoiceParty, TaxCategory
from .models import FA3ValidationIssue, decimal_from_value, money

#: Warianty środka transportu wybierające gałąź schematu (`P_22B`/`P_22C`/`P_22D`).
_TRANSPORT_KINDS = frozenset({"land", "water", "air"})


def enum_value(value: Any) -> str | None:
    if value is None:
        return None
    return str(getattr(value, "value", value))


@dataclass(frozen=True)
class AdditionalDescription:
    key: str
    value: str
    #: Numer wiersza faktury (`NrWierszaFa`) albo zamówienia (`NrWierszaZam`),
    #: gdy informacja dotyczy konkretnej pozycji. Schemat czyni to pole
    #: opcjonalnym, ale bez niego nie da się przypisać opisu do pozycji.
    row_number: int | None = None

    @classmethod
    def key_value(
        cls, key: str, value: str, *, row_number: int | None = None
    ) -> AdditionalDescription:
        return cls(key, value, row_number)


@dataclass(frozen=True)
class Registry:
    full_name: str | None = None
    krs: str | None = None
    regon: str | None = None
    bdo: str | None = None

    @classmethod
    def krs_entry(cls, value: str, *, full_name: str | None = None) -> Registry:
        return cls(full_name=full_name, krs=value)

    @classmethod
    def regon_entry(cls, value: str, *, full_name: str | None = None) -> Registry:
        return cls(full_name=full_name, regon=value)

    @classmethod
    def bdo_entry(cls, value: str, *, full_name: str | None = None) -> Registry:
        return cls(full_name=full_name, bdo=value)


@dataclass(frozen=True)
class Footer:
    infos: tuple[str, ...] = ()
    registries: tuple[Registry, ...] = ()

    @classmethod
    def info(cls, text: str) -> Footer:
        return cls(infos=(text,))

    @classmethod
    def registry(cls, registry: Registry) -> Footer:
        return cls(registries=(registry,))


@dataclass(frozen=True)
class LineIdentifiers:
    unique_id: str | None = None
    internal_index: str | None = None
    gtin: str | None = None
    pkwiu: str | None = None
    cn: str | None = None
    pkob: str | None = None


@dataclass(frozen=True)
class PaymentDueDescription:
    amount: int
    unit: str
    starts_from: str

    @classmethod
    def create(cls, amount: int, unit: str, starts_from: str) -> PaymentDueDescription:
        return cls(amount, unit, starts_from)


@dataclass(frozen=True)
class PaymentDue:
    due_date: date | None = None
    term_description: PaymentDueDescription | None = None

    @classmethod
    def date(cls, value: date) -> PaymentDue:
        return cls(due_date=value)

    @classmethod
    def description(
        cls,
        amount: int,
        unit: str,
        starts_from: str,
    ) -> PaymentDue:
        return cls(term_description=PaymentDueDescription.create(amount, unit, starts_from))


@dataclass(frozen=True)
class NewTransportMeans:
    allowed_date: date
    row_number: int
    kind: str
    mileage: str | None = None
    hours_used: str | None = None
    serial_number: str | None = None
    registry_number: str | None = None
    approval_number: str | None = None
    make: str | None = None
    model: str | None = None
    color: str | None = None
    manufacture_year: str | None = None
    engine_capacity: str | None = None
    engine_power: str | None = None
    value: str = "0"
    tax_amount: str = "0"
    taxable_base: str = "0"
    tax_rate: str | None = None

    def validate(self, path: str) -> list[FA3ValidationIssue]:
        """Sprawdza wariant środka transportu.

        `kind` wybiera gałąź schematu: `land` (`P_22B`), `water` (`P_22C`) albo
        `air` (`P_22D`). Wcześniej dowolny inny napis — np. literówka `sea` —
        cicho wybierał gałąź lądową, więc dokument opisywał inny środek transportu
        niż zamierzył wołający.
        """
        issues: list[FA3ValidationIssue] = []
        if self.kind not in _TRANSPORT_KINDS:
            issues.append(
                FA3ValidationIssue(
                    f"{path}.kind: nieznany wariant {self.kind!r}; dozwolone: "
                    f"{', '.join(sorted(_TRANSPORT_KINDS))}.",
                    column=f"{path}.kind",
                )
            )
        if self.kind in {"water", "air"} and not (self.hours_used or "").strip():
            issues.append(
                FA3ValidationIssue(
                    f"{path}.hours_used: schemat wymaga liczby godzin roboczych dla "
                    f"wariantu {self.kind!r}.",
                    column=f"{path}.hours_used",
                )
            )
        if self.row_number < 1:
            issues.append(
                FA3ValidationIssue(
                    f"{path}.row_number: numer wiersza musi być dodatni.",
                    column=f"{path}.row_number",
                )
            )
        # `NowySrodkiTransportu` w schemacie FA(3) nie ma pól na wartość pojazdu,
        # kwotę podatku ani podstawę — te trzy pola nie trafiają do dokumentu.
        # Wcześniej znikały bez słowa, więc wołający mógł sądzić, że deklaruje
        # podatek od importu środka transportu.
        for field_name in ("value", "tax_amount", "taxable_base"):
            raw = str(getattr(self, field_name) or "").strip()
            if raw not in {"", "0", "0.0", "0.00"}:
                issues.append(
                    FA3ValidationIssue(
                        f"{path}.{field_name}: pole nie występuje w schemacie FA(3) "
                        f"(NowySrodkiTransportu nie ma wartości, kwoty podatku ani "
                        f"podstawy) — wartość {raw!r} nie trafi do dokumentu.",
                        column=f"{path}.{field_name}",
                        severity="warning",
                    )
                )
        return issues


@dataclass(frozen=True)
class CorrectedAdvanceState:
    amount: Decimal
    currency_rate: Decimal | None = None

    @classmethod
    def create(
        cls,
        amount: Decimal | str | int | float,
        *,
        currency_rate: Decimal | str | int | float | None = None,
    ) -> CorrectedAdvanceState:
        return cls(
            decimal_from_value(amount, field_name="corrected_advance_amount"),
            (
                decimal_from_value(currency_rate, field_name="corrected_advance_currency_rate")
                if currency_rate is not None
                else None
            ),
        )


@dataclass(frozen=True)
class ExciseRefund:
    enabled: bool = True


@dataclass(frozen=True)
class OrderLine:
    description: str
    quantity: Decimal
    unit_net_price: Decimal
    tax: TaxCategory
    unit: str = "szt"
    discount: Discount | None = None
    gtu: str | None = None
    procedure: str | None = None
    identifiers: LineIdentifiers | None = None
    excise_amount: Decimal | None = None
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
        gtu: Any = None,
        procedure: Any = None,
        identifiers: LineIdentifiers | None = None,
        excise_amount: Decimal | str | int | float | None = None,
        annex_15: bool = False,
        before_correction: bool = False,
    ) -> OrderLine:
        return cls(
            description=description,
            quantity=decimal_from_value(quantity, field_name="quantity"),
            unit_net_price=decimal_from_value(unit_net_price, field_name="unit_net_price"),
            tax=tax or TaxCategory.standard_23(),
            unit=unit,
            discount=discount,
            gtu=enum_value(gtu),
            procedure=enum_value(procedure),
            identifiers=identifiers,
            excise_amount=(
                decimal_from_value(excise_amount, field_name="excise_amount")
                if excise_amount is not None
                else None
            ),
            annex_15=annex_15,
            before_correction=before_correction,
        )

    @property
    def base_net_amount(self) -> Decimal:
        return money(self.quantity * self.unit_net_price)

    @property
    def unit_discount_amount(self) -> Decimal:
        """Obniżka na JEDNOSTKĘ (ta sama semantyka co `InvoiceLine`)."""
        if self.discount is None:
            return Decimal("0.00")
        return min(self.discount.unit_amount_for(self.unit_net_price), self.unit_net_price)

    @property
    def discount_amount(self) -> Decimal:
        """Łączna obniżka wiersza zamówienia (`P_10` × `P_8BZ`)."""
        return min(money(self.unit_discount_amount * self.quantity), self.base_net_amount)

    @property
    def effective_unit_net_price(self) -> Decimal:
        """Cena jednostkowa netto PO obniżce — to ona trafia do `P_9AZ`.

        `ZamowienieWiersz` nie ma pola na rabat (w całym schemacie FA(3) nie ma
        `P_10Z`), a oficjalny `FA_3_Przykład_29.xml` trzyma tożsamość
        `P_11NettoZ = P_8BZ × P_9AZ`. Emisja ceny sprzed rabatu dawała dokument
        wewnętrznie sprzeczny (dla 20 × 1000 z rabatem 100: `P_9AZ × P_8BZ`
        = 20 000, a `P_11NettoZ` = 18 000), mimo że `xsd_validate=True` go
        przepuszczało.
        """
        return money(self.unit_net_price - self.unit_discount_amount)

    @property
    def effective_net_amount(self) -> Decimal:
        """Wartość netto wiersza (`P_11NettoZ`) — zawsze `P_8BZ × P_9AZ`."""
        return money(self.effective_unit_net_price * self.quantity)

    @property
    def effective_vat_amount(self) -> Decimal:
        if self.tax.vat_rate is None:
            return Decimal("0.00")
        return money(self.effective_net_amount * self.tax.vat_rate / Decimal("100"))


@dataclass(frozen=True)
class Order:
    total_gross: Decimal
    lines: tuple[OrderLine, ...] = ()

    @classmethod
    def create(
        cls,
        total_gross: Decimal | str | int | float,
        lines: tuple[OrderLine, ...] = (),
    ) -> Order:
        return cls(decimal_from_value(total_gross, field_name="total_gross"), lines)


@dataclass(frozen=True)
class Contract:
    number: str | None = None
    date: date | None = None


@dataclass(frozen=True)
class Transport:
    kind: str | None = None
    other_kind_description: str | None = None
    carrier: InvoiceParty | None = None
    order_number: str | None = None
    cargo_description: str = "1"
    other_cargo_description: str | None = None
    package_unit: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    ship_from: Address | None = None
    ship_via: tuple[Address, ...] = ()
    ship_to: Address | None = None

    @classmethod
    def create(
        cls,
        kind: Any,
        *,
        other_kind_description: str | None = None,
        carrier: InvoiceParty | None = None,
        order_number: str | None = None,
        cargo_description: str = "1",
        other_cargo_description: str | None = None,
        package_unit: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        ship_from: Address | None = None,
        ship_via: tuple[Address, ...] = (),
        ship_to: Address | None = None,
    ) -> Transport:
        return cls(
            kind=enum_value(kind),
            other_kind_description=other_kind_description,
            carrier=carrier,
            order_number=order_number,
            cargo_description=cargo_description,
            other_cargo_description=other_cargo_description,
            package_unit=package_unit,
            started_at=started_at,
            finished_at=finished_at,
            ship_from=ship_from,
            ship_via=ship_via,
            ship_to=ship_to,
        )


@dataclass(frozen=True)
class TransactionTerms:
    contracts: tuple[Contract, ...] = ()
    orders: tuple[Contract, ...] = ()
    batch_numbers: tuple[str, ...] = ()
    delivery_terms: str | None = None
    contractual_rate: Decimal | None = None
    contractual_currency: str | None = None
    transports: tuple[Transport, ...] = ()
    intermediary: bool = False


@dataclass(frozen=True)
class AdvancePayment:
    amount: Decimal
    tax: TaxCategory
    paid_on: date | None = None
    currency_rate: Decimal | None = None

    @classmethod
    def create(
        cls,
        amount: Decimal | str | int | float,
        tax: TaxCategory | None = None,
        *,
        paid_on: date | None = None,
        currency_rate: Decimal | str | int | float | None = None,
    ) -> AdvancePayment:
        return cls(
            decimal_from_value(amount, field_name="advance_payment"),
            tax or TaxCategory.standard_23(),
            paid_on,
            (
                decimal_from_value(currency_rate, field_name="advance_currency_rate")
                if currency_rate is not None
                else None
            ),
        )

    @classmethod
    def partial(
        cls,
        amount: Decimal | str | int | float,
        tax: TaxCategory | None = None,
        *,
        paid_on: date | None = None,
        currency_rate: Decimal | str | int | float | None = None,
    ) -> AdvancePayment:
        return cls.create(amount, tax, paid_on=paid_on, currency_rate=currency_rate)


@dataclass(frozen=True)
class ValidationContext:
    domain_path: str
    xml_path: str


@dataclass
class SectionState:
    corrected_seller: InvoiceParty | None = None
    corrected_buyers: list[InvoiceParty] = field(default_factory=list)
    order: Order | None = None
    transaction_terms: TransactionTerms | None = None
    warehouse_documents: list[str] = field(default_factory=list)
    advance_payments: list[AdvancePayment] = field(default_factory=list)
    additional_descriptions: list[AdditionalDescription] = field(default_factory=list)
    footer: Footer | None = None
    corrected_advance_state: CorrectedAdvanceState | None = None
    excise_refund: ExciseRefund | None = None
