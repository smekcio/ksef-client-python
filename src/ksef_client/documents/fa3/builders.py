from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Final

from typing_extensions import Self

from .domain import (
    Annotation,
    Attachment,
    AttachmentBlock,
    AttachmentTable,
    BankAccount,
    CorrectionReference,
    Discount,
    FA3Invoice,
    FA3InvoiceBuilderV2,
    InvoiceLine,
    InvoiceParty,
    PartialPayment,
    PaymentTerms,
    Settlement,
    SettlementAdjustment,
    TaxCategory,
)
from .enums import CorrectionType, MarginProcedure, PaymentMethod, TransportKind
from .models import FA3InvoiceKind, decimal_from_value, money
from .sections import (
    AdditionalDescription,
    AdvancePayment,
    Contract,
    CorrectedAdvanceState,
    ExciseRefund,
    Footer,
    LineIdentifiers,
    NewTransportMeans,
    Order,
    OrderLine,
    PaymentDue,
    Registry,
    TransactionTerms,
    Transport,
    enum_value,
)


class _UnsetType:
    pass


_UNSET: Final = _UnsetType()


class BaseFA3Builder(FA3InvoiceBuilderV2):
    def __init__(self, *, invoice_number: str, kind: FA3InvoiceKind) -> None:
        super().__init__(invoice_number=invoice_number, kind=kind)
        self._corrected_seller: InvoiceParty | None = None
        self._corrected_buyers: list[InvoiceParty] = []
        self._order: Order | None = None
        self._transaction_terms: TransactionTerms | None = None
        self._warehouse_documents: list[str] = []
        self._advance_payments: list[AdvancePayment] = []
        self._additional_descriptions: list[AdditionalDescription] = []
        self._foreign_currency_rate: Decimal | None = None
        self._fp = False
        self._tp = False
        self._excise_refund: ExciseRefund | None = None
        self._corrected_advance_state: CorrectedAdvanceState | None = None
        self._footer: Footer | None = None
        self._simplified_receipt_like = False
        self._order_total_explicit = False

    def add_goods_line(
        self,
        description: str,
        *,
        quantity: Decimal | str | int | float,
        unit_net_price: Decimal | str | int | float,
        tax: TaxCategory | None = None,
        unit: str = "szt",
        discount: Discount | None = None,
        **kwargs: Any,
    ) -> BaseFA3Builder:
        return self._append_line(
            InvoiceLine.goods(
                description,
                quantity=quantity,
                unit_net_price=unit_net_price,
                tax=tax,
                unit=unit,
                discount=discount,
                **kwargs,
            )
        )

    def add_service_line(
        self,
        description: str,
        *,
        quantity: Decimal | str | int | float,
        unit_net_price: Decimal | str | int | float,
        tax: TaxCategory | None = None,
        unit: str = "szt",
        discount: Discount | None = None,
        **kwargs: Any,
    ) -> BaseFA3Builder:
        return self._append_line(
            InvoiceLine.service(
                description,
                quantity=quantity,
                unit_net_price=unit_net_price,
                tax=tax,
                unit=unit,
                discount=discount,
                **kwargs,
            )
        )

    def split_payment(self, required: bool = True) -> BaseFA3Builder:
        return self._merge_annotations(Annotation.split_payment(required))

    def cash_method(self, required: bool = True) -> BaseFA3Builder:
        return self._merge_annotations(Annotation.cash_method(required))

    def self_billing(self, required: bool = True) -> BaseFA3Builder:
        return self._merge_annotations(Annotation.self_billing(required))

    def reverse_charge(self, required: bool = True) -> BaseFA3Builder:
        return self._merge_annotations(Annotation.reverse_charge(required))

    def margin(
        self,
        procedure: MarginProcedure | str = MarginProcedure.USED_GOODS,
    ) -> BaseFA3Builder:
        return self._merge_annotations(Annotation.margin(enum_value(procedure) or "used_goods"))

    def exemption(self, basis: str, *, basis_type: str = "law") -> BaseFA3Builder:
        self._annotations = replace(
            self._annotations,
            exemption_basis=basis,
            exemption_basis_type=basis_type,
        )
        return self

    def payment_due(
        self,
        due_date: date,
        *,
        method: PaymentMethod | str | None = PaymentMethod.TRANSFER,
    ) -> BaseFA3Builder:
        current = self._payment_terms or PaymentTerms()
        self._payment_terms = replace(
            current,
            due_dates=(*current.due_dates, due_date),
            due_terms=(*current.due_terms, PaymentDue.date(due_date)),
            method=enum_value(method),
        )
        return self

    def payment_due_description(
        self,
        amount: int,
        unit: str,
        starts_from: str,
        *,
        method: PaymentMethod | str | None = PaymentMethod.TRANSFER,
    ) -> BaseFA3Builder:
        current = self._payment_terms or PaymentTerms()
        self._payment_terms = replace(
            current,
            due_terms=(
                *current.due_terms,
                PaymentDue.description(amount, unit, starts_from),
            ),
            method=enum_value(method),
        )
        return self

    def paid(self, paid_on: date) -> BaseFA3Builder:
        current = self._payment_terms or PaymentTerms()
        self._payment_terms = replace(current, paid_date=paid_on)
        return self

    def partially_paid(
        self,
        amount: Decimal | str | int | float,
        paid_on: date,
        *,
        method: PaymentMethod | str | None = None,
        other_method_description: str | None = None,
    ) -> BaseFA3Builder:
        current = self._payment_terms or PaymentTerms()
        partial = PartialPayment.create(
            amount,
            paid_on,
            method=enum_value(method),
            other_method_description=other_method_description,
        )
        self._payment_terms = replace(
            current,
            partial_payments=(*current.partial_payments, partial),
        )
        return self

    def bank_account(
        self,
        number: str,
        *,
        swift: str | None = None,
        own_bank_account: str | None = None,
        bank_name: str | None = None,
        description: str | None = None,
        factor: bool = False,
    ) -> BaseFA3Builder:
        current = self._payment_terms or PaymentTerms()
        account = BankAccount(number, swift, own_bank_account, bank_name, description)
        if factor:
            self._payment_terms = replace(
                current,
                factor_accounts=(*current.factor_accounts, account),
            )
        else:
            self._payment_terms = replace(
                current,
                bank_accounts=(*current.bank_accounts, account),
            )
        return self

    def cash_discount(
        self,
        terms: str,
        amount: Decimal | str | int | float | str,
    ) -> BaseFA3Builder:
        current = self._payment_terms or PaymentTerms()
        self._payment_terms = replace(
            current,
            cash_discount_terms=terms,
            cash_discount_amount=str(amount),
        )
        return self

    def transaction_terms(
        self,
        *,
        delivery_terms: str | None | _UnsetType = _UNSET,
        contractual_rate: Decimal | str | int | float | None | _UnsetType = _UNSET,
        contractual_currency: str | None | _UnsetType = _UNSET,
        intermediary: bool | _UnsetType = _UNSET,
    ) -> BaseFA3Builder:
        current = self._transaction_terms or TransactionTerms()
        next_delivery_terms: str | None
        if isinstance(delivery_terms, _UnsetType):
            next_delivery_terms = current.delivery_terms
        else:
            next_delivery_terms = delivery_terms

        next_contractual_rate: Decimal | None
        if isinstance(contractual_rate, _UnsetType):
            next_contractual_rate = current.contractual_rate
        elif contractual_rate is None:
            next_contractual_rate = None
        else:
            next_contractual_rate = decimal_from_value(
                contractual_rate,
                field_name="contractual_rate",
            )

        next_contractual_currency: str | None
        if isinstance(contractual_currency, _UnsetType):
            next_contractual_currency = current.contractual_currency
        else:
            next_contractual_currency = (
                contractual_currency.upper() if contractual_currency else None
            )

        next_intermediary: bool
        if isinstance(intermediary, _UnsetType):
            next_intermediary = current.intermediary
        else:
            next_intermediary = intermediary

        self._transaction_terms = replace(
            current,
            delivery_terms=next_delivery_terms,
            contractual_rate=next_contractual_rate,
            contractual_currency=next_contractual_currency,
            intermediary=next_intermediary,
        )
        return self

    def contract(self, *, number: str | None = None, date: date | None = None) -> BaseFA3Builder:
        current = self._transaction_terms or TransactionTerms()
        self._transaction_terms = replace(
            current,
            contracts=(*current.contracts, Contract(number=number, date=date)),
        )
        return self

    def order_reference(
        self,
        *,
        number: str | None = None,
        date: date | None = None,
    ) -> BaseFA3Builder:
        current = self._transaction_terms or TransactionTerms()
        self._transaction_terms = replace(
            current,
            orders=(*current.orders, Contract(number=number, date=date)),
        )
        return self

    def batch_number(self, value: str) -> BaseFA3Builder:
        current = self._transaction_terms or TransactionTerms()
        self._transaction_terms = replace(
            current,
            batch_numbers=(*current.batch_numbers, value),
        )
        return self

    def warehouse_document(self, number: str) -> BaseFA3Builder:
        self._warehouse_documents.append(number)
        return self

    def transport(
        self,
        kind: TransportKind | str,
        *,
        other_kind_description: str | None = None,
        carrier: InvoiceParty | None = None,
        order_number: str | None = None,
        cargo_description: str = "1",
        other_cargo_description: str | None = None,
        package_unit: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        ship_from: Any = None,
        ship_via: tuple[Any, ...] = (),
        ship_to: Any = None,
    ) -> BaseFA3Builder:
        current = self._transaction_terms or TransactionTerms()
        self._transaction_terms = replace(
            current,
            transports=(
                *current.transports,
                Transport.create(
                    kind,
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
                ),
            ),
        )
        return self

    def additional_description(self, key: str, value: str) -> BaseFA3Builder:
        self._additional_descriptions.append(AdditionalDescription.key_value(key, value))
        return self

    def foreign_currency_rate(
        self,
        value: Decimal | str | int | float,
    ) -> BaseFA3Builder:
        self._foreign_currency_rate = decimal_from_value(value, field_name="foreign_currency_rate")
        return self

    def fiscal_receipt_invoice(self, enabled: bool = True) -> BaseFA3Builder:
        self._fp = enabled
        return self

    def related_party_transaction(self, enabled: bool = True) -> BaseFA3Builder:
        self._tp = enabled
        return self

    def excise_refund(self, enabled: bool = True) -> BaseFA3Builder:
        self._excise_refund = ExciseRefund(enabled)
        return self

    def new_transport(
        self,
        means: NewTransportMeans,
        *,
        intra_eu: bool = False,
    ) -> BaseFA3Builder:
        self._annotations = replace(
            self._annotations,
            new_transport=True,
            new_transport_intra_eu=intra_eu,
            new_transport_means=(*self._annotations.new_transport_means, means),
        )
        return self

    def footer_info(self, text: str) -> BaseFA3Builder:
        current = self._footer or Footer()
        self._footer = replace(current, infos=(*current.infos, text))
        return self

    def registry(self, registry: Registry) -> BaseFA3Builder:
        current = self._footer or Footer()
        self._footer = replace(current, registries=(*current.registries, registry))
        return self

    def corrected_advance_state(
        self,
        amount: Decimal | str | int | float,
        *,
        currency_rate: Decimal | str | int | float | None = None,
    ) -> BaseFA3Builder:
        self._corrected_advance_state = CorrectedAdvanceState.create(
            amount,
            currency_rate=currency_rate,
        )
        return self

    def with_section(self, section: object) -> Self:
        if isinstance(section, AdditionalDescription):
            self._additional_descriptions.append(section)
        elif isinstance(section, Footer):
            current = self._footer or Footer()
            self._footer = Footer(
                infos=(*current.infos, *section.infos),
                registries=(*current.registries, *section.registries),
            )
        elif isinstance(section, ExciseRefund):
            self._excise_refund = section
        elif isinstance(section, CorrectedAdvanceState):
            self._corrected_advance_state = section
        elif isinstance(section, NewTransportMeans):
            self.new_transport(section)
        else:
            raise TypeError(f"Unsupported FA(3) typed section: {type(section).__name__}")
        return self

    def attachment_text(self, header: str, *paragraphs: str) -> Self:
        self._attachment = Attachment.text(header, *paragraphs)
        return self

    def attachment_table(
        self,
        *,
        header: str | None = None,
        columns: tuple[str, ...],
        rows: tuple[tuple[str, ...], ...],
        description: str | None = None,
    ) -> Self:
        table = AttachmentTable(headers=columns, rows=rows, description=description)
        self._attachment = Attachment((AttachmentBlock(header=header, tables=(table,)),))
        return self

    def attachment_block(self, block: AttachmentBlock) -> Self:
        current = self._attachment or Attachment(())
        self._attachment = Attachment((*current.blocks, block))
        return self

    def build(self) -> FA3Invoice:
        invoice = super().build()
        invoice = replace(
            invoice,
            corrected_seller=self._corrected_seller,
            corrected_buyers=tuple(self._corrected_buyers),
            advance_payments=tuple(self._advance_payments),
            order=self._order,
            transaction_terms=self._transaction_terms,
            warehouse_documents=tuple(self._warehouse_documents),
            additional_descriptions=tuple(self._additional_descriptions),
            foreign_currency_rate=self._foreign_currency_rate,
            fp=self._fp,
            tp=self._tp,
            excise_refund=self._excise_refund,
            corrected_advance_state=self._corrected_advance_state,
            footer=self._footer,
        )
        invoice.validate().raise_for_errors()
        return invoice

    def _append_line(self, line: InvoiceLine) -> BaseFA3Builder:
        self._lines.append(line)
        return self

    def _merge_annotations(self, *annotations: Annotation) -> BaseFA3Builder:
        for annotation in annotations:
            if annotation.key == "cash_method":
                self._annotations = replace(
                    self._annotations,
                    cash_method=bool(annotation.value),
                )
            elif annotation.key == "self_billing":
                self._annotations = replace(
                    self._annotations,
                    self_billing=bool(annotation.value),
                )
            elif annotation.key == "reverse_charge":
                self._annotations = replace(
                    self._annotations,
                    reverse_charge=bool(annotation.value),
                )
            elif annotation.key == "split_payment":
                self._annotations = replace(
                    self._annotations,
                    split_payment=bool(annotation.value),
                )
            elif annotation.key == "simplified_triangular":
                self._annotations = replace(
                    self._annotations,
                    simplified_triangular=bool(annotation.value),
                )
            elif annotation.key == "margin_procedure":
                self._annotations = replace(
                    self._annotations,
                    margin_procedure=str(annotation.value),
                )
        return self


class BasicInvoiceBuilder(BaseFA3Builder):
    def __init__(self, *, invoice_number: str) -> None:
        super().__init__(invoice_number=invoice_number, kind=FA3InvoiceKind.BASIC)


class SimplifiedInvoiceBuilder(BaseFA3Builder):
    def __init__(self, *, invoice_number: str) -> None:
        super().__init__(invoice_number=invoice_number, kind=FA3InvoiceKind.SIMPLIFIED)

    def as_simplified_receipt_like(self) -> SimplifiedInvoiceBuilder:
        self._simplified_receipt_like = True
        return self

    def build(self) -> FA3Invoice:
        invoice = super().build()
        if self._simplified_receipt_like:
            if invoice.currency.upper() != "PLN":
                raise ValueError(
                    "invoice.currency: faktura uproszczona paragonowa z limitem 450 PLN "
                    "wymaga waluty PLN."
                )
            if invoice.total_gross > money(Decimal("450.00")):
                raise ValueError(
                    "invoice.total_gross: faktura uproszczona paragonowa nie może "
                    "przekroczyć 450 PLN."
                )
        return invoice


class CorrectionInvoiceBuilder(BaseFA3Builder):
    def __init__(
        self,
        *,
        invoice_number: str,
        kind: FA3InvoiceKind = FA3InvoiceKind.CORRECTION,
    ) -> None:
        super().__init__(invoice_number=invoice_number, kind=kind)

    def corrects_invoice(
        self,
        *,
        number: str,
        issue_date: date,
        reason: str,
        correction_type: CorrectionType | str | None = None,
        ksef_number: str | None = None,
    ) -> CorrectionInvoiceBuilder:
        self._correction_reason = reason
        self._correction_type = enum_value(correction_type)
        self._corrected_invoices.append(CorrectionReference(number, issue_date, ksef_number))
        return self

    def corrects_many(
        self,
        references: tuple[CorrectionReference, ...],
        *,
        reason: str,
        correction_type: CorrectionType | str | None = None,
    ) -> CorrectionInvoiceBuilder:
        self._correction_reason = reason
        self._correction_type = enum_value(correction_type)
        self._corrected_invoices.extend(references)
        return self

    def correction_type(self, value: CorrectionType | str) -> CorrectionInvoiceBuilder:
        self._correction_type = enum_value(value)
        return self

    def corrected_period(self, value: str) -> CorrectionInvoiceBuilder:
        self._corrected_period = value
        return self

    def corrected_invoice_number_override(self, value: str) -> CorrectionInvoiceBuilder:
        self._corrected_invoice_number_override = value
        return self

    def corrected_seller(self, party: InvoiceParty) -> CorrectionInvoiceBuilder:
        self._corrected_seller = party
        return self

    def corrected_buyer(self, party: InvoiceParty) -> CorrectionInvoiceBuilder:
        self._corrected_buyers.append(party)
        return self

    def add_corrected_line_before_after(
        self,
        *,
        before: InvoiceLine,
        after: InvoiceLine,
    ) -> CorrectionInvoiceBuilder:
        self._lines.extend(
            (
                replace(before, before_correction=True),
                replace(after, before_correction=False),
            )
        )
        return self


class AdvanceInvoiceBuilder(BaseFA3Builder):
    def __init__(
        self,
        *,
        invoice_number: str,
        kind: FA3InvoiceKind = FA3InvoiceKind.ADVANCE,
    ) -> None:
        super().__init__(invoice_number=invoice_number, kind=kind)

    def advance_payment(
        self,
        *,
        amount: Decimal | str | int | float,
        tax: TaxCategory | None = None,
        paid_on: date | None = None,
        currency_rate: Decimal | str | int | float | None = None,
    ) -> AdvanceInvoiceBuilder:
        self._advance_payments.append(
            AdvancePayment.create(
                amount,
                tax,
                paid_on=paid_on,
                currency_rate=currency_rate,
            )
        )
        return self

    def order(self, *, total_gross: Decimal | str | int | float) -> AdvanceInvoiceBuilder:
        current_lines = self._order.lines if self._order else ()
        self._order = Order.create(total_gross, current_lines)
        self._order_total_explicit = True
        return self

    def order_line(
        self,
        description: str,
        *,
        quantity: Decimal | str | int | float,
        unit_net_price: Decimal | str | int | float,
        tax: TaxCategory | None = None,
        unit: str = "szt",
        discount: Discount | None = None,
        identifiers: LineIdentifiers | None = None,
        **kwargs: Any,
    ) -> AdvanceInvoiceBuilder:
        line = OrderLine.create(
            description,
            quantity=quantity,
            unit_net_price=unit_net_price,
            tax=tax,
            unit=unit,
            discount=discount,
            identifiers=identifiers,
            **kwargs,
        )
        existing_lines = self._order.lines if self._order else ()
        updated_lines = (*existing_lines, line)
        if self._order is not None and self._order_total_explicit:
            total = self._order.total_gross
        else:
            total = money(
                sum(
                    (
                        entry.effective_net_amount + entry.effective_vat_amount
                        for entry in updated_lines
                    ),
                    Decimal("0.00"),
                )
            )
            self._order_total_explicit = False
        self._order = Order(total_gross=total, lines=updated_lines)
        return self


class SettlementInvoiceBuilder(BaseFA3Builder):
    def __init__(
        self,
        *,
        invoice_number: str,
        kind: FA3InvoiceKind = FA3InvoiceKind.SETTLEMENT,
    ) -> None:
        super().__init__(invoice_number=invoice_number, kind=kind)

    def settles_advance(
        self,
        *,
        invoice_number: str | None = None,
        ksef_number: str | None = None,
    ) -> SettlementInvoiceBuilder:
        super().settles_advance(invoice_number=invoice_number, ksef_number=ksef_number)
        return self

    def settles_advances(
        self,
        references: tuple[tuple[str | None, str | None], ...],
    ) -> SettlementInvoiceBuilder:
        for invoice_number, ksef_number in references:
            self.settles_advance(invoice_number=invoice_number, ksef_number=ksef_number)
        return self

    def remaining_to_pay(self, amount: Decimal | str | int | float) -> SettlementInvoiceBuilder:
        current = self._settlement or Settlement()
        self._settlement = replace(
            current,
            amount_due=decimal_from_value(amount, field_name="remaining_to_pay"),
        )
        return self

    def document_discount(
        self,
        amount: Decimal | str | int | float,
        *,
        reason: str,
    ) -> SettlementInvoiceBuilder:
        current = self._settlement or Settlement()
        self._settlement = replace(
            current,
            deductions=(*current.deductions, SettlementAdjustment.create(amount, reason)),
        )
        return self


class AdvanceCorrectionInvoiceBuilder(CorrectionInvoiceBuilder, AdvanceInvoiceBuilder):
    def __init__(self, *, invoice_number: str) -> None:
        CorrectionInvoiceBuilder.__init__(
            self,
            invoice_number=invoice_number,
            kind=FA3InvoiceKind.ADVANCE_CORRECTION,
        )


class SettlementCorrectionInvoiceBuilder(CorrectionInvoiceBuilder, SettlementInvoiceBuilder):
    def __init__(self, *, invoice_number: str) -> None:
        CorrectionInvoiceBuilder.__init__(
            self,
            invoice_number=invoice_number,
            kind=FA3InvoiceKind.SETTLEMENT_CORRECTION,
        )


__all__ = [
    "AdvanceCorrectionInvoiceBuilder",
    "AdvanceInvoiceBuilder",
    "BaseFA3Builder",
    "BasicInvoiceBuilder",
    "CorrectionInvoiceBuilder",
    "SettlementCorrectionInvoiceBuilder",
    "SettlementInvoiceBuilder",
    "SimplifiedInvoiceBuilder",
]
