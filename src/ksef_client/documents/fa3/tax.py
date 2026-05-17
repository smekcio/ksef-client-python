from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from .domain import (
    Discount,
    InvoiceLine,
    SettlementAdjustment,
    TaxCategory,
    TaxCategoryKind,
    VatClass,
)
from .models import money


@dataclass(frozen=True)
class TaxSummaryLine:
    net_field: str
    vat_field: str | None
    net_amount: Decimal
    vat_amount: Decimal


@dataclass(frozen=True)
class TaxSummary:
    lines: tuple[TaxSummaryLine, ...]
    gross_total: Decimal

    @classmethod
    def from_lines(cls, invoice_lines: tuple[InvoiceLine, ...]) -> TaxSummary:
        net_values: dict[tuple[str, str | None], Decimal] = {}
        vat_values: dict[tuple[str, str | None], Decimal] = {}
        gross_total = Decimal("0.00")
        for line in invoice_lines:
            net_field, vat_field, _vat_w_field = line.tax.summary_fields
            key = (net_field, vat_field)
            net_values[key] = money(
                net_values.get(key, Decimal("0.00")) + line.effective_net_amount
            )
            vat_values[key] = money(
                vat_values.get(key, Decimal("0.00")) + line.effective_vat_amount
            )
            gross_total = money(gross_total + line.effective_gross_amount)
        return cls(
            tuple(
                TaxSummaryLine(
                    net_field=net_field,
                    vat_field=vat_field,
                    net_amount=net_amount,
                    vat_amount=vat_values.get((net_field, vat_field), Decimal("0.00")),
                )
                for (net_field, vat_field), net_amount in net_values.items()
            ),
            gross_total,
        )


__all__ = [
    "Discount",
    "SettlementAdjustment",
    "TaxCategory",
    "TaxCategoryKind",
    "TaxSummary",
    "TaxSummaryLine",
    "VatClass",
]
