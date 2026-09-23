from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..models import EffectiveApiRateLimits, EffectiveApiRateLimitValues


class RateLimitGroup(str, Enum):
    """Grupy limitów API KSeF.

    Nazwy odpowiadają właściwościom modelu ``EffectiveApiRateLimits`` zwracanego
    przez ``GET /rate-limits`` (KSeF API 2.8.0+).
    """

    ANONYMOUS = "anonymous"
    BATCH_SESSION = "batchSession"
    BATCH_SESSION_CLOSE = "batchSessionClose"
    COLLECTIVE_IDENTIFIER = "collectiveIdentifier"
    GLOBAL = "global"
    INVOICE_DOWNLOAD = "invoiceDownload"
    INVOICE_EXPORT = "invoiceExport"
    INVOICE_EXPORT_STATUS = "invoiceExportStatus"
    INVOICE_METADATA = "invoiceMetadata"
    INVOICE_SEND = "invoiceSend"
    INVOICE_STATUS = "invoiceStatus"
    ONLINE_SESSION = "onlineSession"
    ONLINE_SESSION_CLOSE = "onlineSessionClose"
    OTHER = "other"
    SESSION_INVOICE_LIST = "sessionInvoiceList"
    SESSION_LIST = "sessionList"
    SESSION_MISC = "sessionMisc"


# Grupy, których mechanizm nie jest jeszcze aktywny po stronie KSeF (2.8.0).
# `global` opisuje przyszłe limity naliczane per adres IP (obecnie wyłączone),
# `anonymous` obowiązywał wcześniej, ale jest zwracany dopiero od 2.8.0.
INACTIVE_RATE_LIMIT_GROUPS: frozenset[RateLimitGroup] = frozenset(
    {RateLimitGroup.GLOBAL}
)

# Operacje zamykania sesji mają od 2.8.0 osobne, wyższe limity niż otwieranie:
# sesja interaktywna 20/60/240, sesja wsadowa 20/40/120.
SESSION_CLOSE_GROUPS: frozenset[RateLimitGroup] = frozenset(
    {RateLimitGroup.ONLINE_SESSION_CLOSE, RateLimitGroup.BATCH_SESSION_CLOSE}
)


@dataclass(frozen=True)
class RateLimitInfo:
    """Pojedyncza grupa limitów w czytelnej postaci."""

    group: RateLimitGroup
    per_second: int
    per_minute: int
    per_hour: int

    @property
    def is_active(self) -> bool:
        """Czy mechanizm limitu jest obecnie egzekwowany przez KSeF."""
        return self.group not in INACTIVE_RATE_LIMIT_GROUPS

    def as_dict(self) -> dict[str, int]:
        return {
            "perSecond": self.per_second,
            "perMinute": self.per_minute,
            "perHour": self.per_hour,
        }


def _to_info(group: RateLimitGroup, values: EffectiveApiRateLimitValues) -> RateLimitInfo:
    return RateLimitInfo(
        group=group,
        per_second=values.per_second,
        per_minute=values.per_minute,
        per_hour=values.per_hour,
    )


def iter_rate_limits(limits: EffectiveApiRateLimits) -> list[RateLimitInfo]:
    """Zamienia odpowiedź ``GET /rate-limits`` na listę :class:`RateLimitInfo`.

    Kolejność odpowiada kolejności grup w kontrakcie OpenAPI. Grupy nieobecne
    w odpowiedzi są pomijane.
    """
    result: list[RateLimitInfo] = []
    for group in RateLimitGroup:
        values = getattr(limits, _attribute_name(group), None)
        if isinstance(values, EffectiveApiRateLimitValues):
            result.append(_to_info(group, values))
    return result


def get_rate_limit(
    limits: EffectiveApiRateLimits, group: RateLimitGroup | str
) -> RateLimitInfo | None:
    """Zwraca limit dla wskazanej grupy albo ``None``, gdy grupa nie występuje."""
    resolved = group if isinstance(group, RateLimitGroup) else RateLimitGroup(str(group))
    values = getattr(limits, _attribute_name(resolved), None)
    if not isinstance(values, EffectiveApiRateLimitValues):
        return None
    return _to_info(resolved, values)


def _attribute_name(group: RateLimitGroup) -> str:
    """Mapuje nazwę grupy na atrybut modelu (obsługa kolizji ze słowem kluczowym)."""
    name = group.value
    snake = _to_snake_case(name)
    if snake in {"global"}:
        return "global_"
    return snake


def _to_snake_case(name: str) -> str:
    import re

    normalized = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", normalized)
    return normalized.lower()
