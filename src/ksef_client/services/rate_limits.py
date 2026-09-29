from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..models import EffectiveApiRateLimits, EffectiveApiRateLimitValues
from ..utils.naming import to_snake_case


class RateLimitGroup(str, Enum):
    """Grupy limitów API KSeF.

    Zbiór nazw odpowiada właściwościom modelu ``EffectiveApiRateLimits`` zwracanego
    przez ``GET /rate-limits`` (KSeF API 2.8.0+). Kolejność członków jest
    alfabetyczna i **nie** odwzorowuje kolejności właściwości z kontraktu OpenAPI.
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


# Grupy, o których kontrakt nie mówi, czy mechanizm limitu jest w ogóle włączony.
# `global` opisuje limity per adres IP i w kontrakcie 2.8.x ma wyłącznie wartości
# `-1` (patrz `UNLIMITED`), więc budowanie na nim logiki ponawiania nie ma sensu.
#
# UWAGA: to nasza interpretacja, a nie twierdzenie kontraktu. Snapshot OpenAPI nie
# zawiera słów „wyłączone"/„zarezerwowane" — `is_active` znaczy więc „nie znamy
# aktywnego limitu", a nie „KSeF na pewno tego nie egzekwuje".
INACTIVE_RATE_LIMIT_GROUPS: frozenset[RateLimitGroup] = frozenset(
    {RateLimitGroup.GLOBAL}
)

# Operacje zamykania sesji mają od 2.8.0 osobne limity, odrębne od otwierania
# (`onlineSessionClose` / `batchSessionClose`). Kontrakt nie podaje tu konkretnych
# wartości — obowiązujące odczytuj z `GET /rate-limits`.
SESSION_CLOSE_GROUPS: frozenset[RateLimitGroup] = frozenset(
    {RateLimitGroup.ONLINE_SESSION_CLOSE, RateLimitGroup.BATCH_SESSION_CLOSE}
)

# Sentinel KSeF dla „bez limitu". Kontrakt typuje pola jako `int32` i nie opisuje
# tej wartości słownie, ale `GET /rate-limits` zwraca `-1` m.in. dla `global`.
UNLIMITED = -1


@dataclass(frozen=True)
class RateLimitInfo:
    """Pojedyncza grupa limitów w czytelnej postaci.

    Pola mogą przyjąć :data:`UNLIMITED` (``-1``), co oznacza brak limitu — nie
    należy traktować tego jako liczby dozwolonych żądań.
    """

    group: RateLimitGroup
    per_second: int
    per_minute: int
    per_hour: int

    @property
    def is_active(self) -> bool:
        """Czy dla tej grupy znamy aktywny limit.

        ``False`` znaczy „brak znanego limitu" (grupa zarezerwowana albo
        nieaktywna) — nie jest to twierdzenie o stanie egzekwowania po stronie KSeF.
        """
        return self.group not in INACTIVE_RATE_LIMIT_GROUPS

    @property
    def is_unlimited(self) -> bool:
        """Czy **wszystkie trzy** okna są nieograniczone (``-1``).

        Uwaga: ``False`` nie oznacza, że grupa ma limit w każdym oknie. Kontrakt
        dopuszcza ``-1`` w pojedynczych oknach (np. ``anonymous`` ma ``60/-1/-1``).
        Do sprawdzania konkretnego okna użyj :meth:`is_unlimited_window`.
        """
        return self.per_second == self.per_minute == self.per_hour == UNLIMITED

    def is_unlimited_window(self, window: str) -> bool:
        """Czy dane okno (``"per_second"``/``"per_minute"``/``"per_hour"``) jest bez limitu.

        Kontrakt KSeF dopuszcza ``-1`` w pojedynczych oknach niezależnie od
        pozostałych, więc logika ponawiania musi pytać o konkretne okno, a nie
        o całą grupę.
        """
        if window not in {"per_second", "per_minute", "per_hour"}:
            raise ValueError(
                f"Nieznane okno limitu: {window!r}. "
                f"Oczekiwano 'per_second', 'per_minute' albo 'per_hour'."
            )
        return getattr(self, window) == UNLIMITED

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

    Kolejność jest **alfabetyczna według nazwy grupy**, bo iterujemy po
    ``RateLimitGroup`` — nie odwzorowuje kolejności właściwości z kontraktu
    OpenAPI. Grupy nieobecne w odpowiedzi są pomijane.
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
    """Zwraca limit dla wskazanej grupy albo ``None``, gdy grupa nie występuje.

    Nieznana nazwa grupy również zwraca ``None`` — sygnatura ``| None`` oznacza
    „brak danych", a nie „błąd programisty", więc nie podnosimy wyjątku.
    """
    if isinstance(group, RateLimitGroup):
        resolved = group
    else:
        try:
            resolved = RateLimitGroup(str(group))
        except ValueError:
            return None
    values = getattr(limits, _attribute_name(resolved), None)
    if not isinstance(values, EffectiveApiRateLimitValues):
        return None
    return _to_info(resolved, values)


def _attribute_name(group: RateLimitGroup) -> str:
    """Mapuje nazwę grupy na atrybut modelu (obsługa kolizji ze słowem kluczowym).

    Model generowany z OpenAPI używa `global_`, bo `global` jest słowem kluczowym
    Pythona; pozostałe grupy mapują się wprost przez `camelCase` -> `snake_case`.
    """
    snake = to_snake_case(group.value)
    if snake == "global":
        return "global_"
    return snake
