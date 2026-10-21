"""Paginacja wyników KSeF.

KSeF paginuje część kolekcji offsetowo (``pageOffset``/``pageSize``), a część
kursorowo (``continuationToken``). Ten moduł zawiera wyłącznie elementy wspólne
dla paginacji offsetowej, żeby iteratory w klientach nie powtarzały walidacji
i logiki wyznaczania kolejnych stron.

Moduł jest niezależny od warstwy HTTP — można go użyć do własnych zapytań,
które nie przechodzą przez :class:`ksef_client.KsefClient`.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Protocol

#: Minimalny ``pageSize`` w kontrakcie KSeF (wspólny dla wszystkich endpointów).
PAGE_SIZE_MIN = 10

#: Maksymalny ``pageSize`` dla ``POST /invoices/query/metadata`` (OpenAPI 2.9.0).
INVOICE_METADATA_PAGE_SIZE_MAX = 250

#: Domyślny rozmiar strony iteratorów metadanych faktur.
#:
#: Kontrakt dopuszcza 10–250, a domyślna wartość serwera to 10 — czyli 25×
#: więcej żądań niż potrzeba. 100 to kompromis między liczbą round-tripów
#: a rozmiarem odpowiedzi.
INVOICE_METADATA_PAGE_SIZE_DEFAULT = 100

#: Maksymalna liczba wyników, jaką KSeF zwróci dla jednego zapytania.
#:
#: Po przekroczeniu limitu API ustawia ``isTruncated`` i dalsze strony nie
#: zawierają już pełnego zbioru. Iterator kończy wtedy pracę i emituje
#: :class:`KsefPaginationWarning`, żeby wołający nie pomylił obcięcia
#: z kompletnym wynikiem.
INVOICE_METADATA_RESULT_LIMIT = 10_000


class KsefPaginationWarning(RuntimeWarning):
    """Ostrzeżenie o wyniku niepełnym lub nietypowym zakończeniu paginacji.

    Dziedziczy po :class:`RuntimeWarning`, więc jest widoczne domyślnie
    (w przeciwieństwie do ``DeprecationWarning``), ale nie przerywa działania.
    Wołający może je wyciszyć filtrem ``warnings`` albo potraktować jako błąd
    w testach (``-W error::ksef_client.pagination.KsefPaginationWarning``).
    """


class InvoiceMetadataPage(Protocol):
    """Minimalny kontrakt strony metadanych faktur.

    Protokół zamiast konkretnego modelu, żeby moduł nie zależał od
    ``ksef_client.models`` i mógł obsłużyć także własne implementacje stron.
    """

    @property
    def invoices(self) -> list[Any]:
        """Faktury zwrócone na tej stronie."""

    @property
    def has_more(self) -> bool:
        """Czy KSeF deklaruje kolejne wyniki."""

    @property
    def is_truncated(self) -> bool:
        """Czy osiągnięto limit 10 000 wyników zapytania."""


def validate_page_size(
    page_size: int,
    *,
    maximum: int = INVOICE_METADATA_PAGE_SIZE_MAX,
    minimum: int = PAGE_SIZE_MIN,
) -> int:
    """Sprawdza ``pageSize`` przed wysłaniem żądania.

    Walidacja lokalna jest celowa: KSeF odpowiada na ``pageSize`` poza zakresem
    błędem 400 bez wskazania, który parametr jest zły, a przy iteratorze błąd
    pojawiłby się dopiero po pierwszym żądaniu.

    Args:
        page_size: Żądany rozmiar strony.
        maximum: Górna granica dla danego endpointu.
        minimum: Dolna granica z kontraktu.

    Returns:
        Zwraca ``page_size`` bez zmian (wygodne w użyciu inline).

    Raises:
        TypeError: Gdy ``page_size`` nie jest liczbą całkowitą (``bool`` też
            jest odrzucany — ``True`` nie znaczy „jedna faktura").
        ValueError: Gdy wartość jest poza zakresem.
    """
    if isinstance(page_size, bool) or not isinstance(page_size, int):
        raise TypeError(
            f"page_size musi być liczbą całkowitą, otrzymano {type(page_size).__name__}."
        )
    if page_size < minimum or page_size > maximum:
        raise ValueError(
            f"page_size musi mieścić się w zakresie {minimum}..{maximum}, "
            f"otrzymano {page_size}."
        )
    return page_size


def validate_page_offset(page_offset: int) -> int:
    """Sprawdza ``pageOffset`` (indeks strony liczony od zera).

    Args:
        page_offset: Indeks pierwszej strony.

    Returns:
        Zwraca ``page_offset`` bez zmian.

    Raises:
        TypeError: Gdy wartość nie jest liczbą całkowitą.
        ValueError: Gdy wartość jest ujemna.
    """
    if isinstance(page_offset, bool) or not isinstance(page_offset, int):
        raise TypeError(
            f"page_offset musi być liczbą całkowitą, otrzymano {type(page_offset).__name__}."
        )
    if page_offset < 0:
        raise ValueError(f"page_offset nie może być ujemny, otrzymano {page_offset}.")
    return page_offset


def validate_max_pages(max_pages: int | None) -> int | None:
    """Sprawdza opcjonalny bezpiecznik liczby stron.

    Args:
        max_pages: Maksymalna liczba stron albo ``None`` (bez limitu).

    Returns:
        Zwraca ``max_pages`` bez zmian.

    Raises:
        TypeError: Gdy wartość nie jest liczbą całkowitą.
        ValueError: Gdy wartość jest mniejsza od 1.
    """
    if max_pages is None:
        return None
    if isinstance(max_pages, bool) or not isinstance(max_pages, int):
        raise TypeError(
            f"max_pages musi być liczbą całkowitą, otrzymano {type(max_pages).__name__}."
        )
    if max_pages < 1:
        raise ValueError(f"max_pages musi być większe od zera, otrzymano {max_pages}.")
    return max_pages


def iter_page_offsets(
    *,
    page_size: int,
    start_offset: int = 0,
    max_pages: int | None = None,
) -> Iterator[int]:
    """Generuje kolejne wartości ``pageOffset`` dla paginacji offsetowej.

    Funkcja nie zna odpowiedzi serwera — kończy się po ``max_pages`` stronach
    albo wtedy, gdy wołający przerwie iterację (``return``/``break``). Dzięki
    temu tę samą pętlę wykorzystują klient synchroniczny i asynchroniczny.

    Args:
        page_size: Rozmiar strony (już zwalidowany).
        start_offset: Indeks pierwszej strony.
        max_pages: Opcjonalny bezpiecznik liczby stron.

    Yields:
        Kolejne wartości ``pageOffset``.

    Raises:
        ValueError: Gdy ``page_size`` jest poza zakresem albo ``start_offset``
            jest ujemny.
    """
    validate_page_size(page_size)
    validate_page_offset(start_offset)
    validate_max_pages(max_pages)

    offset = start_offset
    pages = 0
    while max_pages is None or pages < max_pages:
        yield offset
        offset += page_size
        pages += 1


def page_should_continue(page: InvoiceMetadataPage) -> bool:
    """Czy po tej stronie warto pobrać kolejną.

    Trzy warunki zakończenia:

    * ``is_truncated`` — KSeF osiągnął limit 10 000 wyników; kolejne strony nie
      uzupełnią zbioru, więc dalsze żądania tylko obciążają limit tempa,
    * ``not has_more`` — serwer deklaruje koniec,
    * pusta strona przy ``has_more=True`` — anomalia serwera; kontynuowanie
      groziłoby nieskończoną pętlą i setkami identycznych żądań.

    Args:
        page: Strona zwrócona przez API.

    Returns:
        ``True``, gdy należy pobrać kolejną stronę.
    """
    if page.is_truncated:
        return False
    if not page.has_more:
        return False
    return bool(page.invoices)


def pagination_warning(
    page: InvoiceMetadataPage,
    *,
    page_size: int,
    page_offset: int,
) -> str | None:
    """Buduje treść ostrzeżenia dla nietypowego zakończenia paginacji.

    Args:
        page: Ostatnia pobrana strona.
        page_size: Rozmiar strony użyty w żądaniu.
        page_offset: Indeks ostatniej strony.

    Returns:
        Treść ostrzeżenia albo ``None``, gdy zakończenie jest normalne.
    """
    if page.is_truncated:
        return (
            "KSeF obciął wynik zapytania do "
            f"{INVOICE_METADATA_RESULT_LIMIT} faktur (isTruncated=true). "
            "Zawęź zakres dat lub filtry — kolejne strony nie zawierają "
            "pozostałych faktur."
        )
    if page.has_more and not page.invoices:
        return (
            "KSeF zwrócił pustą stronę z hasMore=true "
            f"(pageOffset={page_offset}, pageSize={page_size}). "
            "Paginacja została zatrzymana, żeby uniknąć nieskończonej pętli."
        )
    return None


__all__ = [
    "INVOICE_METADATA_PAGE_SIZE_DEFAULT",
    "INVOICE_METADATA_PAGE_SIZE_MAX",
    "INVOICE_METADATA_RESULT_LIMIT",
    "PAGE_SIZE_MIN",
    "InvoiceMetadataPage",
    "KsefPaginationWarning",
    "iter_page_offsets",
    "page_should_continue",
    "pagination_warning",
    "validate_max_pages",
    "validate_page_offset",
    "validate_page_size",
]
