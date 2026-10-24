"""Zarządzanie tokenami dostępowymi KSeF — auto-refresh i wstrzykiwanie w HTTP.

Moduł dodaje **addytwną** warstwę nad :class:`~ksef_client.client.KsefClient`:
:class:`TokenManager` trzyma token dostępowy i odświeżający, a
:class:`~ksef_client.client.AuthenticatedClient` używa go do wstrzykiwania
nagłówka ``Authorization`` w każde żądanie. Dzięki temu metody klientów nie
wymagają już parametru ``access_token``.

Zasady działania:

* **proaktywny refresh** — gdy do wygaśnięcia tokena zostało mniej niż
  ``refresh_margin_seconds`` (domyślnie 60 s), token jest odświeżany **przed**
  wysłaniem żądania,
* **reaktywny refresh** — odpowiedź 401 na żądanie z tokenem z managera powoduje
  jednorazowe odświeżenie i powtórzenie żądania; drugi 401 leci do wołającego,
* **deduplikacja** — refresh odbywa się pod lockiem z podwójnym sprawdzeniem,
  więc dwa równoległe żądania nie wykonają dwóch refreshy,
* **jawny token wygrywa** — jeśli wołający poda ``access_token``/``refresh_token``
  w metodzie, manager nie jest konsultowany (dotychczasowe zachowanie zostaje),
* **``skip_auth``** (pre-signed URL) nigdy nie dostaje nagłówka ``Authorization``,
* **bezpieczne callbacki** — ``on_refresh`` nie może zainicjować kolejnego refreshu;
  taka reentrancja kończy się ``TokenManagerError`` zamiast zakleszczenia.

Bezpieczeństwo: wartości tokenów nie trafiają do ``repr`` ani do logów; po
odświeżeniu wołający może zapisać nowy token przez ``on_refresh`` (np. do keyringa).
"""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import logging
import math
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from .exceptions import KsefHttpError
from .http import AsyncBaseHttpClient, BaseHttpClient, HttpResponse
from .models import AuthenticationTokensResponse, TokenInfo
from .utils.datetime_parsing import try_parse_api_datetime

if TYPE_CHECKING:
    from .clients.auth import AsyncAuthClient, AuthClient
    from .config import KsefClientOptions

logger = logging.getLogger(__name__)


class _SyncNotificationState(threading.local):
    """Per-wątkowy znacznik „trwa callback on_refresh” (wariant sync)."""

    active: bool = False


#: Znacznik „trwa callback on_refresh” — zapobiega zakleszczeniu na locku powiadomień.
#: Wariant sync jest per-wątek (inny wątek może odświeżać równolegle), a async jest
#: per-zadanie (``ContextVar``), więc równoległe zadania nie są fałszywie blokowane.
_SYNC_NOTIFYING = _SyncNotificationState()
_ASYNC_NOTIFYING: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "ksef_client_notifying",
    default=False,
)

_REENTRANT_REFRESH_ERROR = (
    "on_refresh callback must not trigger another token refresh; "
    "the callback runs while token notifications are being serialized."
)

#: Domyślny zapas przed wygaśnięciem tokena (sekundy), po którym następuje refresh.
DEFAULT_REFRESH_MARGIN_SECONDS = 60.0


class TokenManagerError(ValueError):
    """Błąd zarządzania tokenami (brak tokena, brak możliwości odświeżenia)."""


@dataclass(frozen=True)
class TokenSnapshot:
    """Bezpieczny widok stanu tokenów — bez wartości tokenów.

    Attributes:
        has_refresh_token: Czy manager ma token odświeżający.
        access_token_expires_at: Znana data wygaśnięcia tokena dostępowego (UTC).
            ``None`` oznacza, że ważność nie jest znana i refresh jest tylko
            reaktywny (po 401).
        refresh_margin_seconds: Zapas przed wygaśnięciem, po którym następuje refresh.
    """

    has_refresh_token: bool
    access_token_expires_at: datetime | None
    refresh_margin_seconds: float


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _partial_tokens(
    tokens: AuthenticationTokensResponse,
) -> tuple[str, str | None, datetime | None]:
    """Wyciąga tokeny i ważność z odpowiedzi API (tolerancyjnie dla daty)."""
    refresh_token = tokens.refresh_token.token or None
    expires_at = try_parse_api_datetime(tokens.access_token.valid_until)
    return tokens.access_token.token, refresh_token, expires_at


class TokenManager:
    """Token dostępowy + odświeżający z automatycznym refresh (wersja sync).

    Args:
        access_token: Token dostępowy.
        refresh_token: Token odświeżający (``None`` = brak możliwości refreshu).
        access_token_valid_until: Data wygaśnięcia tokena dostępowego — ``str``
            w formacie API albo ``datetime``. ``None`` oznacza brak informacji
            (refresh tylko reaktywny, po 401).
        refresh_margin_seconds: Ile sekund przed wygaśnięciem odświeżyć token.
        on_refresh: Opcjonalny callback wołany po udanym odświeżeniu (np. zapis
            nowego tokena do keyringa). Wyjątek z callbacku propaguje.
        refresh_handler: Własny sposób odświeżenia tokena (``refresh_token ->
            TokenInfo``); domyślnie ustawiany przez
            :meth:`bind_auth_client` na endpoincie ``/auth/token/refresh``.
        clock: Źródło czasu (domyślnie UTC ``now``); wstrzykiwane w testach.

    Raises:
        TokenManagerError: Gdy token jest pusty albo margines/daty są niepoprawne.
    """

    def __init__(
        self,
        access_token: str,
        refresh_token: str | None = None,
        *,
        access_token_valid_until: str | datetime | None = None,
        refresh_margin_seconds: float = DEFAULT_REFRESH_MARGIN_SECONDS,
        on_refresh: Callable[[TokenInfo], None] | None = None,
        refresh_handler: Callable[[str], TokenInfo] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(access_token, str) or not access_token.strip():
            raise TokenManagerError("access_token must be a non-empty string")
        if refresh_token is not None and not isinstance(refresh_token, str):
            raise TokenManagerError("refresh_token must be a string or None")
        if not math.isfinite(refresh_margin_seconds) or refresh_margin_seconds < 0:
            raise TokenManagerError("refresh_margin_seconds must be a finite value >= 0")
        if refresh_handler is not None and not callable(refresh_handler):
            raise TokenManagerError("refresh_handler must be callable")
        if on_refresh is not None and not callable(on_refresh):
            raise TokenManagerError("on_refresh must be callable")
        if clock is not None and not callable(clock):
            raise TokenManagerError("clock must be callable")

        self._access_token = access_token
        self._refresh_token = refresh_token or None
        self._access_token_expires_at = self._normalize_valid_until(access_token_valid_until)
        self._refresh_margin_seconds = refresh_margin_seconds
        self._on_refresh = on_refresh
        self._refresh_handler = refresh_handler
        self._refresh_handler_is_custom = refresh_handler is not None
        self._clock = clock or _utc_now
        self._lock = threading.Lock()
        self._notification_lock = threading.Lock()
        self._last_refresh_info: TokenInfo | None = None

    @staticmethod
    def _normalize_valid_until(value: str | datetime | None) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return _normalize_datetime(value)
        if isinstance(value, str):
            parsed = try_parse_api_datetime(value)
            if parsed is None:
                raise TokenManagerError(
                    f"access_token_valid_until is not a valid timestamp: {value!r}"
                )
            return parsed
        raise TokenManagerError("access_token_valid_until must be str, datetime or None")

    @classmethod
    def from_tokens(
        cls,
        tokens: AuthenticationTokensResponse,
        *,
        refresh_margin_seconds: float = DEFAULT_REFRESH_MARGIN_SECONDS,
        on_refresh: Callable[[TokenInfo], None] | None = None,
        refresh_handler: Callable[[str], TokenInfo] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> TokenManager:
        """Buduje managera z odpowiedzi ``/auth/token/redeem``.

        Nieparsowalna data ważności jest traktowana jak brak informacji
        (refresh reaktywny) — odpowiedź API nie może wywrócić konstrukcji
        managera, bo tokeny są już ważne.
        """
        access_token, refresh_token, expires_at = _partial_tokens(tokens)
        return cls(
            access_token,
            refresh_token,
            access_token_valid_until=expires_at,
            refresh_margin_seconds=refresh_margin_seconds,
            on_refresh=on_refresh,
            refresh_handler=refresh_handler,
            clock=clock,
        )

    def bind_auth_client(self, auth_client: AuthClient) -> None:
        """Podłącza klienta auth jako domyślny handler refreshu.

        Własny ``refresh_handler`` (podany w konstruktorze) nie jest nadpisywany;
        handler podłączony automatycznie jest zastępowany przy ponownym bindowaniu,
        dzięki czemu manager można bezpiecznie przenieść do nowego klienta.
        """

        def _refresh(refresh_token: str) -> TokenInfo:
            return auth_client.refresh_access_token(refresh_token).access_token

        with self._lock:
            if not self._refresh_handler_is_custom:
                self._refresh_handler = _refresh

    @property
    def can_refresh(self) -> bool:
        """Czy manager ma czym odświeżyć token (refresh token + handler)."""
        return self._refresh_token is not None and self._refresh_handler is not None

    @property
    def refresh_margin_seconds(self) -> float:
        return self._refresh_margin_seconds

    def _now(self) -> datetime:
        return _normalize_datetime(self._clock())

    def _needs_refresh_locked(self) -> bool:
        expires_at = self._access_token_expires_at
        if expires_at is None:
            return False
        return self._now() + timedelta(seconds=self._refresh_margin_seconds) >= expires_at

    def _refresh_locked(self) -> TokenInfo:
        if _SYNC_NOTIFYING.active:
            raise TokenManagerError(_REENTRANT_REFRESH_ERROR)
        if self._refresh_token is None or self._refresh_handler is None:
            raise TokenManagerError(
                "Cannot refresh the access token: no refresh token or refresh handler."
            )
        info = self._refresh_handler(self._refresh_token)
        if inspect.isawaitable(info):
            if inspect.iscoroutine(info):
                info.close()
            raise TokenManagerError(
                "refresh_handler is async; use AsyncTokenManager for async handlers."
            )
        if not isinstance(info, TokenInfo) or not info.token:
            raise TokenManagerError("Refresh handler returned an empty access token.")
        self._access_token = info.token
        expires_at = try_parse_api_datetime(info.valid_until)
        if expires_at is not None and expires_at <= self._now():
            # Token z datą ważności w przeszłości odświeżałby się w każdej
            # metodzie; przechodzimy na tryb reaktywny zamiast pętli refreshy.
            logger.warning(
                "Refreshed access token has a validity date in the past; "
                "switching to reactive refresh only."
            )
            expires_at = None
        self._access_token_expires_at = expires_at
        self._last_refresh_info = info
        return info

    def _refresh_if_needed_locked(self) -> TokenInfo | None:
        if not self._needs_refresh_locked():
            return None
        if not self.can_refresh:
            # Brak możliwości refreshu: używamy tokena, jaki jest — serwer
            # odpowie 401, a wołający dostanie oryginalny błąd.
            return None
        return self._refresh_locked()

    def _notify(self, info: TokenInfo | None) -> None:
        if info is not None and self._on_refresh is not None:
            # Serialize writes without holding the token lock during user code.
            # A delayed notification must not overwrite an already newer token.
            with self._notification_lock:
                if info is self._last_refresh_info:
                    previous = _SYNC_NOTIFYING.active
                    _SYNC_NOTIFYING.active = True
                    try:
                        self._on_refresh(info)
                    finally:
                        _SYNC_NOTIFYING.active = previous

    def get_access_token(self) -> str:
        """Zwraca ważny token dostępowy, odświeżając go proaktywnie, gdy trzeba."""
        with self._lock:
            info = self._refresh_if_needed_locked()
            token = self._access_token
        self._notify(info)
        return token

    def _is_access_token_current(self, token: str | None) -> bool:
        """Check an admitted token without waiting or refreshing under a lease."""
        if not self._lock.acquire(blocking=False):
            return False
        try:
            return token == self._access_token and (
                not self.can_refresh
                or self._access_token_expires_at is None
                or self._access_token_expires_at > self._now()
            )
        finally:
            self._lock.release()

    def force_refresh(self, *, stale_token: str | None = None) -> str:
        """Wymusza odświeżenie tokena (używane po odpowiedzi 401).

        Args:
            stale_token: Token, który dostał 401. Gdy w międzyczasie inny wątek
                zdążył odświeżyć token, zwracamy nowy bez kolejnego refreshu.

        Returns:
            Nowy (albo już odświeżony przez inny wątek) token dostępowy.

        Raises:
            TokenManagerError: Gdy manager nie ma czym odświeżyć tokena.
        """
        with self._lock:
            if stale_token is not None and stale_token != self._access_token:
                return self._access_token
            info = self._refresh_locked()
            token = self._access_token
        self._notify(info)
        return token

    def snapshot(self) -> TokenSnapshot:
        """Bezpieczny widok stanu (bez wartości tokenów)."""
        return TokenSnapshot(
            has_refresh_token=self._refresh_token is not None,
            access_token_expires_at=self._access_token_expires_at,
            refresh_margin_seconds=self._refresh_margin_seconds,
        )

    def __repr__(self) -> str:
        return (
            "TokenManager(access_token=<redacted>, "
            f"refresh_token={'<redacted>' if self._refresh_token else None}, "
            f"access_token_expires_at={self._access_token_expires_at!r})"
        )


class AsyncTokenManager:
    """Asynchroniczny odpowiednik :class:`TokenManager` (``asyncio.Lock``).

    Args:
        access_token: Token dostępowy.
        refresh_token: Token odświeżający (``None`` = brak możliwości refreshu).
        access_token_valid_until: Data wygaśnięcia tokena dostępowego.
        refresh_margin_seconds: Ile sekund przed wygaśnięciem odświeżyć token.
        on_refresh: Callback (sync albo async) wołany po udanym odświeżeniu.
        refresh_handler: Własny async handler odświeżenia.
        clock: Źródło czasu (wstrzykiwane w testach).
    """

    def __init__(
        self,
        access_token: str,
        refresh_token: str | None = None,
        *,
        access_token_valid_until: str | datetime | None = None,
        refresh_margin_seconds: float = DEFAULT_REFRESH_MARGIN_SECONDS,
        on_refresh: Callable[[TokenInfo], Awaitable[None] | None] | None = None,
        refresh_handler: Callable[[str], TokenInfo | Awaitable[TokenInfo]] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(access_token, str) or not access_token.strip():
            raise TokenManagerError("access_token must be a non-empty string")
        if refresh_token is not None and not isinstance(refresh_token, str):
            raise TokenManagerError("refresh_token must be a string or None")
        if not math.isfinite(refresh_margin_seconds) or refresh_margin_seconds < 0:
            raise TokenManagerError("refresh_margin_seconds must be a finite value >= 0")
        if refresh_handler is not None and not callable(refresh_handler):
            raise TokenManagerError("refresh_handler must be callable")
        if on_refresh is not None and not callable(on_refresh):
            raise TokenManagerError("on_refresh must be callable")
        if clock is not None and not callable(clock):
            raise TokenManagerError("clock must be callable")

        self._access_token = access_token
        self._refresh_token = refresh_token or None
        self._access_token_expires_at = TokenManager._normalize_valid_until(
            access_token_valid_until
        )
        self._refresh_margin_seconds = refresh_margin_seconds
        self._on_refresh = on_refresh
        self._refresh_handler = refresh_handler
        self._refresh_handler_is_custom = refresh_handler is not None
        self._clock = clock or _utc_now
        self._lock = asyncio.Lock()
        self._notification_lock = asyncio.Lock()
        self._last_refresh_info: TokenInfo | None = None

    @classmethod
    def from_tokens(
        cls,
        tokens: AuthenticationTokensResponse,
        *,
        refresh_margin_seconds: float = DEFAULT_REFRESH_MARGIN_SECONDS,
        on_refresh: Callable[[TokenInfo], Awaitable[None] | None] | None = None,
        refresh_handler: Callable[[str], TokenInfo | Awaitable[TokenInfo]] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> AsyncTokenManager:
        """Buduje managera z odpowiedzi ``/auth/token/redeem`` (wersja async)."""
        access_token, refresh_token, expires_at = _partial_tokens(tokens)
        return cls(
            access_token,
            refresh_token,
            access_token_valid_until=expires_at,
            refresh_margin_seconds=refresh_margin_seconds,
            on_refresh=on_refresh,
            refresh_handler=refresh_handler,
            clock=clock,
        )

    def bind_auth_client(self, auth_client: AsyncAuthClient) -> None:
        """Podłącza async klienta auth jako domyślny handler refreshu.

        Własny ``refresh_handler`` nie jest nadpisywany; handler automatyczny jest
        zastępowany przy ponownym bindowaniu.
        """

        async def _refresh(refresh_token: str) -> TokenInfo:
            response = await auth_client.refresh_access_token(refresh_token)
            return response.access_token

        if not self._refresh_handler_is_custom:
            self._refresh_handler = _refresh

    @property
    def can_refresh(self) -> bool:
        """Czy manager ma czym odświeżyć token."""
        return self._refresh_token is not None and self._refresh_handler is not None

    @property
    def refresh_margin_seconds(self) -> float:
        return self._refresh_margin_seconds

    def _now(self) -> datetime:
        return _normalize_datetime(self._clock())

    def _needs_refresh_locked(self) -> bool:
        expires_at = self._access_token_expires_at
        if expires_at is None:
            return False
        return self._now() + timedelta(seconds=self._refresh_margin_seconds) >= expires_at

    async def _refresh_locked(self) -> TokenInfo:
        if _ASYNC_NOTIFYING.get():
            raise TokenManagerError(_REENTRANT_REFRESH_ERROR)
        if self._refresh_token is None or self._refresh_handler is None:
            raise TokenManagerError(
                "Cannot refresh the access token: no refresh token or refresh handler."
            )
        result = self._refresh_handler(self._refresh_token)
        info = await result if inspect.isawaitable(result) else result
        if not isinstance(info, TokenInfo) or not info.token:
            raise TokenManagerError("Refresh handler returned an empty access token.")
        self._access_token = info.token
        expires_at = try_parse_api_datetime(info.valid_until)
        if expires_at is not None and expires_at <= self._now():
            logger.warning(
                "Refreshed access token has a validity date in the past; "
                "switching to reactive refresh only."
            )
            expires_at = None
        self._access_token_expires_at = expires_at
        self._last_refresh_info = info
        return info

    async def _refresh_if_needed_locked(self) -> TokenInfo | None:
        if not self._needs_refresh_locked():
            return None
        if not self.can_refresh:
            return None
        return await self._refresh_locked()

    async def _notify(self, info: TokenInfo | None) -> None:
        if info is None or self._on_refresh is None:
            return
        # Keep persistence ordered while allowing requests to read the token.
        async with self._notification_lock:
            if info is self._last_refresh_info:
                marker = _ASYNC_NOTIFYING.set(True)
                try:
                    result = self._on_refresh(info)
                    if inspect.isawaitable(result):
                        await result
                finally:
                    _ASYNC_NOTIFYING.reset(marker)

    async def get_access_token(self) -> str:
        """Zwraca ważny token dostępowy, odświeżając go proaktywnie, gdy trzeba."""
        async with self._lock:
            info = await self._refresh_if_needed_locked()
            token = self._access_token
        await self._notify(info)
        return token

    def _is_access_token_current(self, token: str | None) -> bool:
        """Check atomically within the event loop, without awaiting a refresh."""
        if self._lock.locked():
            return False
        return token == self._access_token and (
            not self.can_refresh
            or self._access_token_expires_at is None
            or self._access_token_expires_at > self._now()
        )

    async def force_refresh(self, *, stale_token: str | None = None) -> str:
        """Wymusza odświeżenie tokena po 401 (z deduplikacją po ``stale_token``)."""
        async with self._lock:
            if stale_token is not None and stale_token != self._access_token:
                return self._access_token
            info = await self._refresh_locked()
            token = self._access_token
        await self._notify(info)
        return token

    def snapshot(self) -> TokenSnapshot:
        """Bezpieczny widok stanu (bez wartości tokenów)."""
        return TokenSnapshot(
            has_refresh_token=self._refresh_token is not None,
            access_token_expires_at=self._access_token_expires_at,
            refresh_margin_seconds=self._refresh_margin_seconds,
        )

    def __repr__(self) -> str:
        return (
            "AsyncTokenManager(access_token=<redacted>, "
            f"refresh_token={'<redacted>' if self._refresh_token else None}, "
            f"access_token_expires_at={self._access_token_expires_at!r})"
        )


class TokenRefreshingHttpClient(BaseHttpClient):
    """Klient HTTP wstrzykujący token z :class:`TokenManager` (sync).

    Gdy wołający poda jawny ``access_token``/``refresh_token`` albo ustawi
    ``skip_auth``, żądanie idzie dotychczasową ścieżką — manager nie jest
    konsultowany. Odpowiedź 401 na token z managera powoduje jednorazowe
    odświeżenie i powtórzenie żądania.

    Token jest pobierany w ``_request_once``, aby każda próba pętli retry
    sprawdzała jego ważność także po długim ``Retry-After``.
    """

    def __init__(self, options: KsefClientOptions, token_manager: TokenManager) -> None:
        super().__init__(options)
        self._token_manager = token_manager
        self._request_token: contextvars.ContextVar[str | None] = contextvars.ContextVar(
            "ksef_wire_token", default=None
        )

    @property
    def token_manager(self) -> TokenManager:
        """Manager, z którego klient pobiera token (do weryfikacji spójności)."""
        return self._token_manager

    def _resolve_request_token(
        self,
        *,
        access_token: str | None,
        refresh_token: str | None,
        skip_auth: bool,
    ) -> str | None:
        if skip_auth or access_token is not None or refresh_token is not None:
            return super()._resolve_request_token(
                access_token=access_token, refresh_token=refresh_token, skip_auth=skip_auth
            )
        # A proactive refresh can perform its own HTTP. A failure from that
        # request must not be mistaken for a 401 from this business request.
        self._request_token.set(None)
        token = self._token_manager.get_access_token()
        self._request_token.set(token)
        return token

    def _request_token_is_current(
        self,
        token: str | None,
        *,
        access_token: str | None,
        refresh_token: str | None,
        skip_auth: bool,
    ) -> bool:
        if skip_auth or access_token is not None or refresh_token is not None:
            return True
        return self._token_manager._is_access_token_current(token)

    def _request_once(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> HttpResponse:
        if skip_auth or access_token is not None or refresh_token is not None:
            return super()._request_once(
                method,
                path,
                params=params,
                headers=headers,
                json=json,
                data=data,
                access_token=access_token,
                refresh_token=refresh_token,
                skip_auth=skip_auth,
                expected_status=expected_status,
            )

        marker = self._request_token.set(None)
        try:
            try:
                return super()._request_once(
                    method,
                    path,
                    params=params,
                    headers=headers,
                    json=json,
                    data=data,
                    skip_auth=skip_auth,
                    expected_status=expected_status,
                )
            except KsefHttpError as exc:
                if (
                    exc.status_code != 401
                    or self._request_token.get() is None
                    or not self._token_manager.can_refresh
                ):
                    raise
                self._token_manager.force_refresh(stale_token=self._request_token.get())
                # The second admission may wait too. Sample the current token
                # after that wait instead of holding the just-refreshed value.
                return super()._request_once(
                    method,
                    path,
                    params=params,
                    headers=headers,
                    json=json,
                    data=data,
                    skip_auth=skip_auth,
                    expected_status=expected_status,
                )
        finally:
            self._request_token.reset(marker)


class AsyncTokenRefreshingHttpClient(AsyncBaseHttpClient):
    """Asynchroniczny odpowiednik :class:`TokenRefreshingHttpClient`."""

    def __init__(self, options: KsefClientOptions, token_manager: AsyncTokenManager) -> None:
        super().__init__(options)
        self._token_manager = token_manager
        self._request_token: contextvars.ContextVar[str | None] = contextvars.ContextVar(
            "ksef_wire_token", default=None
        )

    @property
    def token_manager(self) -> AsyncTokenManager:
        """Manager, z którego klient pobiera token (do weryfikacji spójności)."""
        return self._token_manager

    async def _resolve_request_token(
        self,
        *,
        access_token: str | None,
        refresh_token: str | None,
        skip_auth: bool,
    ) -> str | None:
        if skip_auth or access_token is not None or refresh_token is not None:
            return await super()._resolve_request_token(
                access_token=access_token, refresh_token=refresh_token, skip_auth=skip_auth
            )
        self._request_token.set(None)
        token = await self._token_manager.get_access_token()
        self._request_token.set(token)
        return token

    async def _request_token_is_current(
        self,
        token: str | None,
        *,
        access_token: str | None,
        refresh_token: str | None,
        skip_auth: bool,
    ) -> bool:
        if skip_auth or access_token is not None or refresh_token is not None:
            return True
        return self._token_manager._is_access_token_current(token)

    async def _request_once(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> HttpResponse:
        if skip_auth or access_token is not None or refresh_token is not None:
            return await super()._request_once(
                method,
                path,
                params=params,
                headers=headers,
                json=json,
                data=data,
                access_token=access_token,
                refresh_token=refresh_token,
                skip_auth=skip_auth,
                expected_status=expected_status,
            )

        marker = self._request_token.set(None)
        try:
            try:
                return await super()._request_once(
                    method,
                    path,
                    params=params,
                    headers=headers,
                    json=json,
                    data=data,
                    skip_auth=skip_auth,
                    expected_status=expected_status,
                )
            except KsefHttpError as exc:
                if (
                    exc.status_code != 401
                    or self._request_token.get() is None
                    or not self._token_manager.can_refresh
                ):
                    raise
                await self._token_manager.force_refresh(stale_token=self._request_token.get())
                # The second admission may wait too. Sample the current token
                # after that wait instead of holding the just-refreshed value.
                return await super()._request_once(
                    method,
                    path,
                    params=params,
                    headers=headers,
                    json=json,
                    data=data,
                    skip_auth=skip_auth,
                    expected_status=expected_status,
                )
        finally:
            self._request_token.reset(marker)


__all__ = [
    "DEFAULT_REFRESH_MARGIN_SECONDS",
    "AsyncTokenManager",
    "AsyncTokenRefreshingHttpClient",
    "TokenManager",
    "TokenManagerError",
    "TokenRefreshingHttpClient",
    "TokenSnapshot",
]
