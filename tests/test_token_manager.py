from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import pytest

from ksef_client.models import (
    AuthenticationTokenRefreshResponse,
    AuthenticationTokensResponse,
    TokenInfo,
)
from ksef_client.token_manager import (
    AsyncTokenManager,
    TokenManager,
    TokenManagerError,
)

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
FAR_FUTURE = "2099-01-01T00:00:00+00:00"


def _recording_handler(
    calls: list[str],
    *,
    token: str = "new",
    valid_until: str | None = None,
) -> Callable[[str], TokenInfo]:
    def handler(refresh_token: str) -> TokenInfo:
        calls.append(refresh_token)
        return TokenInfo(token, valid_until)

    return handler


def _clock() -> datetime:
    return NOW


def _tokens(
    access_token: str = "access",
    refresh_token: str = "refresh",
    *,
    access_valid_until: str | None = "2026-10-22T13:00:00+00:00",
) -> AuthenticationTokensResponse:
    return AuthenticationTokensResponse(
        access_token=TokenInfo(access_token, access_valid_until),
        refresh_token=TokenInfo(refresh_token, "2026-12-31T00:00:00+00:00"),
    )


# --- konstrukcja ----------------------------------------------------------


@pytest.mark.parametrize("access_token", ["", "   ", None, 123])
def test_constructor_rejects_invalid_access_token(access_token: object) -> None:
    with pytest.raises(TokenManagerError):
        TokenManager(access_token)  # type: ignore[arg-type]


def test_constructor_rejects_non_string_refresh_token() -> None:
    with pytest.raises(TokenManagerError):
        TokenManager("token", 123)  # type: ignore[arg-type]


@pytest.mark.parametrize("margin", [-1, float("nan"), float("inf")])
def test_constructor_rejects_invalid_margin(margin: float) -> None:
    with pytest.raises(TokenManagerError):
        TokenManager("token", refresh_margin_seconds=margin)


@pytest.mark.parametrize("margin", [float("nan"), float("inf")])
def test_async_constructor_rejects_invalid_margin(margin: float) -> None:
    with pytest.raises(TokenManagerError):
        AsyncTokenManager("token", refresh_margin_seconds=margin)


def test_constructor_rejects_invalid_validity_string() -> None:
    with pytest.raises(TokenManagerError):
        TokenManager("token", access_token_valid_until="not-a-date")


def test_constructor_rejects_invalid_validity_type() -> None:
    with pytest.raises(TokenManagerError):
        TokenManager("token", access_token_valid_until=123)  # type: ignore[arg-type]


def test_constructor_accepts_naive_datetime_as_utc() -> None:
    manager = TokenManager("token", access_token_valid_until=datetime(2099, 1, 1))

    expires_at = manager.snapshot().access_token_expires_at
    assert expires_at is not None
    assert expires_at.tzinfo is timezone.utc


def test_from_tokens_extracts_state() -> None:
    manager = TokenManager.from_tokens(_tokens())

    snapshot = manager.snapshot()
    assert snapshot.has_refresh_token is True
    assert snapshot.access_token_expires_at == datetime(
        2026, 10, 22, 13, 0, tzinfo=timezone.utc
    )
    assert manager.can_refresh is False  # brak handlera do momentu bindu


def test_from_tokens_tolerates_invalid_validity() -> None:
    manager = TokenManager.from_tokens(_tokens(access_valid_until="garbage"))

    assert manager.snapshot().access_token_expires_at is None


def test_from_tokens_without_refresh_token() -> None:
    manager = TokenManager.from_tokens(_tokens(refresh_token=""))

    assert manager.snapshot().has_refresh_token is False
    assert manager.can_refresh is False


# --- proaktywny refresh ---------------------------------------------------


def test_get_access_token_returns_current_when_far_from_expiry() -> None:
    calls: list[str] = []
    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW + timedelta(hours=1),
        refresh_handler=_recording_handler(calls),
        clock=_clock,
    )

    assert manager.get_access_token() == "old"
    assert calls == []


def test_proactive_refresh_within_margin() -> None:
    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW + timedelta(seconds=30),
        refresh_margin_seconds=60,
        refresh_handler=lambda rt: TokenInfo("new", "2026-10-22T18:00:00+00:00"),
        clock=_clock,
    )

    assert manager.get_access_token() == "new"
    # nowy termin ważności jest dalej niż margines → kolejne wywołanie nie odświeża
    assert manager.get_access_token() == "new"


def test_proactive_refresh_when_token_already_expired() -> None:
    calls: list[str] = []
    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW - timedelta(minutes=5),
        refresh_handler=_recording_handler(calls),
        clock=_clock,
    )

    assert manager.get_access_token() == "new"
    assert calls == ["rt"]


def test_no_proactive_refresh_without_validity_information() -> None:
    calls: list[str] = []
    manager = TokenManager(
        "old",
        "rt",
        refresh_handler=_recording_handler(calls),
        clock=_clock,
    )

    assert manager.get_access_token() == "old"
    assert calls == []


def test_expired_token_without_refresh_capability_is_returned_stale() -> None:
    manager = TokenManager(
        "old",
        access_token_valid_until=NOW - timedelta(minutes=5),
        clock=_clock,
    )

    assert manager.get_access_token() == "old"
    assert manager.can_refresh is False


# --- force_refresh --------------------------------------------------------


def test_force_refresh_returns_new_token() -> None:
    manager = TokenManager(
        "old",
        "rt",
        refresh_handler=lambda rt: TokenInfo("fresh", None),
        clock=_clock,
    )

    assert manager.force_refresh() == "fresh"
    assert manager.get_access_token() == "fresh"


def test_force_refresh_dedupes_when_token_already_changed() -> None:
    calls: list[str] = []
    manager = TokenManager(
        "current",
        "rt",
        refresh_handler=_recording_handler(calls, token="unused"),
        clock=_clock,
    )

    assert manager.force_refresh(stale_token="stale-from-request") == "current"
    assert calls == []


def test_force_refresh_without_capability_raises() -> None:
    manager = TokenManager("token", clock=_clock)

    with pytest.raises(TokenManagerError):
        manager.force_refresh()


def test_refresh_handler_returning_empty_token_raises() -> None:
    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW - timedelta(minutes=5),
        refresh_handler=lambda rt: TokenInfo("", None),
        clock=_clock,
    )

    with pytest.raises(TokenManagerError):
        manager.get_access_token()


def test_refresh_returning_past_validity_switches_to_reactive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[str] = []
    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW - timedelta(minutes=5),
        refresh_handler=_recording_handler(calls, valid_until="2020-01-01T00:00:00+00:00"),
        clock=_clock,
    )

    assert manager.get_access_token() == "new"
    assert manager.snapshot().access_token_expires_at is None
    # bez daty ważności nie ma kolejnego proaktywnego refreshu
    assert manager.get_access_token() == "new"
    assert calls == ["rt"]
    assert "reactive refresh" in caplog.text


# --- on_refresh i bezpieczeństwo -----------------------------------------


def test_on_refresh_receives_new_token_info() -> None:
    received: list[TokenInfo] = []
    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW - timedelta(minutes=5),
        refresh_handler=lambda rt: TokenInfo("new", None),
        on_refresh=received.append,
        clock=_clock,
    )

    manager.get_access_token()

    assert [info.token for info in received] == ["new"]


def test_on_refresh_exception_propagates() -> None:
    def failing(_: TokenInfo) -> None:
        raise RuntimeError("persist failed")

    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW - timedelta(minutes=5),
        refresh_handler=lambda rt: TokenInfo("new", None),
        on_refresh=failing,
        clock=_clock,
    )

    with pytest.raises(RuntimeError, match="persist failed"):
        manager.get_access_token()


def test_repr_and_snapshot_do_not_leak_token_values() -> None:
    manager = TokenManager("secret-access", "secret-refresh", clock=_clock)

    text = repr(manager)

    assert "secret-access" not in text
    assert "secret-refresh" not in text
    assert "access_token=<redacted>" in text
    snapshot = manager.snapshot()
    assert not hasattr(snapshot, "access_token")
    assert not hasattr(snapshot, "refresh_token")


# --- bind_auth_client -----------------------------------------------------


class _FakeAuthClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def refresh_access_token(self, refresh_token: str) -> AuthenticationTokenRefreshResponse:
        self.calls.append(refresh_token)
        return AuthenticationTokenRefreshResponse(
            access_token=TokenInfo("fresh-from-endpoint", "2099-01-01T00:00:00+00:00")
        )


def test_bind_auth_client_uses_refresh_endpoint() -> None:
    auth_client = _FakeAuthClient()
    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW - timedelta(minutes=5),
        clock=_clock,
    )

    manager.bind_auth_client(auth_client)  # type: ignore[arg-type]

    assert manager.can_refresh is True
    assert manager.get_access_token() == "fresh-from-endpoint"
    assert auth_client.calls == ["rt"]


def test_rebinding_manager_uses_latest_auth_client() -> None:
    first = _FakeAuthClient()
    second = _FakeAuthClient()
    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW - timedelta(minutes=5),
        clock=_clock,
    )

    manager.bind_auth_client(first)  # type: ignore[arg-type]
    manager.bind_auth_client(second)  # type: ignore[arg-type]

    assert manager.get_access_token() == "fresh-from-endpoint"
    assert first.calls == []
    assert second.calls == ["rt"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"refresh_handler": "not-callable"},
        {"on_refresh": "not-callable"},
        {"clock": "not-callable"},
    ],
)
def test_constructor_rejects_non_callable_hooks(kwargs: dict[str, object]) -> None:
    with pytest.raises(TokenManagerError, match="must be callable"):
        TokenManager("token", **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"refresh_handler": "not-callable"},
        {"on_refresh": "not-callable"},
        {"clock": "not-callable"},
    ],
)
def test_async_constructor_rejects_non_callable_hooks(kwargs: dict[str, object]) -> None:
    with pytest.raises(TokenManagerError, match="must be callable"):
        AsyncTokenManager("token", **kwargs)  # type: ignore[arg-type]


def test_bind_auth_client_does_not_override_custom_handler() -> None:
    auth_client = _FakeAuthClient()
    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW - timedelta(minutes=5),
        refresh_handler=lambda rt: TokenInfo("custom", None),
        clock=_clock,
    )

    manager.bind_auth_client(auth_client)  # type: ignore[arg-type]
    manager.get_access_token()

    assert auth_client.calls == []


# --- współbieżność --------------------------------------------------------


def test_concurrent_requests_share_one_refresh() -> None:
    calls: list[str] = []

    def handler(refresh_token: str) -> TokenInfo:
        calls.append(refresh_token)
        time.sleep(0.05)  # trzyma lock, żeby drugi wątek na niego poczekał
        return TokenInfo("new", "2099-01-01T00:00:00+00:00")

    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW - timedelta(minutes=5),
        refresh_handler=handler,
        clock=_clock,
    )
    barrier = threading.Barrier(2)
    results: list[str] = []

    def worker() -> None:
        barrier.wait()
        results.append(manager.get_access_token())

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert calls == ["rt"]
    assert results == ["new", "new"]


# --- AsyncTokenManager ----------------------------------------------------


def test_async_manager_proactive_refresh_and_dedupe() -> None:
    async def scenario() -> None:
        calls: list[str] = []

        async def handler(refresh_token: str) -> TokenInfo:
            calls.append(refresh_token)
            await asyncio.sleep(0.01)
            return TokenInfo("new", "2099-01-01T00:00:00+00:00")

        manager = AsyncTokenManager(
            "old",
            "rt",
            access_token_valid_until=NOW - timedelta(minutes=5),
            refresh_handler=handler,
            clock=_clock,
        )

        results = await asyncio.gather(manager.get_access_token(), manager.get_access_token())

        assert results == ["new", "new"]
        assert calls == ["rt"]

    asyncio.run(scenario())


def test_async_manager_force_refresh_and_dedupe() -> None:
    async def scenario() -> None:
        calls: list[str] = []

        async def handler(refresh_token: str) -> TokenInfo:
            calls.append(refresh_token)
            return TokenInfo("fresh", None)

        manager = AsyncTokenManager("old", "rt", refresh_handler=handler, clock=_clock)

        assert await manager.force_refresh() == "fresh"
        assert await manager.force_refresh(stale_token="old") == "fresh"
        assert calls == ["rt"]

    asyncio.run(scenario())


def test_async_manager_without_refresh_returns_stale_and_force_raises() -> None:
    async def scenario() -> None:
        manager = AsyncTokenManager(
            "old",
            access_token_valid_until=NOW - timedelta(minutes=5),
            clock=_clock,
        )

        assert await manager.get_access_token() == "old"
        with pytest.raises(TokenManagerError):
            await manager.force_refresh()

    asyncio.run(scenario())


def test_async_manager_on_refresh_supports_sync_and_async_callbacks() -> None:
    async def scenario() -> None:
        received: list[str] = []

        def sync_callback(info: TokenInfo) -> None:
            received.append(info.token)

        async def async_callback(info: TokenInfo) -> None:
            received.append(f"async:{info.token}")

        async def handler(refresh_token: str) -> TokenInfo:
            return TokenInfo("new", None)

        sync_manager = AsyncTokenManager(
            "old", "rt", refresh_margin_seconds=0, refresh_handler=handler,
            on_refresh=sync_callback, clock=_clock,
        )
        await sync_manager.force_refresh()

        async_manager = AsyncTokenManager(
            "old", "rt", refresh_handler=handler, on_refresh=async_callback, clock=_clock
        )
        await async_manager.force_refresh()

        assert received == ["new", "async:new"]

    asyncio.run(scenario())


def test_async_manager_tolerates_invalid_validity_from_api() -> None:
    async def scenario() -> None:
        manager = AsyncTokenManager.from_tokens(
            _tokens(access_valid_until="garbage"), clock=_clock
        )

        assert manager.snapshot().access_token_expires_at is None

    asyncio.run(scenario())


def test_async_manager_repr_redacts_tokens() -> None:
    async def scenario() -> None:
        manager = AsyncTokenManager("secret-access", "secret-refresh", clock=_clock)

        text = repr(manager)

        assert "secret-access" not in text
        assert "secret-refresh" not in text

    asyncio.run(scenario())

# --- uzupełnienie pokrycia: walidacje async i ścieżki brzegowe ------------


def test_constructor_accepts_valid_string_validity() -> None:
    manager = TokenManager("token", access_token_valid_until="2099-01-01T00:00:00+00:00")

    assert manager.snapshot().access_token_expires_at == datetime(
        2099, 1, 1, tzinfo=timezone.utc
    )
    assert manager.refresh_margin_seconds == 60.0


@pytest.mark.parametrize("access_token", ["", "   ", None, 123])
def test_async_constructor_rejects_invalid_access_token(access_token: object) -> None:
    with pytest.raises(TokenManagerError):
        AsyncTokenManager(access_token)  # type: ignore[arg-type]


def test_async_constructor_rejects_invalid_parameters() -> None:
    with pytest.raises(TokenManagerError):
        AsyncTokenManager("token", 123)  # type: ignore[arg-type]
    with pytest.raises(TokenManagerError):
        AsyncTokenManager("token", refresh_margin_seconds=-1)
    with pytest.raises(TokenManagerError):
        AsyncTokenManager("token", access_token_valid_until="not-a-date")
    with pytest.raises(TokenManagerError):
        AsyncTokenManager("token", access_token_valid_until=123)  # type: ignore[arg-type]


class _FakeAsyncAuthClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def refresh_access_token(self, refresh_token: str) -> AuthenticationTokenRefreshResponse:
        self.calls.append(refresh_token)
        return AuthenticationTokenRefreshResponse(access_token=TokenInfo("fresh", FAR_FUTURE))


def test_async_rebinding_manager_uses_latest_auth_client() -> None:
    async def scenario() -> None:
        first = _FakeAsyncAuthClient()
        second = _FakeAsyncAuthClient()
        manager = AsyncTokenManager(
            "old",
            "rt",
            access_token_valid_until=NOW - timedelta(minutes=5),
            clock=_clock,
        )

        manager.bind_auth_client(first)  # type: ignore[arg-type]
        manager.bind_auth_client(second)  # type: ignore[arg-type]

        assert await manager.get_access_token() == "fresh"
        assert first.calls == []
        assert second.calls == ["rt"]

    asyncio.run(scenario())


def test_async_bind_auth_client_uses_refresh_endpoint() -> None:
    async def scenario() -> None:
        auth_client = _FakeAsyncAuthClient()
        manager = AsyncTokenManager(
            "old",
            "rt",
            access_token_valid_until=NOW - timedelta(minutes=5),
            clock=_clock,
        )

        manager.bind_auth_client(auth_client)  # type: ignore[arg-type]

        assert manager.can_refresh is True
        assert manager.refresh_margin_seconds == 60.0
        assert await manager.get_access_token() == "fresh"
        assert auth_client.calls == ["rt"]
        # bind nie nadpisuje własnego handlera
        manager.bind_auth_client(auth_client)  # type: ignore[arg-type]
        assert auth_client.calls == ["rt"]

    asyncio.run(scenario())


def test_async_refresh_handler_returning_empty_token_raises() -> None:
    async def scenario() -> None:
        async def handler(refresh_token: str) -> TokenInfo:
            return TokenInfo("", None)

        manager = AsyncTokenManager(
            "old",
            "rt",
            access_token_valid_until=NOW - timedelta(minutes=5),
            refresh_handler=handler,
            clock=_clock,
        )

        with pytest.raises(TokenManagerError):
            await manager.get_access_token()

    asyncio.run(scenario())


def test_async_refresh_returning_past_validity_switches_to_reactive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        calls: list[str] = []

        async def handler(refresh_token: str) -> TokenInfo:
            calls.append(refresh_token)
            return TokenInfo("new", "2020-01-01T00:00:00+00:00")

        manager = AsyncTokenManager(
            "old",
            "rt",
            access_token_valid_until=NOW - timedelta(minutes=5),
            refresh_handler=handler,
            clock=_clock,
        )

        assert await manager.get_access_token() == "new"
        assert manager.snapshot().access_token_expires_at is None
        assert await manager.get_access_token() == "new"
        assert calls == ["rt"]

    asyncio.run(scenario())
    assert "reactive refresh" in caplog.text


def test_sync_manager_rejects_async_refresh_handler() -> None:
    async def handler(refresh_token: str) -> TokenInfo:
        return TokenInfo("new", None)

    manager = TokenManager(
        "old",
        "rt",
        access_token_valid_until=NOW - timedelta(minutes=5),
        refresh_handler=handler,  # type: ignore[arg-type]
        clock=_clock,
    )

    with pytest.raises(TokenManagerError, match="AsyncTokenManager"):
        manager.get_access_token()


def test_async_manager_accepts_sync_refresh_handler() -> None:
    async def scenario() -> None:
        manager = AsyncTokenManager(
            "old",
            "rt",
            refresh_handler=lambda rt: TokenInfo("fresh", None),
            clock=_clock,
        )

        assert await manager.force_refresh() == "fresh"

    asyncio.run(scenario())


@pytest.mark.parametrize("delay_before_callback", [False, True])
def test_concurrent_refresh_callbacks_cannot_overwrite_newer_token(
    delay_before_callback: bool,
) -> None:
    from concurrent.futures import ThreadPoolExecutor

    first_started = threading.Event()
    release_first = threading.Event()
    second_refreshed = threading.Event()
    saved: list[str] = []
    refreshes = 0

    def handler(_: str) -> TokenInfo:
        nonlocal refreshes
        refreshes += 1
        if refreshes == 2:
            second_refreshed.set()
        return TokenInfo(f"token-{refreshes}", FAR_FUTURE)

    def persist(info: TokenInfo) -> None:
        if info.token == "token-1" and not delay_before_callback:
            first_started.set()
            assert release_first.wait(5)
        saved.append(info.token)

    manager = TokenManager("initial", "rt", refresh_handler=handler, on_refresh=persist)
    notify = manager._notify

    def delayed_notify(info: TokenInfo | None) -> None:
        if info is not None and info.token == "token-1" and delay_before_callback:
            first_started.set()
            assert release_first.wait(5)
        notify(info)

    manager._notify = delayed_notify  # type: ignore[method-assign]
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(manager.force_refresh)
        try:
            assert first_started.wait(5)
            second = executor.submit(manager.force_refresh)
            assert second_refreshed.wait(5)
            if delay_before_callback:
                assert second.result(timeout=5) == "token-2"
        finally:
            release_first.set()
        assert first.result(timeout=5) == "token-1"
        assert second.result(timeout=5) == "token-2"

    assert saved == (["token-2"] if delay_before_callback else ["token-1", "token-2"])
    assert manager.get_access_token() == saved[-1] == "token-2"


@pytest.mark.parametrize("delay_before_callback", [False, True])
def test_async_refresh_callbacks_cannot_overwrite_newer_token(
    delay_before_callback: bool,
) -> None:
    async def scenario() -> None:
        first_started = asyncio.Event()
        release_first = asyncio.Event()
        second_refreshed = asyncio.Event()
        saved: list[str] = []
        refreshes = 0

        async def handler(_: str) -> TokenInfo:
            nonlocal refreshes
            refreshes += 1
            if refreshes == 2:
                second_refreshed.set()
            return TokenInfo(f"token-{refreshes}", FAR_FUTURE)

        async def persist(info: TokenInfo) -> None:
            if info.token == "token-1" and not delay_before_callback:
                first_started.set()
                await release_first.wait()
            saved.append(info.token)

        manager = AsyncTokenManager("initial", "rt", refresh_handler=handler, on_refresh=persist)
        notify = manager._notify

        async def delayed_notify(info: TokenInfo | None) -> None:
            if info is not None and info.token == "token-1" and delay_before_callback:
                first_started.set()
                await release_first.wait()
            await notify(info)

        manager._notify = delayed_notify  # type: ignore[method-assign]
        first = asyncio.create_task(manager.force_refresh())
        try:
            await first_started.wait()
            second = asyncio.create_task(manager.force_refresh())
            await second_refreshed.wait()
            if delay_before_callback:
                assert await second == "token-2"
        finally:
            release_first.set()
        assert await first == "token-1"
        assert await second == "token-2"
        assert saved == (["token-2"] if delay_before_callback else ["token-1", "token-2"])
        assert await manager.get_access_token() == saved[-1] == "token-2"

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))
