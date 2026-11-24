from __future__ import annotations

import io
import urllib.error
import urllib.request
from email.message import Message
from typing import Any

import pytest

from dva.contracts.intelligence import ProviderError
from dva.intelligence.http import NotFoundError, UrllibTransport, _NoRedirects


class FakeResponse(io.BytesIO):
    def __init__(self, data: bytes, status: int = 200) -> None:
        super().__init__(data)
        self.status = status

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class FakeOpener:
    """Plays back a list of outcomes: bytes for a 200 response, or an exception."""

    def __init__(self, *outcomes: bytes | BaseException) -> None:
        self.outcomes = list(outcomes)
        self.requests: list[urllib.request.Request] = []
        self.timeouts: list[float] = []

    def open(self, request: urllib.request.Request, timeout: float) -> FakeResponse:
        self.requests.append(request)
        self.timeouts.append(timeout)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return FakeResponse(outcome)


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x", code, "error", Message(), None)


def transport(opener: FakeOpener, **kwargs: Any) -> tuple[UrllibTransport, list[float]]:
    sleeps: list[float] = []
    client = UrllibTransport(sleep=sleeps.append, **kwargs)
    client._opener = opener  # type: ignore[assignment]
    return client, sleeps


def test_successful_request_sends_identifying_but_anonymous_headers() -> None:
    opener = FakeOpener(b'{"ok": true}')
    client, _ = transport(opener, timeout=12)
    assert client.request("POST", "https://api.example/x", b"{}") == b'{"ok": true}'
    request = opener.requests[0]
    assert request.get_method() == "POST"
    assert request.get_header("User-agent", "").startswith("DVA/")
    assert request.get_header("Content-type") == "application/json"
    assert opener.timeouts == [12]


@pytest.mark.parametrize("url", ["http://api.example/x", "file:///etc/passwd", "ftp://x/y"])
def test_only_https_is_allowed(url: str) -> None:
    opener = FakeOpener()
    client, _ = transport(opener)
    with pytest.raises(ProviderError):
        client.request("GET", url)
    assert opener.requests == []


def test_server_errors_and_rate_limits_are_retried_with_backoff() -> None:
    opener = FakeOpener(http_error(503), http_error(429), b"done")
    client, sleeps = transport(opener, attempts=3, backoff=0.5)
    assert client.request("GET", "https://api.example/x") == b"done"
    assert sleeps == [0.5, 1.0]


def test_retries_are_bounded() -> None:
    opener = FakeOpener(http_error(500), urllib.error.URLError(OSError()), TimeoutError())
    client, sleeps = transport(opener, attempts=3)
    with pytest.raises(ProviderError) as error:
        client.request("GET", "https://api.example/x")
    assert "3 attempts" in str(error.value)
    assert len(opener.requests) == 3


def test_client_errors_are_not_retried() -> None:
    opener = FakeOpener(http_error(400))
    client, sleeps = transport(opener)
    with pytest.raises(ProviderError):
        client.request("GET", "https://api.example/x")
    assert sleeps == []
    with pytest.raises(NotFoundError):
        transport(FakeOpener(http_error(404)))[0].request("GET", "https://api.example/x")


def test_redirects_are_refused() -> None:
    with pytest.raises(ProviderError):
        transport(FakeOpener(http_error(302)))[0].request("GET", "https://api.example/x")


def test_the_real_opener_does_not_follow_redirects() -> None:
    handlers = vars(UrllibTransport()._opener)["handlers"]
    assert any(isinstance(h, _NoRedirects) for h in handlers)
    request = urllib.request.Request("https://api.example/x")
    follow = _NoRedirects().redirect_request(
        request, io.BytesIO(), 302, "Found", Message(), "http://evil.example/"
    )
    assert follow is None


def test_oversized_responses_are_refused() -> None:
    client, _ = transport(FakeOpener(b"x" * 11), max_bytes=10)
    with pytest.raises(ProviderError):
        client.request("GET", "https://api.example/x")
    client, _ = transport(FakeOpener(b"x" * 10), max_bytes=10)
    assert client.request("GET", "https://api.example/x") == b"x" * 10
