"""A small, defensive HTTPS client built on the standard library.

Every request has a timeout, every response has a size cap, only ``https://``
URLs are accepted, and redirects are refused, so a response can't send DVA to
some other host. Rate limiting and server errors are retried a bounded number
of times with growing pauses; anything else fails straight away. The
User-Agent names DVA and its version, and nothing about the user.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import IO, Protocol

from dva import __version__
from dva.contracts.intelligence import ProviderError

_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_BYTES = 32 * 1024 * 1024


class NotFoundError(ProviderError):
    """The server answered 404."""


class HttpTransport(Protocol):
    def request(self, method: str, url: str, body: bytes | None = None) -> bytes: ...


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> urllib.request.Request | None:
        """Never follow a redirect; urllib then reports it as an HTTP error."""
        return None


class UrllibTransport:
    def __init__(
        self,
        *,
        timeout: float = 30.0,
        max_bytes: int = _MAX_BYTES,
        attempts: int = 3,
        backoff: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._attempts = max(1, attempts)
        self._backoff = backoff
        self._sleep = sleep
        self._opener = urllib.request.build_opener(_NoRedirects())

    def request(self, method: str, url: str, body: bytes | None = None) -> bytes:
        if not url.startswith("https://"):
            raise ProviderError("refusing a non-HTTPS URL")
        headers = {"User-Agent": f"DVA/{__version__}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        last_error = "no attempt was made"
        for attempt in range(self._attempts):
            if attempt:
                self._sleep(self._backoff * (2 ** (attempt - 1)))
            # The scheme was checked above: only https:// URLs reach this point.
            request = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310
            try:
                with self._opener.open(request, timeout=self._timeout) as response:
                    status = response.status
                    if 300 <= status < 400:
                        raise ProviderError(f"unexpected redirect (HTTP {status})")
                    return self._read(response)
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    raise NotFoundError("not found (HTTP 404)") from None
                if error.code not in _RETRY_STATUSES:
                    raise ProviderError(f"request rejected (HTTP {error.code})") from None
                last_error = f"server busy or failing (HTTP {error.code})"
            except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
                reason = getattr(error, "reason", error)
                last_error = f"could not connect ({type(reason).__name__})"
        raise ProviderError(f"{last_error}; gave up after {self._attempts} attempts")

    def _read(self, response: IO[bytes]) -> bytes:
        data = response.read(self._max_bytes + 1)
        if len(data) > self._max_bytes:
            raise ProviderError("response is larger than the allowed size")
        return data
