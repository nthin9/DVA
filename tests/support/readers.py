"""In-memory file readers for adapter tests."""

from __future__ import annotations

from collections.abc import Mapping

from dva.contracts.files import FileAccessDeniedError


class MemoryReader:
    """Serves project files from a dict and records every path requested."""

    def __init__(self, files: Mapping[str, bytes | str] | None = None) -> None:
        self.files = {
            path: data.encode("utf-8") if isinstance(data, str) else data
            for path, data in (files or {}).items()
        }
        self.requested: list[str] = []

    def read(self, relative_path: str) -> bytes:
        self.requested.append(relative_path)
        try:
            return self.files[relative_path]
        except KeyError:
            raise FileAccessDeniedError("file is not available") from None
