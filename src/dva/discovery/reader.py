"""Root-confined, size-bounded file reader handed to adapters."""

from __future__ import annotations

import stat
from pathlib import Path

from dva.contracts.files import FileAccessDeniedError, FileAccessError, FileTooLargeError
from dva.domain.paths import require_relative_path


class BoundedFileReader:
    """Reads project files by relative POSIX path without leaving the project root.

    Every path component is checked: symlinks and Windows junctions are
    refused (not followed), as are colons (which would address NTFS alternate
    data streams) and anything that is not a regular file. Error messages
    contain only the relative path, never the absolute one.
    """

    def __init__(self, root: Path, max_file_bytes: int) -> None:
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")
        self._root = root.resolve(strict=True)
        self._max_file_bytes = max_file_bytes

    def read(self, relative_path: str) -> bytes:
        try:
            path = require_relative_path(relative_path)
        except ValueError as exc:
            raise FileAccessDeniedError(
                f"not a normalized project-relative path: {relative_path!r}"
            ) from exc
        if ":" in path:
            raise FileAccessDeniedError(f"path must not contain ':': {path!r}")

        target = self._root
        try:
            for part in path.split("/"):
                target = target / part
                if target.is_symlink() or target.is_junction():
                    raise FileAccessDeniedError(f"refusing to follow a link: {path!r}")
            info = target.lstat()
        except FileNotFoundError as exc:
            raise FileAccessError(f"file not found: {path!r}") from exc
        except OSError as exc:
            raise FileAccessError(f"cannot access {path!r}: {exc.strerror or 'error'}") from exc

        if not stat.S_ISREG(info.st_mode):
            raise FileAccessDeniedError(f"not a regular file: {path!r}")
        if info.st_size > self._max_file_bytes:
            raise FileTooLargeError(
                f"{path!r} is {info.st_size} bytes, over the {self._max_file_bytes}-byte limit"
            )
        if not target.resolve().is_relative_to(self._root):
            raise FileAccessDeniedError(f"path resolves outside the project root: {path!r}")

        try:
            with target.open("rb") as handle:
                data = handle.read(self._max_file_bytes + 1)
        except OSError as exc:
            raise FileAccessError(f"cannot read {path!r}: {exc.strerror or 'error'}") from exc
        if len(data) > self._max_file_bytes:
            raise FileTooLargeError(f"{path!r} grew past the {self._max_file_bytes}-byte limit")
        return data
