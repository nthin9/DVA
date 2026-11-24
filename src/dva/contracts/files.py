"""Root-confined, size-bounded read access to project files."""

from __future__ import annotations

from typing import Protocol


class FileAccessError(Exception):
    """A project file could not be read safely. Messages never contain absolute paths."""


class FileAccessDeniedError(FileAccessError):
    """The path escapes the project root, is a link, or is otherwise not allowed."""


class FileTooLargeError(FileAccessError):
    """The file exceeds the configured size limit."""


class ProjectFileReader(Protocol):
    """Reads files by project-relative POSIX path, confined to the project root."""

    def read(self, relative_path: str) -> bytes:
        """Return the file's bytes or raise :class:`FileAccessError`."""
        ...
