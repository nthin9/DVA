"""Validation for project-relative paths stored in domain objects.

Domain objects never hold absolute paths: scan results may be exported, and
local paths are private user data. Paths are POSIX-style and relative to the
scanned project root.
"""

from __future__ import annotations

import posixpath
import re

_DRIVE = re.compile(r"^[A-Za-z]:")


def require_relative_path(value: str) -> str:
    """Return ``value`` if it is a normalized, relative POSIX path; raise otherwise."""
    if not value:
        raise ValueError("path must not be empty")
    if "\\" in value or "\x00" in value:
        raise ValueError(f"path must use '/' separators and no NUL bytes: {value!r}")
    if value.startswith("/") or _DRIVE.match(value):
        raise ValueError(f"path must be relative: {value!r}")
    if posixpath.normpath(value) != value or value == ".":
        raise ValueError(f"path must be normalized: {value!r}")
    if value == ".." or value.startswith("../"):
        raise ValueError(f"path must not escape the project root: {value!r}")
    return value
