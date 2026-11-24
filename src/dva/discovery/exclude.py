"""Paths the user asked discovery to skip.

A pattern is a project-relative path such as ``tests/fixtures`` (which skips
that folder and everything in it) or a glob such as ``examples/*/package.json``
or ``*/fixtures``, where ``*`` matches any characters including ``/``. Matching
ignores case, like the built-in folder exclusions. Patterns can't point
outside the project.
"""

from __future__ import annotations

from collections.abc import Iterable
from fnmatch import fnmatchcase

from dva.domain.paths import require_relative_path


def normalize_pattern(value: str) -> str:
    """The canonical form of a pattern; raises ``ValueError`` for an unusable one."""
    pattern = value.strip().replace("\\", "/")
    while pattern.startswith("./"):
        pattern = pattern[2:]
    pattern = pattern.rstrip("/")
    try:
        return require_relative_path(pattern)
    except ValueError:
        raise ValueError(
            f"{value!r} can't be excluded: give a path inside the project, such as tests/fixtures"
        ) from None


class ExcludeRules:
    """Decides whether a project-relative path was excluded by the user."""

    def __init__(self, patterns: Iterable[str] = ()) -> None:
        normalized = dict.fromkeys(normalize_pattern(p) for p in patterns)
        self.patterns: tuple[str, ...] = tuple(normalized)
        self._folded = tuple(p.casefold() for p in self.patterns)

    def __bool__(self) -> bool:
        return bool(self.patterns)

    def matches(self, rel_path: str) -> bool:
        path = rel_path.casefold()
        return any(
            path == pattern or path.startswith(pattern + "/") or fnmatchcase(path, pattern)
            for pattern in self._folded
        )
