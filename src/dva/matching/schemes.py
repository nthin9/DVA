"""Per-ecosystem rules for package names and versions.

Each supported ecosystem gets an explicit entry: how to tell whether two
package names refer to the same package, and how to turn a version string
into something that sorts correctly. Version strings are never compared as
plain text, since that would put ``1.10`` before ``1.9``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from dva.matching.semver import InvalidSemVerError, SemVer


class UnparsableVersionError(ValueError):
    """A version string that the ecosystem's rules can't interpret."""


@dataclass(frozen=True, slots=True)
class VersionScheme:
    """How one ecosystem names packages and orders versions."""

    name: str
    _normalize_name: Callable[[str], str]
    _parse: Callable[[str], Any]

    def same_package(self, a: str, b: str) -> bool:
        return self._normalize_name(a) == self._normalize_name(b)

    def key(self, version: str) -> Any:
        """A sortable key for ``version``; raises :class:`UnparsableVersionError`."""
        try:
            return self._parse(version)
        except (InvalidVersion, InvalidSemVerError, ValueError) as error:
            raise UnparsableVersionError(str(error)) from None


def _pep440(version: str) -> Version:
    return Version(version)


#: Python packages: PEP 503 name normalization and PEP 440 versions.
PYPI = VersionScheme("pep440", lambda name: str(canonicalize_name(name)), _pep440)
#: npm packages: exact names and Semantic Versioning 2.0.0.
NPM = VersionScheme("semver", lambda name: name, SemVer.parse)
#: SemVer with exact names, for ranges an advisory marks as ``SEMVER``.
SEMVER = NPM

_BY_ECOSYSTEM = {"pypi": PYPI, "npm": NPM}


def scheme_for(ecosystem: str) -> VersionScheme | None:
    """The rules for a DVA ecosystem identifier, or ``None`` if DVA has none."""
    return _BY_ECOSYSTEM.get(ecosystem)
