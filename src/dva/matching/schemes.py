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

from packaging.specifiers import InvalidSpecifier, SpecifierSet
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
    _exact: Callable[[str], str | None]

    def same_package(self, a: str, b: str) -> bool:
        return self._normalize_name(a) == self._normalize_name(b)

    def normalize_name(self, name: str) -> str:
        """The ecosystem's normalized spelling of a package name."""
        return self._normalize_name(name)

    def exact_version(self, constraint: str) -> str | None:
        """The single version ``constraint`` pins, or ``None`` if it allows more than one."""
        return self._exact(constraint.strip())

    def key(self, version: str) -> Any:
        """A sortable key for ``version``; raises :class:`UnparsableVersionError`."""
        try:
            return self._parse(version)
        except (InvalidVersion, InvalidSemVerError, ValueError) as error:
            raise UnparsableVersionError(str(error)) from None


def _pep440(version: str) -> Version:
    return Version(version)


def _pep440_exact(constraint: str) -> str | None:
    """``==2.31.0`` pins one version; ``==2.*``, ``>=2`` or ``==2.0, !=2.0.1`` don't."""
    try:
        specifiers = list(SpecifierSet(constraint))
    except InvalidSpecifier:
        return None
    if len(specifiers) != 1:
        return None
    (specifier,) = specifiers
    if specifier.operator != "==" or specifier.version.endswith(".*"):
        return None
    try:
        Version(specifier.version)
    except InvalidVersion:
        return None
    return specifier.version


def _semver_exact(constraint: str) -> str | None:
    """npm pins one version with a bare version (``1.2.3``) or ``=1.2.3``."""
    candidate = constraint[1:] if constraint.startswith("=") else constraint
    try:
        SemVer.parse(candidate)
    except InvalidSemVerError:
        return None
    return candidate.removeprefix("v")


#: Python packages: PEP 503 name normalization and PEP 440 versions.
PYPI = VersionScheme("pep440", lambda name: str(canonicalize_name(name)), _pep440, _pep440_exact)
#: npm packages: exact names and Semantic Versioning 2.0.0.
NPM = VersionScheme("semver", lambda name: name, SemVer.parse, _semver_exact)
#: SemVer with exact names, for ranges an advisory marks as ``SEMVER``.
SEMVER = NPM

_BY_ECOSYSTEM = {"pypi": PYPI, "npm": NPM}


def known_ecosystems() -> tuple[str, ...]:
    """The DVA ecosystem identifiers that have version rules."""
    return tuple(_BY_ECOSYSTEM)


def scheme_for(ecosystem: str) -> VersionScheme | None:
    """The rules for a DVA ecosystem identifier, or ``None`` if DVA has none."""
    return _BY_ECOSYSTEM.get(ecosystem)
