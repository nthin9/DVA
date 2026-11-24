"""Python package names and identities."""

from __future__ import annotations

from urllib.parse import quote

from packaging.utils import canonicalize_name

from dva.domain.identity import PackageIdentity

ECOSYSTEM = "pypi"


def canonical(name: str) -> str:
    """The normalized form of a project name (lowercase, runs of ``-_.`` become ``-``)."""
    return str(canonicalize_name(name))


def identity(name: str) -> PackageIdentity:
    """Identity for a PyPI project, using its normalized name and Package URL."""
    normalized = canonical(name)
    return PackageIdentity(ECOSYSTEM, normalized, purl=f"pkg:pypi/{quote(normalized)}")
