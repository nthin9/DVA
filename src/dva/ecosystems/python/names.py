"""Python package names and identities."""

from __future__ import annotations

from urllib.parse import quote

from packaging.utils import canonicalize_name

from dva.domain.identity import PackageIdentity

ECOSYSTEM = "pypi"


def canonical(name: str) -> str:
    """The normalized form of a project name (lowercase, runs of ``-_.`` become ``-``)."""
    return str(canonicalize_name(name))


def identity(name: str, *, from_registry: bool = True) -> PackageIdentity:
    """Identity for a Python project, using its normalized name.

    A ``pkg:pypi`` Package URL says the package comes from PyPI, so it is only
    set for packages from a registry, not for ones built from git, a URL or a
    local path.
    """
    normalized = canonical(name)
    purl = f"pkg:pypi/{quote(normalized)}" if from_registry else None
    return PackageIdentity(ECOSYSTEM, normalized, purl=purl)
