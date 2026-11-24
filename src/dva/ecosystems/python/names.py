"""Python package names and identities."""

from __future__ import annotations

from urllib.parse import quote, urlsplit

from packaging.utils import canonicalize_name

from dva.domain.identity import PackageIdentity

ECOSYSTEM = "pypi"


def canonical(name: str) -> str:
    """The normalized form of a project name (lowercase, runs of ``-_.`` become ``-``)."""
    return str(canonicalize_name(name))


#: Hosts of the public Python Package Index. Any other index may be private.
PUBLIC_INDEX_HOSTS = frozenset({"pypi.org", "pypi.python.org", "files.pythonhosted.org"})


def is_public_index(url: str) -> bool:
    """Whether a package index URL points at PyPI itself."""
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return False
    return (host or "").lower() in PUBLIC_INDEX_HOSTS


def identity(name: str, *, from_registry: bool = True) -> PackageIdentity:
    """Identity for a Python project, using its normalized name.

    A ``pkg:pypi`` Package URL says the package comes from PyPI, so it is only
    set for packages from a registry, not for ones built from git, a URL or a
    local path.
    """
    normalized = canonical(name)
    purl = f"pkg:pypi/{quote(normalized)}" if from_registry else None
    return PackageIdentity(ECOSYSTEM, normalized, purl=purl)
