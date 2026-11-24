"""npm package names and identities."""

from __future__ import annotations

import re
from urllib.parse import quote

from dva.domain.identity import PackageIdentity

ECOSYSTEM = "npm"

#: npm's limit on package name length.
_MAX_NAME_LENGTH = 214
_PART = re.compile(r"^[A-Za-z0-9._~-][A-Za-z0-9._~-]*$")


def is_valid_name(name: str) -> bool:
    """Whether ``name`` is a plausible npm package name (``pkg`` or ``@scope/pkg``).

    Older packages may contain capital letters, so those are accepted; spaces,
    path tricks and anything outside URL-safe characters are not.
    """
    if not name or len(name) > _MAX_NAME_LENGTH or name.startswith((".", "_")):
        return False
    if name.startswith("@"):
        scope, slash, rest = name[1:].partition("/")
        return bool(slash) and bool(_PART.match(scope)) and bool(_PART.match(rest))
    return bool(_PART.match(name))


def identity(name: str, *, from_registry: bool = True) -> PackageIdentity:
    """Identity for an npm package; the scope (``@babel``) becomes the namespace.

    A ``pkg:npm`` Package URL is only set for packages from a registry.
    """
    namespace: str | None = None
    local = name
    if name.startswith("@") and "/" in name:
        namespace, local = name.split("/", 1)
    purl = None
    if from_registry:
        path = f"{quote(namespace)}/{quote(local)}" if namespace else quote(local)
        purl = f"pkg:npm/{path}"
    return PackageIdentity(ECOSYSTEM, local, namespace=namespace, purl=purl)
