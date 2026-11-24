"""Semantic Versioning 2.0.0 versions and their ordering.

This covers exact versions only (``1.2.3-beta.1+build.5``), which is what
npm lockfiles record and what OSV's ``SEMVER`` ranges use. npm's range syntax
(``^1.2``, ``~1``, ``>=1 <2``) is a different thing and isn't needed here,
because DVA only checks exact installed versions against advisories.

Ordering follows section 11 of the specification: compare major, minor and
patch numerically; a pre-release sorts before the release; pre-release
identifiers compare one by one, numbers numerically and below text; a longer
list of identifiers wins when all earlier ones are equal; build metadata is
ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The regular expression recommended by the specification (semver.org).
_SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

#: A pre-release identifier: (0, number) for numeric ones, (1, text) otherwise,
#: so numbers sort before text and compare numerically.
type _Identifier = tuple[int, int] | tuple[int, str]
type _PreKey = tuple[int | _Identifier, ...]


class InvalidSemVerError(ValueError):
    """The text is not a Semantic Versioning 2.0.0 version."""


@dataclass(frozen=True, slots=True, order=True)
class SemVer:
    major: int
    minor: int
    patch: int
    #: (1,) for a release, (0, *identifiers) for a pre-release, so releases
    #: sort after every pre-release of the same version.
    _pre: _PreKey

    @classmethod
    def parse(cls, text: str) -> SemVer:
        # Some tools write a leading "v"; npm drops it, so DVA does too.
        candidate = text[1:] if text.startswith(("v", "=")) else text
        match = _SEMVER.match(candidate)
        if match is None:
            raise InvalidSemVerError(f"not a semantic version: {text[:40]!r}")
        major, minor, patch, pre, _build = match.groups()
        if pre is None:
            key: _PreKey = (1,)
        else:
            key = (0, *(_identifier(part) for part in pre.split(".")))
        return cls(int(major), int(minor), int(patch), key)


def _identifier(part: str) -> _Identifier:
    return (0, int(part)) if part.isdigit() else (1, part)
