"""Classifying the version specs written in ``package.json``.

npm accepts much more than version ranges as a dependency's value: aliases
(``npm:other@^1``), git repositories (``git+https://...``, ``github:user/repo``
or just ``user/repo``), tarball URLs, local paths (``file:``), links, and the
``workspace:`` protocol used by Yarn and pnpm. Only registry ranges can be
looked up in a vulnerability database, so each spec is tagged with its source.
The spec text itself is kept as written, minus any credentials in a URL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from dva.domain.dependency import SourceKind
from dva.ecosystems.npm.names import is_valid_name
from dva.ecosystems.text import redact_url

_GIT_PREFIXES = ("git+", "git://", "github:", "gitlab:", "bitbucket:", "gist:")
_PATH_PREFIXES = ("file:", "link:", "./", "../", "/", "~/", ".\\", "..\\")
_GITHUB_SHORTHAND = re.compile(r"^[A-Za-z0-9][\w.-]*/[\w.-]+(?:#\S*)?$")


@dataclass(frozen=True, slots=True)
class Spec:
    source: SourceKind
    #: The registry package actually installed, when it differs (aliases).
    target_name: str | None
    constraint: str | None


class InvalidSpecError(ValueError):
    """The spec cannot be understood. The message is safe to show."""


def classify(spec: str) -> Spec:
    text = spec.strip()
    if not text:
        # npm reads an empty spec as "any version".
        return Spec(SourceKind.REGISTRY, None, None)
    if text.startswith("npm:"):
        return _alias(text[4:])
    lowered = text.lower()
    if lowered.startswith(_GIT_PREFIXES) or _GITHUB_SHORTHAND.match(text):
        return Spec(SourceKind.GIT, None, redact_url(text))
    if lowered.startswith(("http://", "https://")):
        return Spec(SourceKind.URL, None, redact_url(text))
    if lowered.startswith(_PATH_PREFIXES) or re.match(r"^[A-Za-z]:[\\/]", text):
        return Spec(SourceKind.PATH, None, text)
    if lowered.startswith("workspace:"):
        return Spec(SourceKind.WORKSPACE, None, text)
    return Spec(SourceKind.REGISTRY, None, text)


def _alias(rest: str) -> Spec:
    if rest.startswith("@"):
        at = rest.find("@", 1)
    else:
        at = rest.find("@")
    name, constraint = (rest, None) if at == -1 else (rest[:at], rest[at + 1 :] or None)
    if not is_valid_name(name):
        raise InvalidSpecError("alias does not name a valid package")
    return Spec(SourceKind.REGISTRY, name, constraint)
