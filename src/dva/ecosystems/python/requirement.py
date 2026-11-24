"""Turning one dependency specifier (PEP 508) into a declared requirement.

Parsing is done by ``packaging``, the reference implementation, so names,
extras, markers and URLs follow the standard grammar exactly. Constraint and
marker text are then taken from the original string, because ``packaging``
reorders and reformats them and DVA keeps what the file actually says.
"""

from __future__ import annotations

import re

from packaging.requirements import InvalidRequirement, Requirement

from dva.domain.dependency import DeclaredRequirement, SourceKind
from dva.ecosystems.python.names import canonical, identity
from dva.ecosystems.text import preview, redact_url

_NAME_AND_EXTRAS = re.compile(
    r"^\s*[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\s*(?:\[[^\]]*\])?\s*"
)
_URL_MARKER_SEPARATOR = re.compile(r"\s;")


class RequirementSyntaxError(ValueError):
    """A specifier is not valid PEP 508. The message is safe to show to users."""


def parse_requirement(
    text: str,
    *,
    groups: tuple[str, ...] = (),
    line: int | None = None,
    project_name: str | None = None,
) -> DeclaredRequirement:
    """Parse ``text`` as a PEP 508 dependency specifier.

    ``project_name`` is the name of the project being scanned, if known; a
    requirement on the project itself (for example to pull in one of its own
    extras) is marked as a workspace dependency rather than a registry one.
    """
    text = text.strip()
    try:
        parsed = Requirement(text)
    except InvalidRequirement:
        raise RequirementSyntaxError(f"not a valid requirement: {preview(text)!r}") from None

    if parsed.url is not None:
        constraint: str | None = redact_url(parsed.url)
        source = _url_source(parsed.url)
        separator = _URL_MARKER_SEPARATOR.search(text, text.index("@"))
        markers = text[separator.end() :].strip() if separator else None
    else:
        head, has_marker, tail = text.partition(";")
        constraint = _raw_constraint(head)
        source = SourceKind.REGISTRY
        markers = tail.strip() if has_marker else None

    if project_name is not None and canonical(parsed.name) == canonical(project_name):
        source = SourceKind.WORKSPACE

    return DeclaredRequirement(
        identity=identity(parsed.name, from_registry=source is SourceKind.REGISTRY),
        constraint=constraint,
        markers=markers or None,
        groups=groups,
        line=line,
        source=source,
        extras=tuple(sorted({canonical(extra) for extra in parsed.extras})),
    )


def _raw_constraint(head: str) -> str | None:
    match = _NAME_AND_EXTRAS.match(head)
    remainder = head[match.end() :].strip() if match else head.strip()
    if remainder.startswith("(") and remainder.endswith(")"):
        remainder = remainder[1:-1].strip()
    return remainder or None


def _url_source(url: str) -> SourceKind:
    scheme = url.split(":", 1)[0].lower()
    if scheme.startswith("git+"):
        return SourceKind.GIT
    if scheme == "file":
        return SourceKind.PATH
    return SourceKind.URL
