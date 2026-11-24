"""Vulnerability advisories, as published by a vulnerability database.

The shape follows the OSV format, which several databases share, but nothing
here depends on a particular provider. Text, severity and version data are
kept exactly as the advisory gives them: DVA never computes a severity,
guesses a fixed version, or rewrites an advisory's description.

Version strings in ranges are stored verbatim. Interpreting them is the job
of the matching layer, which knows each ecosystem's version rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


class EventKind(StrEnum):
    INTRODUCED = "introduced"
    FIXED = "fixed"
    LAST_AFFECTED = "last_affected"
    LIMIT = "limit"


@dataclass(frozen=True, slots=True)
class RangeEvent:
    """One boundary of an affected range, such as ``fixed: 2.31.0``."""

    kind: EventKind
    version: str

    def __post_init__(self) -> None:
        if not self.version or self.version != self.version.strip():
            raise ValueError("range event version must be non-empty without surrounding spaces")


@dataclass(frozen=True, slots=True)
class AffectedRange:
    """A range of affected versions.

    ``type`` says how to read the versions: ``SEMVER`` (Semantic Versioning),
    ``ECOSYSTEM`` (the package ecosystem's own rules), or ``GIT`` (commit
    hashes in ``repo``). Other types are kept but can't be evaluated.
    """

    type: str
    events: tuple[RangeEvent, ...]
    repo: str | None = None

    def __post_init__(self) -> None:
        if not self.type:
            raise ValueError("range type must be non-empty")
        if not self.events:
            raise ValueError("a range needs at least one event")


@dataclass(frozen=True, slots=True)
class Severity:
    """A severity score as published, for example a CVSS vector string.

    ``type`` names the scoring system (``CVSS_V3``, ``CVSS_V4`` ...);
    ``source`` says who assigned it, when the advisory says.
    """

    type: str
    score: str
    source: str | None = None

    def __post_init__(self) -> None:
        if not self.type or not self.score:
            raise ValueError("severity needs a type and a score")


@dataclass(frozen=True, slots=True)
class AffectedPackage:
    """A package an advisory applies to, with its affected ranges and versions.

    ``ecosystem`` is DVA's ecosystem identifier (``pypi``, ``npm``) when DVA
    supports the ecosystem, and the database's own name for it otherwise.
    ``versions`` lists affected versions explicitly, when the database does.
    ``severities`` are scores the advisory gives for this package only; OSV
    uses them instead of advisory-wide scores when they differ per package.
    """

    ecosystem: str
    name: str
    purl: str | None = None
    ranges: tuple[AffectedRange, ...] = ()
    versions: tuple[str, ...] = ()
    severities: tuple[Severity, ...] = ()

    def __post_init__(self) -> None:
        if not self.ecosystem or not self.name:
            raise ValueError("affected package needs an ecosystem and a name")


@dataclass(frozen=True, slots=True)
class Reference:
    type: str
    url: str

    def __post_init__(self) -> None:
        if not self.type or not self.url:
            raise ValueError("reference needs a type and a URL")


def _require_utc(field: str, value: datetime | None) -> None:
    if value is not None and value.utcoffset() != UTC.utcoffset(None):
        raise ValueError(f"{field} must be a UTC timestamp")


@dataclass(frozen=True, slots=True)
class Advisory:
    """One advisory record.

    ``modified`` is when the database last changed the record; it decides
    whether a cached copy is current. ``withdrawn`` is set when the database
    retracted the advisory. ``database_severity`` is the database's own
    rating label (for example GitHub's ``MODERATE``), kept separate from
    scored severities because it isn't a standard scale.
    """

    id: str
    modified: datetime
    published: datetime | None = None
    withdrawn: datetime | None = None
    aliases: tuple[str, ...] = ()
    related: tuple[str, ...] = ()
    summary: str | None = None
    details: str | None = None
    severities: tuple[Severity, ...] = ()
    database_severity: str | None = None
    references: tuple[Reference, ...] = ()
    affected: tuple[AffectedPackage, ...] = ()
    schema_version: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("advisory id must be non-empty")
        _require_utc("modified", self.modified)
        _require_utc("published", self.published)
        _require_utc("withdrawn", self.withdrawn)

    @property
    def cve_ids(self) -> tuple[str, ...]:
        """The CVE identifiers among the advisory's own id and aliases."""
        return tuple(i for i in (self.id, *self.aliases) if i.startswith("CVE-"))
