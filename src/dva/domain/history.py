"""Registered projects, saved scans, and the differences between two scans.

A saved scan is never changed after it is stored. What DVA compares between
two scans is a :class:`ScanDigest`: the package versions each scan found, the
status each one had, and the advisories that affected it. Comparing two
digests only reports what the two scans said. A finding that is no longer
reported is not described as fixed, and a package the newer scan couldn't
check is kept apart from one it checked and found no advisory for.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path

from dva.domain.identity import PackageIdentity
from dva.domain.paths import require_relative_path
from dva.domain.scan import CompletionState
from dva.domain.vulnerability import CheckStatus, DataSource, VulnerabilityStatus

#: The longest project name DVA accepts.
MAX_NAME_LENGTH = 64


def _require_utc(field: str, value: datetime | None) -> None:
    if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
        raise ValueError(f"{field} must be a timezone-aware UTC datetime")


def root_key(root: Path) -> str:
    """The form in which two project folders are compared: case-insensitive on Windows."""
    return os.path.normcase(str(root))


def require_project_name(name: str) -> None:
    """Project names are short labels typed on the command line."""
    if not name or name != name.strip():
        raise ValueError("a project name can't be empty or start or end with spaces")
    if len(name) > MAX_NAME_LENGTH:
        raise ValueError(f"a project name can be at most {MAX_NAME_LENGTH} characters")
    if name.startswith("-"):
        raise ValueError("a project name can't start with '-'")
    if name.isdigit():
        raise ValueError("a project name can't be only digits")
    if any(not char.isprintable() for char in name):
        raise ValueError("a project name can't contain control characters")


@dataclass(frozen=True, slots=True)
class Project:
    """A local folder registered for repeated scans.

    ``root`` is the absolute folder path. It stays in the local database and
    is never written into a report. ``excludes`` lists project-relative paths
    or patterns that every rescan skips.
    """

    id: int
    name: str
    root: Path
    created_at: datetime
    excludes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_project_name(self.name)
        if not self.root.is_absolute():
            raise ValueError("a project root must be an absolute path")
        _require_utc("created_at", self.created_at)
        for pattern in self.excludes:
            require_relative_path(pattern)


@dataclass(frozen=True, slots=True)
class PackageRef:
    """A package as compared between scans: ecosystem, scope or group, and name."""

    ecosystem: str
    namespace: str | None
    name: str

    def __post_init__(self) -> None:
        # The same rules as PackageIdentity: no empty or padded parts.
        PackageIdentity(self.ecosystem, self.name, self.namespace)

    @property
    def full_name(self) -> str:
        return f"{self.namespace}/{self.name}" if self.namespace else self.name


def package_key(package: PackageRef) -> tuple[str, str, str]:
    """A sort key for packages, for a stable display order."""
    return (package.ecosystem, package.namespace or "", package.name)


@dataclass(frozen=True, slots=True)
class DigestEntry:
    """One package version a scan found.

    ``version`` is ``None`` when no exact version was known. ``status`` is
    ``None`` when the scan ran without a vulnerability check. ``advisories``
    lists the advisories that affected this version, and is non-empty exactly
    when the status is ``affected``.
    """

    package: PackageRef
    version: str | None
    status: CheckStatus | None
    advisories: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.version == "":
            raise ValueError("a version can't be empty; use None when it isn't known")
        if (self.status is CheckStatus.AFFECTED) != bool(self.advisories):
            raise ValueError("advisories are required for, and only allowed on, affected entries")
        if any(not advisory for advisory in self.advisories):
            raise ValueError("advisory ids can't be empty")


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """The headline facts of one scan."""

    tool_version: str
    started_at: datetime
    finished_at: datetime
    completion: CompletionState
    vulnerability_status: VulnerabilityStatus
    #: Where advisory data came from; ``None`` when vulnerabilities weren't checked.
    data_source: DataSource | None = None
    #: The oldest retrieval time of the advisory data the scan used.
    oldest_data_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.tool_version:
            raise ValueError("tool_version must be non-empty")
        _require_utc("started_at", self.started_at)
        _require_utc("finished_at", self.finished_at)
        _require_utc("oldest_data_at", self.oldest_data_at)
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")


@dataclass(frozen=True, slots=True)
class ScanDigest:
    """What a scan found, in the form two scans are compared in."""

    summary: ScanSummary
    manifests: tuple[str, ...] = ()
    entries: tuple[DigestEntry, ...] = ()

    def __post_init__(self) -> None:
        for path in self.manifests:
            require_relative_path(path)
        keys = [(entry.package, entry.version) for entry in self.entries]
        if len(set(keys)) != len(keys):
            raise ValueError("a digest lists each package version once")


@dataclass(frozen=True, slots=True)
class ScanRecord:
    """A saved scan as listed in a project's history."""

    id: int
    project_id: int
    summary: ScanSummary
    #: How many package versions (or unversioned declarations) the scan found.
    packages: int
    #: How many of those were affected by at least one advisory.
    affected: int
    #: How many distinct advisories affected them.
    advisories: int


class GoneReason(StrEnum):
    """Why an advisory reported in the older scan isn't reported in the newer one."""

    #: The package isn't in the newer scan at all.
    PACKAGE_REMOVED = "package_removed"
    #: The package is there, but not this version.
    VERSION_CHANGED = "version_changed"
    #: The same version was checked and the source no longer matched the advisory to it.
    NO_LONGER_MATCHED = "no_longer_matched"
    #: The same version is there, but the newer scan couldn't check it.
    NOT_CHECKED = "not_checked"


@dataclass(frozen=True, slots=True)
class FindingRef:
    """One advisory affecting one package version."""

    package: PackageRef
    version: str
    advisory_id: str


@dataclass(frozen=True, slots=True)
class GoneFinding:
    finding: FindingRef
    reason: GoneReason


@dataclass(frozen=True, slots=True)
class VersionChange:
    """A package found in both scans with different versions.

    The versions are listed as each scan found them; nothing here says which
    one is newer.
    """

    package: PackageRef
    old_versions: tuple[str, ...]
    new_versions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScanComparison:
    """The differences between an older and a newer scan of one project."""

    old: ScanRecord
    new: ScanRecord
    manifests_added: tuple[str, ...] = ()
    manifests_removed: tuple[str, ...] = ()
    packages_added: tuple[PackageRef, ...] = ()
    packages_removed: tuple[PackageRef, ...] = ()
    versions_changed: tuple[VersionChange, ...] = ()
    #: Findings for package versions the older scan didn't report them for.
    new_findings: tuple[FindingRef, ...] = ()
    #: Findings for package versions that were in the older scan but weren't checked there.
    first_checked_findings: tuple[FindingRef, ...] = ()
    gone_findings: tuple[GoneFinding, ...] = ()
    #: Package versions in both scans that the older scan checked and the newer one couldn't.
    newly_unchecked: tuple[tuple[PackageRef, str], ...] = ()

    @property
    def reports_more(self) -> bool:
        """Whether the newer scan reports an advisory finding the older one didn't."""
        return bool(self.new_findings or self.first_checked_findings)

    @property
    def has_changes(self) -> bool:
        return any(
            (
                self.manifests_added,
                self.manifests_removed,
                self.packages_added,
                self.packages_removed,
                self.versions_changed,
                self.new_findings,
                self.first_checked_findings,
                self.gone_findings,
                self.newly_unchecked,
            )
        )
