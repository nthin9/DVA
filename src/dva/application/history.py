"""Use cases for registered projects: register, rescan, and compare saved scans.

Rescanning reads a project exactly as ``dva scan`` does (nothing is run or
installed, and no project file is changed) and then saves the result as a new
snapshot. Earlier snapshots are never modified.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from dva.application.analyze import analyze_project
from dva.application.vulnerabilities import requirement_version
from dva.contracts.history import HistoryError, HistoryStore
from dva.domain.dependency import SourceKind
from dva.domain.history import (
    DigestEntry,
    FindingRef,
    GoneFinding,
    GoneReason,
    PackageRef,
    Project,
    ScanComparison,
    ScanDigest,
    ScanRecord,
    ScanSummary,
    VersionChange,
    package_key,
    require_project_name,
)
from dva.domain.identity import PackageIdentity
from dva.domain.scan import ScanResult
from dva.domain.vulnerability import CheckStatus
from dva.ecosystems.registry import AdapterRegistry
from dva.matching.schemes import UnparsableVersionError, known_ecosystems, scheme_for

type Clock = Callable[[], datetime]
type Check = Callable[[ScanResult], ScanResult]
type Render = Callable[[ScanResult], str]

#: Statuses that mean a package version was actually checked against the source.
CHECKED = frozenset({CheckStatus.AFFECTED, CheckStatus.NO_MATCHING_ADVISORY})
#: An older scan that checked a version, or didn't have it at all, makes a finding "new".
CHECKED_OR_ABSENT: frozenset[CheckStatus | None | str] = frozenset({*CHECKED, "absent"})


class ProjectRootError(ValueError):
    """The folder to register doesn't exist or isn't a folder."""


class UnknownScanError(HistoryError):
    """The project has no saved scan with that number, or not enough scans to compare."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def register_project(
    store: HistoryStore, root: Path, name: str | None = None, *, clock: Clock = _utc_now
) -> Project:
    """Register the folder ``root``. The name defaults to the folder's name."""
    try:
        resolved = root.resolve(strict=True)
    except OSError:
        raise ProjectRootError("the folder doesn't exist or can't be accessed") from None
    if not resolved.is_dir():
        raise ProjectRootError("that path is not a folder")
    chosen = name if name is not None else resolved.name
    require_project_name(chosen)
    return store.add_project(chosen, resolved, clock())


def _ref(identity: PackageIdentity) -> PackageRef:
    return PackageRef(identity.ecosystem, identity.namespace, identity.name)


def digest_scan(scan: ScanResult) -> ScanDigest:
    """Reduce a scan to what is compared between scans."""
    report = scan.vulnerabilities
    summary = ScanSummary(
        tool_version=scan.tool_version,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        completion=scan.completion,
        vulnerability_status=scan.vulnerability_status,
        data_source=report.data_source if report else None,
        oldest_data_at=report.oldest_data_at if report else None,
    )
    entries: dict[tuple[PackageRef, str | None], DigestEntry] = {}
    if report is not None:
        for check in report.checks:
            key = (_ref(check.identity), check.version)
            advisories = sorted({f.advisory_id for f in check.findings})
            if key in entries:  # Two identities that compare equal here: merge them.
                advisories = sorted({*advisories, *entries[key].advisories})
                status = CheckStatus.AFFECTED if advisories else entries[key].status
            else:
                status = check.status
            entries[key] = DigestEntry(key[0], key[1], status, tuple(advisories))
    else:
        for package, version in _versions(scan):
            entries.setdefault((package, version), DigestEntry(package, version, None))
    versioned = {package for package, version in entries if version is not None}
    kept = [e for (p, v), e in entries.items() if v is not None or p not in versioned]
    return ScanDigest(
        summary=summary,
        manifests=tuple(sorted(m.path for m in scan.manifests)),
        entries=tuple(sorted(kept, key=lambda e: (package_key(e.package), e.version or ""))),
    )


def _versions(scan: ScanResult) -> Iterable[tuple[PackageRef, str | None]]:
    """Package versions in a scan that wasn't checked, chosen the way the
    vulnerability check chooses them by default, so checked and unchecked
    scans compare cleanly: public registry releases with an exact version keep
    it; anything else (git, URL, path, workspace, another registry, or a
    range) counts as having no exact version."""
    for manifest in scan.manifests:
        for package in manifest.packages:
            known = (
                package.source is SourceKind.REGISTRY
                and scheme_for(package.identity.ecosystem) is not None
            )
            yield _ref(package.identity), package.version if known else None
        for requirement in manifest.requirements:
            public = requirement.source is SourceKind.REGISTRY
            yield _ref(requirement.identity), requirement_version(requirement) if public else None


@dataclass(frozen=True, slots=True)
class RescanResult:
    scan: ScanResult
    record: ScanRecord
    #: The differences from the previous saved scan, if there was one.
    comparison: ScanComparison | None


def rescan_project(
    store: HistoryStore,
    project: Project,
    registry: AdapterRegistry,
    *,
    render_report: Render,
    check: Check | None = None,
) -> RescanResult:
    """Scan a registered project again and save the result as a new snapshot.

    ``check`` attaches the vulnerability check (``None`` skips it).
    ``render_report`` produces the JSON report text saved with the scan.
    Raises :class:`dva.application.analyze.InvalidProjectRootError` if the
    folder is gone; nothing is saved then.
    """
    previous = store.scans(project.id, limit=1)
    scan = analyze_project(project.root, registry)
    if check is not None:
        scan = check(scan)
    digest = digest_scan(scan)
    record = store.save_scan(project.id, digest, render_report(scan))
    comparison = None
    if previous:
        old = store.digest(project.id, previous[0].id)
        if old is not None:
            comparison = compare_digests(previous[0], old, record, digest)
    return RescanResult(scan, record, comparison)


def find_package(
    store: HistoryStore, name: str
) -> tuple[tuple[Project, ScanRecord, DigestEntry], ...]:
    """Which registered projects use a package, according to each one's latest scan.

    ``name`` is normalized the way each ecosystem does it (for Python,
    ``Foo_Bar`` and ``foo-bar`` are the same package) and may include an npm
    scope (``@babel/core``).
    """
    found: list[tuple[Project, ScanRecord, DigestEntry]] = []
    namespace: str | None = None
    local = name.strip()
    if local.startswith("@") and "/" in local:  # A scoped name, such as @babel/core.
        namespace, local = local.split("/", 1)
    for ecosystem in known_ecosystems():
        scheme = scheme_for(ecosystem)
        if not local:
            continue
        normalized = scheme.normalize_name(local) if scheme else local
        try:
            package = PackageRef(ecosystem, namespace, normalized)
        except ValueError:
            continue
        found += store.latest_entries(package)
    return tuple(found)


def compare_scans(
    store: HistoryStore,
    project: Project,
    old_id: int | None = None,
    new_id: int | None = None,
) -> ScanComparison:
    """Compare two of a project's saved scans.

    With no ids, compares the latest scan with the one before it. With only
    ``old_id``, compares that scan with the latest.
    """
    records = {record.id: record for record in store.scans(project.id)}
    newest = sorted(records, reverse=True)
    if new_id is None:
        if not newest:
            raise UnknownScanError("the project has no saved scans yet")
        new_id = newest[0]
    if old_id is None:
        older = [scan_id for scan_id in newest if scan_id < new_id]
        if not older:
            raise UnknownScanError("comparing needs at least two saved scans")
        old_id = older[0]
    for scan_id in (old_id, new_id):
        if scan_id not in records:
            raise UnknownScanError(f"the project has no saved scan #{scan_id}")
    old, new = store.digest(project.id, old_id), store.digest(project.id, new_id)
    if old is None or new is None:
        raise UnknownScanError("a saved scan disappeared while it was being read")
    return compare_digests(records[old_id], old, records[new_id], new)


def _sorted_versions(package: PackageRef, versions: Iterable[str]) -> tuple[str, ...]:
    """Versions in the ecosystem's own order where it can tell, text order otherwise."""
    scheme = scheme_for(package.ecosystem)
    parsed, unparsed = [], []
    for version in set(versions):
        try:
            if scheme is None:
                raise UnparsableVersionError(version)
            parsed.append((scheme.key(version), version))
        except UnparsableVersionError:
            unparsed.append(version)
    try:
        ordered = [version for _, version in sorted(parsed)]
    except TypeError:  # Keys that can't be ordered against each other.
        ordered = sorted(version for _, version in parsed)
    return (*ordered, *sorted(unparsed))


def compare_digests(
    old_record: ScanRecord, old: ScanDigest, new_record: ScanRecord, new: ScanDigest
) -> ScanComparison:
    """The differences between two scans of the same project."""

    def versions(digest: ScanDigest) -> dict[PackageRef, set[str]]:
        found: dict[PackageRef, set[str]] = {}
        for entry in digest.entries:
            bucket = found.setdefault(entry.package, set())
            if entry.version is not None:
                bucket.add(entry.version)
        return found

    def findings(digest: ScanDigest) -> set[FindingRef]:
        return {
            FindingRef(e.package, e.version, advisory)
            for e in digest.entries
            if e.version is not None
            for advisory in e.advisories
        }

    old_versions, new_versions = versions(old), versions(new)
    new_status = {(e.package, e.version): e.status for e in new.entries}
    old_status = {(e.package, e.version): e.status for e in old.entries}

    gone = []
    for finding in sorted(findings(old) - findings(new), key=_finding_key):
        key = (finding.package, finding.version)
        if finding.package not in new_versions:
            reason = GoneReason.PACKAGE_REMOVED
        elif key not in new_status:
            # Declared without an exact version now: the newer scan couldn't check it.
            known = new_versions[finding.package]
            reason = GoneReason.VERSION_CHANGED if known else GoneReason.NOT_CHECKED
        elif new_status[key] in CHECKED:
            reason = GoneReason.NO_LONGER_MATCHED
        else:
            reason = GoneReason.NOT_CHECKED
        gone.append(GoneFinding(finding, reason))

    unchecked = sorted(
        (
            (package, version)
            for (package, version), status in new_status.items()
            if version is not None
            and status not in CHECKED
            and old_status.get((package, version)) in CHECKED
        ),
        key=lambda item: (package_key(item[0]), item[1]),
    )

    added = sorted(findings(new) - findings(old), key=_finding_key)
    changed = [
        VersionChange(
            package,
            _sorted_versions(package, old_versions[package]),
            _sorted_versions(package, new_versions[package]),
        )
        for package in sorted(old_versions.keys() & new_versions.keys(), key=package_key)
        if old_versions[package] != new_versions[package]
    ]
    return ScanComparison(
        old=old_record,
        new=new_record,
        manifests_added=tuple(sorted(set(new.manifests) - set(old.manifests))),
        manifests_removed=tuple(sorted(set(old.manifests) - set(new.manifests))),
        packages_added=tuple(sorted(new_versions.keys() - old_versions.keys(), key=package_key)),
        packages_removed=tuple(sorted(old_versions.keys() - new_versions.keys(), key=package_key)),
        versions_changed=tuple(changed),
        new_findings=tuple(
            f
            for f in added
            if old_status.get((f.package, f.version), "absent") in CHECKED_OR_ABSENT
        ),
        first_checked_findings=tuple(
            f
            for f in added
            if old_status.get((f.package, f.version), "absent") not in CHECKED_OR_ABSENT
        ),
        gone_findings=tuple(gone),
        newly_unchecked=tuple(unchecked),
    )


def _finding_key(finding: FindingRef) -> tuple[tuple[str, str, str], str, str]:
    return (package_key(finding.package), finding.version, finding.advisory_id)
