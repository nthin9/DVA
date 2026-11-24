"""Plain-text listings of registered projects, saved scans, and comparisons.

Package names, versions, advisory ids and file paths came from scanned files
or advisories, so they all go through ``clean_text`` before being printed.
Nothing here says a project is safe: an advisory that is no longer reported
is described as exactly that.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from dva.domain.history import (
    FindingRef,
    GoneReason,
    PackageRef,
    Project,
    ScanComparison,
    ScanRecord,
    ScanSummary,
)
from dva.domain.vulnerability import DataSource, VulnerabilityStatus
from dva.reporting.overview import clean_text

#: How many entries of one kind to list before summarizing the rest.
LIST_LIMIT = 15

_GONE_DISCLAIMER = (
    "An advisory that is no longer reported is not proof that a problem was fixed: "
    "it only means the newer scan didn't report it."
)

_GONE_REASONS = {
    GoneReason.PACKAGE_REMOVED: "the package is no longer in the project",
    GoneReason.VERSION_CHANGED: "the project now has a different version",
    GoneReason.NO_LONGER_MATCHED: "the source no longer matched it to this version",
}


def _when(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC")


def _plural(count: int, word: str, plural: str | None = None) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {plural or word + 's'}"


_DATA_SOURCES = {
    DataSource.LIVE: "live data",
    DataSource.CACHE: "cached data",
    DataSource.MIXED: "live and cached data",
    DataSource.NONE: "no advisory data",
}


def _package(package: PackageRef) -> str:
    return f"{clean_text(package.full_name)} ({clean_text(package.ecosystem)})"


def _finding(finding: FindingRef) -> str:
    name = clean_text(finding.package.full_name)
    return f"{name} {clean_text(finding.version)}: {clean_text(finding.advisory_id)}"


def _limited(items: Sequence[str], indent: str = "  ") -> list[str]:
    lines = [f"{indent}{item}" for item in items[:LIST_LIMIT]]
    if len(items) > LIST_LIMIT:
        lines.append(f"{indent}... and {len(items) - LIST_LIMIT} more")
    return lines


def _status(summary: ScanSummary) -> str:
    vulns = summary.vulnerability_status
    text = f"analysis {summary.completion.value.replace('_', ' ')}, "
    if vulns is VulnerabilityStatus.NOT_QUERIED:
        return text + "vulnerabilities not checked"
    source = f", {_DATA_SOURCES[summary.data_source]}" if summary.data_source else ""
    return text + f"vulnerability check {vulns.value}{source}"


def _counts(record: ScanRecord) -> str:
    text = _plural(record.packages, "package")
    if record.summary.vulnerability_status is VulnerabilityStatus.NOT_QUERIED:
        return text
    advisories = _plural(record.advisories, "advisory", "advisories")
    return f"{text}, {record.affected} affected ({advisories})"


def render_projects(projects: Sequence[tuple[Project, ScanRecord | None]]) -> str:
    if not projects:
        return "No projects are registered. Add one with: dva project add PATH\n"
    lines = ["Registered projects:", ""]
    for project, latest in projects:
        lines.append(f"  {clean_text(project.name)}")
        lines.append(f"    folder: {clean_text(str(project.root))}")
        if latest is None:
            lines.append("    last scan: none yet")
        else:
            when = _when(latest.summary.started_at)
            lines.append(f"    last scan: #{latest.id}, {when}, {_counts(latest)}")
    return "\n".join(lines) + "\n"


def render_history(project: Project, records: Sequence[ScanRecord]) -> str:
    name = clean_text(project.name)
    if not records:
        return f"No saved scans for {name!r} yet. Run: dva rescan {name}\n"
    lines = [f"Saved scans of {name!r}, newest first:", ""]
    for record in records:
        lines.append(f"  #{record.id}  {_when(record.summary.started_at)}  {_counts(record)}")
        lines.append(f"      {_status(record.summary)}")
    return "\n".join(lines) + "\n"


def summary_line(project: Project, comparison: ScanComparison) -> str:
    """One line for the end of ``dva rescan``."""
    old = comparison.old
    if not comparison.has_changes:
        return f"Changes since scan #{old.id}: none."
    parts = []
    packages = (
        len(comparison.packages_added),
        len(comparison.packages_removed),
        len(comparison.versions_changed),
    )
    if any(packages):
        added, removed, changed = packages
        parts.append(f"packages {added} added, {removed} removed, {changed} changed")
    if comparison.new_findings:
        parts.append(_plural(len(comparison.new_findings), "new advisory finding"))
    if comparison.first_checked_findings:
        count = len(comparison.first_checked_findings)
        parts.append(f"{_plural(count, 'finding')} for versions not checked before")
    if comparison.gone_findings:
        parts.append(f"{len(comparison.gone_findings)} no longer reported")
    if comparison.newly_unchecked:
        parts.append(f"{len(comparison.newly_unchecked)} no longer checked")
    if comparison.manifests_added or comparison.manifests_removed:
        parts.append("dependency files changed")
    details = f"dva compare {clean_text(project.name)}"
    return f"Changes since scan #{old.id}: {'; '.join(parts)}. Details: {details}"


def render_comparison(project: Project, comparison: ScanComparison) -> str:
    old, new = comparison.old, comparison.new
    lines = [
        f"Comparing scans of {clean_text(project.name)!r}:",
        f"  older: #{old.id}, {_when(old.summary.started_at)}, {_status(old.summary)}",
        f"  newer: #{new.id}, {_when(new.summary.started_at)}, {_status(new.summary)}",
    ]
    if not comparison.has_changes:
        lines += ["", "No differences in dependency files, packages or advisories."]
    lines += _section(
        "Dependency files",
        [f"+ {clean_text(p)}" for p in comparison.manifests_added]
        + [f"- {clean_text(p)}" for p in comparison.manifests_removed],
    )
    lines += _section(
        "Packages",
        [f"+ {_package(p)}" for p in comparison.packages_added]
        + [f"- {_package(p)}" for p in comparison.packages_removed]
        + [
            f"~ {_package(c.package)}: {_versions(c.old_versions)} -> {_versions(c.new_versions)}"
            for c in comparison.versions_changed
        ],
    )
    lines += _section("New advisory findings", [_finding(f) for f in comparison.new_findings])
    lines += _section(
        "Reported now, but not checked in the older scan",
        [_finding(f) for f in comparison.first_checked_findings],
    )
    reported = [g for g in comparison.gone_findings if g.reason is not GoneReason.NOT_CHECKED]
    lines += _section(
        "No longer reported",
        [f"{_finding(g.finding)} ({_GONE_REASONS[g.reason]})" for g in reported],
    )
    unchecked = [g.finding for g in comparison.gone_findings if g.reason is GoneReason.NOT_CHECKED]
    lines += _section(
        "Reported before, but could not be checked in the newer scan",
        [_finding(f) for f in unchecked],
    )
    lines += _section(
        "Checked before, but not in the newer scan",
        [
            f"{clean_text(package.full_name)} {clean_text(version)}"
            for package, version in comparison.newly_unchecked
        ],
    )
    if comparison.gone_findings or comparison.newly_unchecked:
        lines += ["", _GONE_DISCLAIMER]
    return "\n".join(lines) + "\n"


def _versions(versions: Sequence[str]) -> str:
    if not versions:
        return "no exact version"
    return ", ".join(clean_text(v) for v in versions)


def _section(title: str, items: Sequence[str]) -> list[str]:
    if not items:
        return []
    return ["", f"{title} ({len(items)}):", *_limited(items)]
