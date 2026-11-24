"""The plain-text summary printed at the end of ``dva scan``.

Every string that came from a scanned file or an advisory goes through
``clean_text`` first, so a crafted package name or advisory can't send
escape codes to the terminal; optional colour is added afterwards by
:mod:`dva.reporting.style`. Severity is shown exactly as the advisory gives
it; DVA doesn't compute scores, and only orders packages by the database's
own label.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from dva.domain.advisory import Advisory
from dva.domain.manifest import ParseStatus
from dva.domain.scan import CompletionState, ScanResult
from dva.domain.vulnerability import (
    CheckStatus,
    Finding,
    PackageCheck,
    VulnerabilityReport,
    VulnerabilityStatus,
)
from dva.reporting.overview import (
    Overview,
    check_rank,
    clean_text,
    findings_by_severity,
    group_findings,
    group_rank,
    package_name,
    severity_name,
)
from dva.reporting.style import PLAIN, SEVERITY_COLOURS, Style

#: How many not-checked, unknown or failed packages to list before summarizing.
LIST_LIMIT = 15

_DISCLAIMER = (
    "No matching advisory means the source had no advisory matching that version "
    "when it was asked. It is not proof that a package is safe."
)

_ANALYSIS = {
    CompletionState.COMPLETE: "complete",
    CompletionState.PARTIAL: "partial",
    CompletionState.FAILED: "failed",
    CompletionState.NO_SUPPORTED_FILES: "no supported files found",
}
_CHECK = {
    VulnerabilityStatus.NOT_QUERIED: "not run",
    VulnerabilityStatus.COMPLETE: "complete",
    VulnerabilityStatus.PARTIAL: "partial",
    VulnerabilityStatus.FAILED: "failed",
}


def _when(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "unknown"


def _plural(count: int, word: str, plural: str | None = None) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {plural or word + 's'}"


def _severity_counts(counts: dict[str, int], style: Style) -> str:
    return ", ".join(
        style(
            f"{n} {'without a rating' if name == 'unrated' else name}",
            *SEVERITY_COLOURS.get(name, ()),
        )
        for name, n in counts.items()
    )


def _affected_checks(report: VulnerabilityReport) -> list[PackageCheck]:
    """Affected packages, most severe first, then by name."""
    advisories = {a.id: a for a in report.advisories}
    affected = [c for c in report.checks if c.status is CheckStatus.AFFECTED]
    return sorted(
        affected, key=lambda c: (-check_rank(c, advisories), package_name(c), c.version or "")
    )


def render_text(scan: ScanResult, style: Style = PLAIN) -> str:
    overview = Overview.of(scan)
    title = f"DVA {scan.tool_version}: scan of {clean_text(scan.project_name)!r}"
    lines: list[str] = [style(title, "bold"), ""]
    lines += _files(scan, overview)
    if scan.excluded:
        lines.append(f"Excluded on request: {', '.join(clean_text(p) for p in scan.excluded)}")
    lines.append("")
    report = scan.vulnerabilities
    if report is None:
        lines.append("Vulnerabilities: not checked (the scan ran without a vulnerability lookup)")
    else:
        lines += _vulnerabilities(report, style)
    lines += ["", _result_line(scan, style)]
    if report is not None:
        lines += ["", _DISCLAIMER]
    return "\n".join(lines) + "\n"


def render_brief(scan: ScanResult, style: Style = PLAIN) -> str:
    """One line per affected package, then the result."""
    title = f"DVA {scan.tool_version}: scan of {clean_text(scan.project_name)!r}"
    lines = [style(title, "bold")]
    report = scan.vulnerabilities
    if report is not None:
        advisories = {a.id: a for a in report.advisories}
        for check in _affected_checks(report):
            counts = findings_by_severity([check], advisories)
            total = sum(counts.values())
            name = f"{package_name(check)} {clean_text(check.version or '')}"
            lines.append(
                f"  {style(name, 'bold')}: {_plural(total, 'advisory', 'advisories')} "
                f"({_severity_counts(counts, style)})"
            )
        unsure = sum(
            1
            for c in report.checks
            if c.status in (CheckStatus.UNKNOWN, CheckStatus.NOT_CHECKED, CheckStatus.LOOKUP_FAILED)
        )
        if unsure:
            lines.append(
                f"  {_plural(unsure, 'package')} couldn't be fully checked (see the full summary)"
            )
    lines.append(_result_line(scan, style))
    return "\n".join(lines) + "\n"


def _files(scan: ScanResult, overview: Overview) -> list[str]:
    if not scan.manifests:
        return ["Dependency files: none found that DVA recognizes"]
    counts = ", ".join(f"{n} {status}" for status, n in overview.files_by_status.items())
    lines = [f"Dependency files: {len(scan.manifests)} found ({counts})"]
    for manifest in sorted(scan.manifests, key=lambda m: m.path):
        if manifest.status is not ParseStatus.PARSED:
            problems = [d for d in manifest.diagnostics if d.level.value != "info"]
            detail = clean_text(problems[0].message) if problems else ""
            lines.append(f"  {manifest.status.value:<12} {clean_text(manifest.path)}  {detail}")
    lines.append(
        f"Packages: {overview.resolved_packages} from lockfiles "
        f"({overview.direct_dependencies} direct), "
        f"{overview.declared_requirements} declared in manifests"
    )
    for diagnostic in scan.diagnostics:
        if diagnostic.level.value != "info":
            lines.append(f"  note: {clean_text(diagnostic.message)}")
    return lines


def _vulnerabilities(report: VulnerabilityReport, style: Style) -> list[str]:
    source = report.provider.upper()
    data = {
        "live": f"live data, retrieved {_when(report.checked_at)}",
        "cache": f"cached data, oldest retrieved {_when(report.oldest_data_at)}",
        "mixed": f"live and cached data, oldest retrieved {_when(report.oldest_data_at)}",
        "none": "no data available",
    }[report.data_source.value]
    lines = [style(f"Vulnerabilities ({source}, {data}):", "bold")]
    by_status: dict[CheckStatus, list[PackageCheck]] = {status: [] for status in CheckStatus}
    for check in report.checks:
        by_status[check.status].append(check)
    affected = _affected_checks(report)
    advisories = {a.id: a for a in report.advisories}

    counts = [
        f"{len(by_status[CheckStatus.AFFECTED])} affected",
        f"{len(by_status[CheckStatus.NO_MATCHING_ADVISORY])} with no matching advisory",
        f"{len(by_status[CheckStatus.UNKNOWN])} unknown",
        f"{len(by_status[CheckStatus.NOT_CHECKED])} not checked",
        f"{len(by_status[CheckStatus.LOOKUP_FAILED])} lookup failed",
    ]
    lines.append("  Packages: " + ", ".join(counts))
    severities = findings_by_severity(affected, advisories)
    if severities:
        lines.append(
            "  Advisories by the database's rating: " + _severity_counts(severities, style)
        )

    if affected:
        lines.append("")
        for check in affected:
            lines += _affected(check, advisories, style)
    for status, title in (
        (CheckStatus.UNKNOWN, "Could not decide"),
        (CheckStatus.LOOKUP_FAILED, "Lookup failed"),
        (CheckStatus.NOT_CHECKED, "Not checked"),
    ):
        items = sorted(by_status[status], key=lambda c: (package_name(c), c.version or ""))
        if items:
            lines += ["", f"  {title}:"]
            for check in items[:LIST_LIMIT]:
                version = f" {clean_text(check.version)}" if check.version else ""
                reason = clean_text(check.reasons[0]) if check.reasons else ""
                lines.append(f"    {package_name(check)}{version}: {reason}")
            if len(items) > LIST_LIMIT:
                lines.append(f"    ... and {len(items) - LIST_LIMIT} more (see the JSON report)")
    for diagnostic in report.diagnostics:
        lines.append(f"  note: {clean_text(diagnostic.message)}")
    return lines


def _affected(check: PackageCheck, advisories: dict[str, Advisory], style: Style) -> list[str]:
    version = clean_text(check.version or "")
    lines = [style(f"  {package_name(check)} {version}", "bold")]
    for group in group_findings(check.findings, advisories):
        finding, copies = group[0], group[1:]
        advisory = advisories[finding.advisory_id]
        shown = {advisory.id, *(f.advisory_id for f in copies)}
        aliases = [clean_text(a) for a in advisory.aliases if a not in shown]
        alias_text = f" ({', '.join(aliases)})" if aliases else ""
        level = severity_name(group_rank(group, advisories))
        lines.append(
            f"    {style(clean_text(advisory.id), *SEVERITY_COLOURS.get(level, ()))}{alias_text}"
        )
        if copies:
            also = ", ".join(clean_text(f.advisory_id) for f in copies)
            lines.append(f"      also published as: {also}")
        if advisory.summary:
            lines.append(f"      {clean_text(advisory.summary)}")
        severity = _severity(advisory, group)
        if severity:
            lines.append(f"      severity: {severity}")
        fixed_versions = list(dict.fromkeys(v for f in group for v in f.fixed_versions))
        last_affected = list(dict.fromkeys(v for f in group for v in f.last_affected))
        if fixed_versions:
            fixed = ", ".join(clean_text(v) for v in fixed_versions)
            lines.append(f"      fixed in: {style(fixed, 'green')}")
        elif last_affected:
            last = ", ".join(clean_text(v) for v in last_affected)
            lines.append(f"      no fixed version given (last affected: {last})")
        else:
            lines.append("      no fixed version given by the advisory")
    places = sorted({clean_text(loc.path) for loc in check.locations})
    lines.append(f"    found in: {', '.join(places)}")
    return lines


def _severity(advisory: Advisory, group: Sequence[Finding]) -> str:
    parts = []
    if advisory.database_severity:
        parts.append(f"{clean_text(advisory.database_severity)} (rated by the database)")
    parts += [f"{clean_text(s.type)} {clean_text(s.score)}" for s in advisory.severities]
    package = dict.fromkeys(s for f in group for s in f.severities)
    parts += [
        f"{clean_text(s.type)} {clean_text(s.score)} (for this package)"
        for s in package
        if s not in advisory.severities
    ]
    return "; ".join(parts)


def _result_line(scan: ScanResult, style: Style = PLAIN) -> str:
    report = scan.vulnerabilities
    affected = sum(1 for c in report.checks if c.status is CheckStatus.AFFECTED) if report else 0
    vulns = scan.vulnerability_status
    analysis = _ANALYSIS[scan.completion]
    if affected:
        headline = style(f"Result: {_plural(affected, 'affected package')} found.", "red", "bold")
    elif vulns is VulnerabilityStatus.COMPLETE:
        headline = style("Result: no package matched a known advisory.", "green")
    elif vulns is VulnerabilityStatus.NOT_QUERIED:
        headline = "Result: vulnerabilities were not checked."
    else:
        headline = style(
            "Result: no affected package found, but the check was incomplete.", "yellow"
        )
    return f"{headline} Dependency analysis: {analysis}. Vulnerability check: {_CHECK[vulns]}."
