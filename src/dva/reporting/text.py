"""The plain-text summary printed at the end of ``dva scan``.

Every string that came from a scanned file or an advisory goes through
``clean_text`` first, so a crafted package name or advisory can't send
escape codes to the terminal. Severity is shown exactly as the advisory gives
it; DVA doesn't compute scores.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from dva.domain.advisory import Advisory
from dva.domain.manifest import ParseStatus
from dva.domain.scan import ScanResult
from dva.domain.vulnerability import (
    CheckStatus,
    Finding,
    PackageCheck,
    VulnerabilityReport,
    VulnerabilityStatus,
)
from dva.reporting.overview import Overview, clean_text, group_findings, package_name

#: How many not-checked, unknown or failed packages to list before summarizing.
LIST_LIMIT = 15

_DISCLAIMER = (
    "No matching advisory means the source had no advisory matching that version "
    "when it was asked. It is not proof that a package is safe."
)


def _when(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "unknown"


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def render_text(scan: ScanResult) -> str:
    overview = Overview.of(scan)
    lines: list[str] = [f"DVA {scan.tool_version}: scan of {clean_text(scan.project_name)!r}", ""]
    lines += _files(scan, overview)
    if scan.excluded:
        lines.append(f"Excluded on request: {', '.join(clean_text(p) for p in scan.excluded)}")
    lines.append("")
    report = scan.vulnerabilities
    if report is None:
        lines.append("Vulnerabilities: not checked (the scan ran without a vulnerability lookup)")
    else:
        lines += _vulnerabilities(report)
    lines += ["", _result_line(scan), "", _DISCLAIMER]
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


def _vulnerabilities(report: VulnerabilityReport) -> list[str]:
    source = report.provider.upper()
    data = {
        "live": f"live data, retrieved {_when(report.checked_at)}",
        "cache": f"cached data, oldest retrieved {_when(report.oldest_data_at)}",
        "mixed": f"live and cached data, oldest retrieved {_when(report.oldest_data_at)}",
        "none": "no data available",
    }[report.data_source.value]
    lines = [f"Vulnerabilities ({source}, {data}):"]
    by_status: dict[CheckStatus, list[PackageCheck]] = {status: [] for status in CheckStatus}
    for check in report.checks:
        by_status[check.status].append(check)
    affected = sorted(by_status[CheckStatus.AFFECTED], key=lambda c: (package_name(c), c.version))
    advisories = {a.id: a for a in report.advisories}

    counts = [
        f"{len(by_status[CheckStatus.AFFECTED])} affected",
        f"{len(by_status[CheckStatus.NO_MATCHING_ADVISORY])} with no matching advisory",
        f"{len(by_status[CheckStatus.UNKNOWN])} unknown",
        f"{len(by_status[CheckStatus.NOT_CHECKED])} not checked",
        f"{len(by_status[CheckStatus.LOOKUP_FAILED])} lookup failed",
    ]
    lines.append("  Packages: " + ", ".join(counts))

    if affected:
        lines.append("")
        for check in affected:
            lines += _affected(check, advisories)
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


def _affected(check: PackageCheck, advisories: dict[str, Advisory]) -> list[str]:
    version = clean_text(check.version or "")
    lines = [f"  {package_name(check)} {version}"]
    for group in group_findings(check.findings, advisories):
        finding, copies = group[0], group[1:]
        advisory = advisories[finding.advisory_id]
        shown = {advisory.id, *(f.advisory_id for f in copies)}
        aliases = [clean_text(a) for a in advisory.aliases if a not in shown]
        alias_text = f" ({', '.join(aliases)})" if aliases else ""
        lines.append(f"    {clean_text(advisory.id)}{alias_text}")
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
            lines.append(f"      fixed in: {', '.join(clean_text(v) for v in fixed_versions)}")
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


def _result_line(scan: ScanResult) -> str:
    report = scan.vulnerabilities
    affected = sum(1 for c in report.checks if c.status is CheckStatus.AFFECTED) if report else 0
    vulns = scan.vulnerability_status
    analysis = scan.completion.value.replace("_", " ")
    if affected:
        headline = f"Result: {_plural(affected, 'affected package')} found."
    elif vulns is VulnerabilityStatus.COMPLETE:
        headline = "Result: no package matched a known advisory."
    elif vulns is VulnerabilityStatus.NOT_QUERIED:
        headline = "Result: vulnerabilities were not checked."
    else:
        headline = "Result: no affected package found, but the check was incomplete."
    return f"{headline} Dependency analysis: {analysis}. Vulnerability check: {vulns.value}."
