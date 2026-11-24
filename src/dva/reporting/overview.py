"""Counts and groupings shared by every output format.

Reports only present what the scan already decided; nothing here analyzes
anything. Keeping the counting in one place means the terminal summary, the
JSON report and the HTML report always agree.
"""

from __future__ import annotations

import unicodedata
from collections import Counter
from dataclasses import dataclass

from dva.domain.advisory import Advisory
from dva.domain.manifest import ManifestKind
from dva.domain.scan import ScanResult
from dva.domain.vulnerability import CheckStatus, Finding, PackageCheck

type JsonValue = str | int | bool | None | list[JsonValue] | dict[str, JsonValue]


def clean_text(value: str) -> str:
    """Untrusted text made safe to print: control and invisible formatting
    characters (terminal escape codes, bidirectional overrides) become ``?``,
    and line breaks become spaces."""
    out = []
    for char in value:
        if char in "\r\n\t":
            out.append(" ")
        elif unicodedata.category(char) in ("Cc", "Cf", "Cs", "Co", "Cn"):
            out.append("?")
        else:
            out.append(char)
    return "".join(out)


def package_name(check: PackageCheck) -> str:
    identity = check.identity
    name = f"{identity.namespace}/{identity.name}" if identity.namespace else identity.name
    return clean_text(name)


def group_findings(
    findings: tuple[Finding, ...], advisories: dict[str, Advisory]
) -> list[list[Finding]]:
    """Findings grouped so that copies of one vulnerability appear together.

    Databases often publish the same issue under their own ids (a GitHub
    ``GHSA-`` advisory and a PyPI ``PYSEC-`` one, say) and list each other as
    aliases. Each group starts with the most informative record: one with a
    summary and the database's own severity label, then the lowest id.
    """
    groups: list[list[Finding]] = []
    ids_of: list[set[str]] = []
    for finding in sorted(findings, key=lambda f: f.advisory_id):
        advisory = advisories.get(finding.advisory_id)
        names = {finding.advisory_id, *(advisory.aliases if advisory else ())}
        for index, known in enumerate(ids_of):
            if known & names:
                groups[index].append(finding)
                known |= names
                break
        else:
            groups.append([finding])
            ids_of.append(set(names))

    def richness(finding: Finding) -> tuple[int, str]:
        advisory = advisories.get(finding.advisory_id)
        score = 0
        if advisory is not None:
            score = int(bool(advisory.summary)) + int(bool(advisory.database_severity))
        return (-score, finding.advisory_id)

    return [sorted(group, key=richness) for group in groups]


#: The database severity labels DVA orders, most severe first. Databases use
#: "MODERATE" (GitHub) or "MEDIUM"; both are the same level here.
SEVERITY_LEVELS = ("critical", "high", "moderate", "low")
_RANKS = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}
UNRATED = "unrated"


def severity_rank(label: str | None) -> int:
    """How severe a database's own label is: 4 for critical down to 1 for low,
    0 when there is no label DVA recognizes. DVA never computes a severity."""
    return _RANKS.get((label or "").strip().lower(), 0)


def severity_name(rank: int) -> str:
    return SEVERITY_LEVELS[4 - rank] if rank else UNRATED


def group_rank(group: list[Finding], advisories: dict[str, Advisory]) -> int:
    """The most severe label among one vulnerability's copies."""
    return max(
        (
            severity_rank(advisories[f.advisory_id].database_severity)
            for f in group
            if f.advisory_id in advisories
        ),
        default=0,
    )


def check_rank(check: PackageCheck, advisories: dict[str, Advisory]) -> int:
    """The most severe label among the vulnerabilities affecting one package version."""
    return max(
        (group_rank(g, advisories) for g in group_findings(check.findings, advisories)),
        default=0,
    )


def findings_by_severity(
    checks: tuple[PackageCheck, ...] | list[PackageCheck], advisories: dict[str, Advisory]
) -> dict[str, int]:
    """How many vulnerabilities (copies counted once) affect each package version,
    by label, most severe first; levels with none are left out."""
    counts: Counter[str] = Counter()
    for check in checks:
        for group in group_findings(check.findings, advisories):
            counts[severity_name(group_rank(group, advisories))] += 1
    return {name: counts[name] for name in (*SEVERITY_LEVELS, UNRATED) if counts[name]}


@dataclass(frozen=True, slots=True)
class Overview:
    files_by_status: dict[str, int]
    files_by_kind: dict[str, int]
    declared_requirements: int
    resolved_packages: int
    direct_dependencies: int
    outcomes: dict[str, int]
    advisories: int

    @classmethod
    def of(cls, scan: ScanResult) -> Overview:
        files = Counter(m.status.value for m in scan.manifests)
        kinds = Counter(m.kind.value for m in scan.manifests)
        direct = sum(
            len({e.child_id for e in m.edges if e.is_direct})
            for m in scan.manifests
            if m.kind is ManifestKind.LOCKFILE
        )
        report = scan.vulnerabilities
        outcomes = Counter(c.status.value for c in report.checks) if report else Counter()
        return cls(
            files_by_status=dict(sorted(files.items())),
            files_by_kind=dict(sorted(kinds.items())),
            declared_requirements=sum(len(m.requirements) for m in scan.manifests),
            resolved_packages=sum(len(m.packages) for m in scan.manifests),
            direct_dependencies=direct,
            outcomes={status.value: outcomes.get(status.value, 0) for status in CheckStatus},
            advisories=len(report.advisories) if report else 0,
        )

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "files_by_status": dict(self.files_by_status),
            "files_by_kind": dict(self.files_by_kind),
            "declared_requirements": self.declared_requirements,
            "resolved_packages": self.resolved_packages,
            "direct_dependencies": self.direct_dependencies,
            "outcomes": dict(self.outcomes),
            "advisories": self.advisories,
        }
