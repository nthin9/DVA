"""Marking findings as accepted risks, and reading acceptance files.

Acceptances only come from places the user chose: a file passed with
``--accept-file``, or the ones saved with a registered project. DVA never
reads them from the scanned folder on its own, so a project can't silence
its own findings.
"""

from __future__ import annotations

import tomllib
from collections.abc import Sequence
from dataclasses import replace
from datetime import date
from pathlib import Path

from dva.domain.acceptance import Acceptance
from dva.domain.advisory import Advisory
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.scan import ScanResult
from dva.domain.vulnerability import Finding, PackageCheck
from dva.matching.schemes import scheme_for

#: The largest acceptance file DVA reads.
MAX_FILE_BYTES = 1024 * 1024
_KEYS = {"advisory", "reason", "package", "until"}


class AcceptanceFileError(ValueError):
    """An acceptance file can't be used. Messages name the entry, not file contents."""


def read_acceptance_file(path: Path) -> tuple[Acceptance, ...]:
    """Parse a TOML file of ``[[accept]]`` entries."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise AcceptanceFileError("the acceptance file is larger than 1 MiB")
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError:
        raise AcceptanceFileError("the acceptance file can't be read") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        raise AcceptanceFileError("the acceptance file is not valid TOML") from None
    unknown_top = set(data) - {"accept"}
    if unknown_top:
        raise AcceptanceFileError("the acceptance file may only contain [[accept]] entries")
    entries = data.get("accept", [])
    if not isinstance(entries, list):
        raise AcceptanceFileError("'accept' must be a list of [[accept]] entries")
    found = []
    for number, entry in enumerate(entries, start=1):
        where = f"[[accept]] entry {number}"
        if not isinstance(entry, dict):
            raise AcceptanceFileError(f"{where} is not a table")
        if set(entry) - _KEYS:
            raise AcceptanceFileError(f"{where} has keys other than {', '.join(sorted(_KEYS))}")
        advisory, reason = entry.get("advisory"), entry.get("reason")
        package, until = entry.get("package"), entry.get("until")
        if not isinstance(advisory, str) or not isinstance(reason, str):
            raise AcceptanceFileError(f"{where} needs an advisory and a reason")
        if package is not None and not isinstance(package, str):
            raise AcceptanceFileError(f"{where}: package must be text")
        if isinstance(until, str):
            try:
                until = date.fromisoformat(until)
            except ValueError:
                raise AcceptanceFileError(f"{where}: until must be a date (YYYY-MM-DD)") from None
        if until is not None and (not isinstance(until, date) or hasattr(until, "hour")):
            raise AcceptanceFileError(f"{where}: until must be a date (YYYY-MM-DD)")
        try:
            found.append(Acceptance(advisory, reason, package, until))
        except ValueError as error:
            raise AcceptanceFileError(f"{where}: {error}") from None
    return tuple(found)


def _same_package(acceptance: Acceptance, check: PackageCheck) -> bool:
    if acceptance.package is None:
        return True
    identity = check.identity
    full = f"{identity.namespace}/{identity.name}" if identity.namespace else identity.name
    scheme = scheme_for(identity.ecosystem)
    if scheme is not None:
        return scheme.same_package(acceptance.package, full)
    return acceptance.package.casefold() == full.casefold()


def _copies(findings: tuple[Finding, ...], advisories: dict[str, Advisory]) -> list[set[str]]:
    """For each finding, every id that names the same vulnerability: its own
    id and aliases, joined with those of other findings that share one."""
    names = []
    for finding in findings:
        advisory = advisories.get(finding.advisory_id)
        names.append({finding.advisory_id, *(advisory.aliases if advisory else ())})
    changed = True
    while changed:
        changed = False
        for i in range(len(names)):
            for j in range(len(names)):
                if i != j and names[i] & names[j] and not names[j] <= names[i]:
                    names[i] |= names[j]
                    changed = True
    return names


def apply_acceptances(
    scan: ScanResult, acceptances: Sequence[Acceptance], today: date
) -> ScanResult:
    """Mark findings that an acceptance covers, and note expired or unused ones."""
    report = scan.vulnerabilities
    if report is None or not acceptances:
        return scan
    advisories = {a.id: a for a in report.advisories}
    used: set[Acceptance] = set()
    expired: set[Acceptance] = set()
    checks = []
    for check in report.checks:
        if not check.findings:
            checks.append(check)
            continue
        findings = []
        for finding, ids in zip(check.findings, _copies(check.findings, advisories), strict=True):
            chosen = None
            for acceptance in acceptances:
                if acceptance.names(ids) and _same_package(acceptance, check):
                    if acceptance.expired(today):
                        expired.add(acceptance)
                    elif chosen is None:
                        chosen = acceptance
                        used.add(acceptance)
            findings.append(replace(finding, accepted=chosen))
        checks.append(replace(check, findings=tuple(findings)))

    notes = [
        Diagnostic(
            "vulnerabilities.acceptance_expired",
            DiagnosticLevel.INFO,
            f"the acceptance of {a.advisory} expired on {a.until}; the finding counts again",
        )
        for a in sorted(expired, key=lambda a: (a.advisory, a.package or ""))
        if a not in used
    ]
    notes += [
        Diagnostic(
            "vulnerabilities.acceptance_unused",
            DiagnosticLevel.INFO,
            f"the acceptance of {a.advisory}"
            + (f" for {a.package}" if a.package else "")
            + " matched no finding in this scan",
        )
        for a in sorted(
            set(acceptances) - used - expired, key=lambda a: (a.advisory, a.package or "")
        )
    ]
    new_report = replace(report, checks=tuple(checks), diagnostics=(*report.diagnostics, *notes))
    return replace(scan, vulnerabilities=new_report)


def unaccepted(check: PackageCheck) -> list[Finding]:
    return [f for f in check.findings if f.accepted is None]
