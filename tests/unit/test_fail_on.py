"""--fail-on: which findings make the exit code 1."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dva.cli import EXIT_AFFECTED, EXIT_CLEAN, EXIT_INCOMPLETE, FAIL_LEVELS, exit_code
from dva.domain.acceptance import Acceptance
from dva.domain.advisory import Advisory
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.identity import PackageIdentity
from dva.domain.scan import ScanResult
from dva.domain.vulnerability import (
    CheckStatus,
    DataSource,
    Finding,
    Location,
    PackageCheck,
    VulnerabilityReport,
)

T0 = datetime(2026, 3, 1, tzinfo=UTC)


def scan(label: str | None, *, accepted: bool = False, incomplete: bool = False) -> ScanResult:
    advisory = Advisory("GHSA-x", T0, database_severity=label)
    finding = Finding(
        "GHSA-x", ("range",), accepted=Acceptance("GHSA-x", "ok") if accepted else None
    )
    check = PackageCheck(
        PackageIdentity("npm", "pkg"),
        "1.0.0",
        CheckStatus.AFFECTED,
        (Location("package-lock.json", "node_modules/pkg"),),
        findings=(finding,),
    )
    report = VulnerabilityReport("osv", T0, DataSource.LIVE, (check,), (advisory,), T0)
    notes = (Diagnostic("discovery.depth_limit", DiagnosticLevel.WARNING, "deep"),)
    return ScanResult(
        "0.0.1", "demo", T0, T0, vulnerabilities=report, diagnostics=notes if incomplete else ()
    )


@pytest.mark.parametrize(
    ("label", "passing_levels"),
    [
        ("CRITICAL", ()),
        ("HIGH", ("critical",)),
        ("MODERATE", ("high", "critical")),
        ("MEDIUM", ("high", "critical")),
        ("LOW", ("moderate", "high", "critical")),
    ],
)
def test_each_level(label: str, passing_levels: tuple[str, ...]) -> None:
    for level in FAIL_LEVELS:
        expected = EXIT_CLEAN if level in passing_levels else EXIT_AFFECTED
        assert exit_code(scan(label), level) == expected, (label, level)


def test_unrated_advisories_always_fail() -> None:
    assert exit_code(scan(None), "critical") == EXIT_AFFECTED
    assert exit_code(scan("weird"), "critical") == EXIT_AFFECTED


def test_accepted_findings_never_fail() -> None:
    assert exit_code(scan("CRITICAL", accepted=True), "any") == EXIT_CLEAN


def test_below_the_threshold_an_incomplete_scan_still_says_so() -> None:
    assert exit_code(scan("LOW", incomplete=True), "high") == EXIT_INCOMPLETE
    assert exit_code(scan("CRITICAL", incomplete=True), "high") == EXIT_AFFECTED
