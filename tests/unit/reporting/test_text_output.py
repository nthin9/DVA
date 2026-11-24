"""The terminal summary: ordering, counts, wording, brief mode and colour."""

from __future__ import annotations

import io
from datetime import UTC, datetime

from dva.domain.advisory import Advisory
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
from dva.reporting.overview import findings_by_severity, severity_rank
from dva.reporting.style import Style, colour_wanted
from dva.reporting.text import render_brief, render_text

T0 = datetime(2026, 3, 1, tzinfo=UTC)


def affected(name: str, *advisory_ids: str) -> PackageCheck:
    return PackageCheck(
        PackageIdentity("npm", name),
        "1.0.0",
        CheckStatus.AFFECTED,
        (Location("package-lock.json", f"node_modules/{name}"),),
        findings=tuple(Finding(a, ("range",)) for a in advisory_ids),
    )


def scan_with(*checks: PackageCheck, advisories: tuple[Advisory, ...]) -> ScanResult:
    report = VulnerabilityReport("osv", T0, DataSource.LIVE, checks, advisories, T0)
    return ScanResult("0.0.1", "demo", T0, T0, vulnerabilities=report)


ADVISORIES = (
    Advisory("GHSA-low", T0, database_severity="LOW", summary="minor"),
    Advisory("GHSA-crit", T0, database_severity="CRITICAL", summary="bad"),
    Advisory("GHSA-high", T0, database_severity="HIGH"),
    # Same vulnerability as GHSA-high, published again by another database.
    Advisory("PYSEC-copy", T0, aliases=("GHSA-high",)),
    Advisory("GHSA-none", T0),
)


def test_severity_rank_uses_only_the_database_label() -> None:
    assert [severity_rank(x) for x in ("CRITICAL", "High", "MODERATE", "medium", "low")] == [
        4,
        3,
        2,
        2,
        1,
    ]
    assert severity_rank(None) == 0 and severity_rank("weird") == 0


def test_affected_packages_are_listed_most_severe_first() -> None:
    scan = scan_with(
        affected("aaa", "GHSA-low"),
        affected("zzz", "GHSA-crit"),
        affected("mmm", "GHSA-high", "PYSEC-copy"),
        advisories=ADVISORIES,
    )
    text = render_text(scan)
    assert text.index("zzz 1.0.0") < text.index("mmm 1.0.0") < text.index("aaa 1.0.0")
    # Copies of one vulnerability count once.
    assert "Advisories by the database's rating: 1 critical, 1 high, 1 low" in text
    counts = findings_by_severity(list(scan.vulnerabilities.checks), {a.id: a for a in ADVISORIES})  # type: ignore[union-attr]
    assert counts == {"critical": 1, "high": 1, "low": 1}


def test_unrated_advisories_are_counted_separately() -> None:
    text = render_text(scan_with(affected("x", "GHSA-none"), advisories=ADVISORIES))
    assert "1 without a rating" in text


def test_result_line_uses_plain_words_and_the_disclaimer_needs_a_check() -> None:
    unchecked = ScanResult("0.0.1", "demo", T0, T0)
    text = render_text(unchecked)
    assert "not_queried" not in text and "no_supported_files" not in text
    assert "Vulnerability check: not run." in text
    assert "not proof that a package is safe" not in text
    checked = render_text(scan_with(advisories=()))
    assert "not proof that a package is safe" in checked


def test_brief_has_one_line_per_affected_package() -> None:
    scan = scan_with(
        affected("aaa", "GHSA-low"),
        affected("zzz", "GHSA-crit", "GHSA-high"),
        advisories=ADVISORIES,
    )
    lines = render_brief(scan).splitlines()
    assert lines[1] == "  zzz 1.0.0: 2 advisories (1 critical, 1 high)"
    assert lines[2] == "  aaa 1.0.0: 1 advisory (1 low)"
    assert lines[-1].startswith("Result: 2 affected packages found.")


def test_colour_wraps_only_cleaned_text() -> None:
    hostile = Advisory("GHSA-crit", T0, database_severity="CRITICAL", summary="\x1b[2Jboom")
    scan = scan_with(affected("evil\x1b]0;x\x07", "GHSA-crit"), advisories=(hostile,))
    coloured = render_text(scan, Style(True))
    assert "\x1b[" in coloured  # DVA's own colour codes are there...
    # ...but none from the advisory or the package name survive.
    assert "\x1b[2J" not in coloured and "\x1b]0;" not in coloured and "\x07" not in coloured
    assert "\x1b" not in render_text(scan)


class FakeTerminal(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


def test_colour_choice() -> None:
    assert colour_wanted("never", FakeTerminal(True), {}) is False
    assert colour_wanted("always", FakeTerminal(False), {}) is True
    assert colour_wanted("auto", FakeTerminal(False), {}) is False
    assert colour_wanted("auto", FakeTerminal(True), {"NO_COLOR": "1"}) is False
    assert colour_wanted("auto", FakeTerminal(True), {"TERM": "dumb"}) is False
