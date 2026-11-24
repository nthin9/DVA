"""Accepted risks: matching, expiry, files, and what reports and exit codes do."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from dva.application.acceptance import (
    AcceptanceFileError,
    apply_acceptances,
    read_acceptance_file,
    unaccepted,
)
from dva.cli import EXIT_AFFECTED, exit_code
from dva.domain.acceptance import Acceptance
from dva.domain.advisory import Advisory
from dva.domain.deserialization import loads_scan
from dva.domain.identity import PackageIdentity
from dva.domain.scan import ScanResult
from dva.domain.serialization import dumps_scan
from dva.domain.vulnerability import (
    CheckStatus,
    DataSource,
    Finding,
    Location,
    PackageCheck,
    VulnerabilityReport,
)
from dva.reporting.text import render_brief, render_text

T0 = datetime(2026, 3, 1, tzinfo=UTC)
TODAY = date(2026, 3, 1)
ADVISORIES = (
    Advisory("GHSA-aaaa", T0, aliases=("CVE-2026-1",), summary="first"),
    Advisory("PYSEC-1", T0, aliases=("GHSA-aaaa",)),  # A copy of the same vulnerability.
    Advisory("GHSA-bbbb", T0, summary="second"),
)


def scan(*packages: tuple[str, tuple[str, ...]]) -> ScanResult:
    checks = tuple(
        PackageCheck(
            PackageIdentity("pypi", name),
            "1.0",
            CheckStatus.AFFECTED,
            (Location("requirements.txt", line=1),),
            findings=tuple(Finding(a, ("range",)) for a in ids),
        )
        for name, ids in packages
    )
    report = VulnerabilityReport("osv", T0, DataSource.LIVE, checks, ADVISORIES, T0)
    return ScanResult("0.0.1", "demo", T0, T0, vulnerabilities=report)


def accepted_ids(result: ScanResult) -> set[tuple[str, str]]:
    assert result.vulnerabilities is not None
    return {
        (c.identity.name, f.advisory_id)
        for c in result.vulnerabilities.checks
        for f in c.findings
        if f.accepted is not None
    }


def test_an_alias_accepts_every_copy_of_the_vulnerability() -> None:
    base = scan(("lib", ("GHSA-aaaa", "PYSEC-1", "GHSA-bbbb")))
    result = apply_acceptances(base, [Acceptance("cve-2026-1", "not reachable")], TODAY)
    assert accepted_ids(result) == {("lib", "GHSA-aaaa"), ("lib", "PYSEC-1")}
    assert exit_code(result) == EXIT_AFFECTED  # GHSA-bbbb is still open.


def test_fully_accepted_findings_no_longer_fail_but_stay_listed() -> None:
    base = scan(("lib", ("GHSA-bbbb",)))
    result = apply_acceptances(base, [Acceptance("GHSA-bbbb", "tracked in TICKET-1")], TODAY)
    assert result.vulnerabilities is not None
    (check,) = result.vulnerabilities.checks
    assert check.status is CheckStatus.AFFECTED and not unaccepted(check)
    assert exit_code(result) != EXIT_AFFECTED
    text = render_text(result)
    assert "lib 1.0 (accepted risk)" in text and "accepted risk: tracked in TICKET-1" in text
    assert "found, all accepted risks" in text
    assert "accepted risk" in render_brief(result)


def test_package_scope_and_name_normalization() -> None:
    base = scan(("my-lib", ("GHSA-bbbb",)), ("other", ("GHSA-bbbb",)))
    result = apply_acceptances(base, [Acceptance("GHSA-bbbb", "ok", package="My_Lib")], TODAY)
    assert accepted_ids(result) == {("my-lib", "GHSA-bbbb")}


def test_expired_and_unused_acceptances_are_reported() -> None:
    base = scan(("lib", ("GHSA-bbbb",)))
    result = apply_acceptances(
        base,
        [
            Acceptance("GHSA-bbbb", "old", until=date(2026, 2, 28)),
            Acceptance("GHSA-zzzz", "nothing matches"),
        ],
        TODAY,
    )
    assert accepted_ids(result) == set()
    assert exit_code(result) == EXIT_AFFECTED
    assert result.vulnerabilities is not None
    codes = {d.code for d in result.vulnerabilities.diagnostics}
    assert codes == {"vulnerabilities.acceptance_expired", "vulnerabilities.acceptance_unused"}
    # The last day itself still counts.
    still = apply_acceptances(base, [Acceptance("GHSA-bbbb", "ok", until=TODAY)], TODAY)
    assert accepted_ids(still) == {("lib", "GHSA-bbbb")}


def test_acceptances_survive_the_json_round_trip() -> None:
    result = apply_acceptances(
        scan(("lib", ("GHSA-bbbb",))),
        [Acceptance("GHSA-bbbb", "ok", package="lib", until=date(2027, 1, 1))],
        TODAY,
    )
    text = dumps_scan(result)
    assert dumps_scan(loads_scan(text)) == text
    assert '"until": "2027-01-01"' in text


@pytest.mark.parametrize(
    ("advisory", "reason"),
    [("", "x"), ("GHSA x", "x"), ("GHSA-1", ""), ("GHSA-1", "   "), ("GHSA-1", "a\x1bb")],
)
def test_invalid_acceptances_are_refused(advisory: str, reason: str) -> None:
    with pytest.raises(ValueError):
        Acceptance(advisory, reason)


def test_acceptance_file(tmp_path: Path) -> None:
    good = tmp_path / "accept.toml"
    good.write_text(
        '[[accept]]\nadvisory = "CVE-2026-1"\nreason = "not used"\nuntil = 2026-12-31\n\n'
        '[[accept]]\nadvisory = "GHSA-bbbb"\npackage = "lib"\nreason = "tracked"\n'
        'until = "2027-01-01"\n',
        encoding="utf-8",
    )
    first, second = read_acceptance_file(good)
    assert first == Acceptance("CVE-2026-1", "not used", None, date(2026, 12, 31))
    assert second.package == "lib" and second.until == date(2027, 1, 1)


@pytest.mark.parametrize(
    "content",
    [
        "not toml [",
        "other = 1\n",
        '[[accept]]\nadvisory = "X"\n',
        '[[accept]]\nadvisory = "X"\nreason = "r"\nextra = 1\n',
        '[[accept]]\nadvisory = "X"\nreason = "r"\nuntil = "soon"\n',
        '[[accept]]\nadvisory = "X"\nreason = "r"\nuntil = 2026-01-01T10:00:00\n',
        '[[accept]]\nadvisory = "has space"\nreason = "r"\n',
    ],
)
def test_bad_acceptance_files_are_refused(tmp_path: Path, content: str) -> None:
    path = tmp_path / "accept.toml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(AcceptanceFileError):
        read_acceptance_file(path)


def test_oversized_and_missing_files_are_refused(tmp_path: Path) -> None:
    big = tmp_path / "big.toml"
    big.write_text("# " + "x" * (1024 * 1024 + 1), encoding="utf-8")
    with pytest.raises(AcceptanceFileError):
        read_acceptance_file(big)
    with pytest.raises(AcceptanceFileError):
        read_acceptance_file(tmp_path / "missing.toml")
