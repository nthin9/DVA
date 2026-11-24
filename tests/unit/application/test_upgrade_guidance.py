"""Upgrade suggestions and how a package is pulled in."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from dva.application.vulnerabilities import check_vulnerabilities
from dva.domain.dependency import DependencyEdge, ResolvedPackage, SourceKind
from dva.domain.manifest import ManifestAnalysis, ManifestKind, ParseStatus
from dva.domain.scan import ScanResult
from dva.domain.vulnerability import CheckStatus, PackageCheck
from dva.ecosystems.npm.names import identity
from dva.intelligence.osv.source import OsvSource
from dva.reporting.overview import introduced_by
from dva.reporting.text import render_text
from dva.storage.advisory_cache import SqliteAdvisoryCache
from dva.storage.database import open_database
from tests.support.osv_fake import FakeOsvTransport

T0 = datetime(2026, 3, 1, tzinfo=UTC)


def record(advisory_id: str, *ranges: tuple[str, str | None], name: str = "pkg") -> dict[str, Any]:
    """An OSV record for npm ``name`` with SEMVER ranges (introduced, fixed)."""
    events = []
    for introduced, fixed in ranges:
        events.append({"introduced": introduced})
        if fixed is not None:
            events.append({"fixed": fixed})
    return {
        "id": advisory_id,
        "modified": "2026-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": name},
                "ranges": [{"type": "SEMVER", "events": events}],
            }
        ],
    }


def lock(*packages: tuple[str, str], edges: tuple[tuple[str | None, str], ...] = ()) -> ScanResult:
    manifest = ManifestAnalysis(
        "package-lock.json",
        "npm",
        "npm",
        ManifestKind.LOCKFILE,
        "package-lock",
        ParseStatus.PARSED,
        packages=tuple(
            ResolvedPackage(f"node_modules/{n}", identity(n), v, source=SourceKind.REGISTRY)
            for n, v in packages
        ),
        edges=tuple(DependencyEdge(p, c) for p, c in edges),
    )
    return ScanResult("0.0.1", "demo", T0, T0, manifests=(manifest,))


def checked(scan: ScanResult, *records: dict[str, Any]) -> PackageCheck:
    transport = FakeOsvTransport({("npm", "pkg"): [r["id"] for r in records]})
    for r in records:
        transport.records[r["id"]] = r
    cache = SqliteAdvisoryCache(open_database(":memory:"))
    result = check_vulnerabilities(scan, OsvSource(transport), cache, clock=lambda: T0)
    assert result.vulnerabilities is not None
    (check,) = [c for c in result.vulnerabilities.checks if c.identity.name == "pkg"]
    return check


def test_the_lowest_fix_that_clears_every_advisory_is_suggested() -> None:
    check = checked(
        lock(("pkg", "1.0.0")),
        record("A-1", ("0", "1.2.0")),
        record("A-2", ("0", "1.5.0")),
    )
    assert check.status is CheckStatus.AFFECTED
    assert (check.upgrade_to, check.upgrade_note) == ("1.5.0", None)


def test_a_fix_affected_by_another_advisory_is_skipped() -> None:
    # 1.5.0 fixes A-1, but A-3 affects 1.5.0 up to 1.8.0 (not the current 1.0.0).
    check = checked(
        lock(("pkg", "1.0.0")),
        record("A-1", ("0", "1.5.0")),
        record("A-3", ("1.5.0", "1.8.0")),
    )
    assert [f.advisory_id for f in check.findings] == ["A-1"]
    assert check.upgrade_to == "1.8.0"


def test_an_advisory_without_a_fix_means_no_suggestion() -> None:
    check = checked(
        lock(("pkg", "1.0.0")), record("A-1", ("0", "1.5.0")), record("A-2", ("0", None))
    )
    assert check.upgrade_to is None
    assert check.upgrade_note == "an advisory for this version names no fixed version"


def test_versions_are_ordered_by_the_ecosystem_rules() -> None:
    # 2.0.0-rc.1 sorts after 1.9.0 and before 2.0.0 under Semantic Versioning.
    check = checked(
        lock(("pkg", "1.0.0")),
        record("A-1", ("0", "1.9.0")),
        record("A-2", ("0", "2.0.0-rc.1")),
        record("A-3", ("0", "10.0.0"), ("11.0.0", "12.0.0")),
    )
    assert check.upgrade_to == "10.0.0"


def test_no_single_version_when_every_fix_is_affected_again() -> None:
    check = checked(
        lock(("pkg", "1.0.0")),
        record("A-1", ("0", "1.5.0")),
        record("A-2", ("1.5.0", None)),
    )
    assert check.upgrade_to is None
    assert "no single fixed version" in (check.upgrade_note or "")


def test_unaffected_packages_get_no_guidance() -> None:
    check = checked(lock(("pkg", "2.0.0")), record("A-1", ("0", "1.5.0")))
    assert check.status is CheckStatus.NO_MATCHING_ADVISORY
    assert check.upgrade_to is None and check.upgrade_note is None


def test_introduced_by_finds_the_shortest_chain_and_survives_cycles() -> None:
    nm = "node_modules/"
    scan = lock(
        ("app", "1.0.0"),
        ("mid", "1.0.0"),
        ("deep", "1.0.0"),
        ("pkg", "1.0.0"),
        ("loop", "1.0.0"),
        ("back", "1.0.0"),
        edges=(
            (None, nm + "app"),
            (nm + "app", nm + "mid"),
            (nm + "mid", nm + "deep"),
            (nm + "deep", nm + "pkg"),
            (nm + "app", nm + "pkg"),
            (nm + "loop", nm + "back"),
            (nm + "back", nm + "loop"),
        ),
    )
    paths = introduced_by(scan)
    assert paths[("package-lock.json", nm + "app")] == []
    assert paths[("package-lock.json", nm + "pkg")] == ["app"]
    assert paths[("package-lock.json", nm + "deep")] == ["app", "mid"]
    assert ("package-lock.json", nm + "loop") not in paths


def test_summary_shows_the_guidance() -> None:
    scan = lock(
        ("app", "1.0.0"),
        ("pkg", "1.0.0"),
        edges=((None, "node_modules/app"), ("node_modules/app", "node_modules/pkg")),
    )
    transport = FakeOsvTransport({("npm", "pkg"): ["A-1"]})
    transport.records["A-1"] = record("A-1", ("0", "1.5.0"))
    cache = SqliteAdvisoryCache(open_database(":memory:"))
    text = render_text(check_vulnerabilities(scan, OsvSource(transport), cache))
    assert "upgrade to 1.5.0 clears the advisory listed here" in text
    assert "OSV lists no advisory affecting 1.5.0" in text
    assert "pulled in by: app" in text
