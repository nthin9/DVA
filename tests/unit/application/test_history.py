from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from dva.application.analyze import analyze_project
from dva.application.history import (
    ProjectRootError,
    UnknownScanError,
    compare_digests,
    compare_scans,
    digest_scan,
    register_project,
    rescan_project,
)
from dva.contracts.history import DuplicateProjectError
from dva.domain.history import (
    DigestEntry,
    GoneReason,
    PackageRef,
    ScanDigest,
    ScanRecord,
    ScanSummary,
    require_project_name,
)
from dva.domain.scan import CompletionState
from dva.domain.serialization import dumps_scan
from dva.domain.vulnerability import CheckStatus, DataSource, VulnerabilityStatus
from dva.ecosystems.registry import default_registry
from dva.storage.database import open_database
from dva.storage.history import SqliteHistoryStore

T0 = datetime(2026, 1, 1, tzinfo=UTC)
T1 = datetime(2026, 2, 1, tzinfo=UTC)
LODASH = PackageRef("npm", None, "lodash")
BABEL = PackageRef("npm", "@babel", "core")
IDNA = PackageRef("pypi", None, "idna")
AFFECTED, CLEAN = CheckStatus.AFFECTED, CheckStatus.NO_MATCHING_ADVISORY
FIXTURES = Path(__file__).parents[2] / "fixtures"


def summary(
    when: datetime = T0, status: VulnerabilityStatus = VulnerabilityStatus.COMPLETE
) -> ScanSummary:
    source = None if status is VulnerabilityStatus.NOT_QUERIED else DataSource.LIVE
    return ScanSummary("0.0.1", when, when, CompletionState.COMPLETE, status, source)


def record(scan_id: int, when: datetime = T0) -> ScanRecord:
    return ScanRecord(scan_id, 1, summary(when), 0, 0, 0)


def entry(
    package: PackageRef, version: str | None, status: CheckStatus | None, *advisories: str
) -> DigestEntry:
    return DigestEntry(package, version, status, tuple(advisories))


def compare(old: list[DigestEntry], new: list[DigestEntry], **kwargs: tuple[str, ...]):  # type: ignore[no-untyped-def]
    return compare_digests(
        record(1),
        ScanDigest(summary(T0), kwargs.get("old_files", ()), tuple(old)),
        record(2, T1),
        ScanDigest(summary(T1), kwargs.get("new_files", ()), tuple(new)),
    )


def test_identical_scans_have_no_changes() -> None:
    entries = [entry(LODASH, "4.17.20", AFFECTED, "GHSA-1"), entry(IDNA, "3.10", CLEAN)]
    result = compare(entries, entries, old_files=("package.json",), new_files=("package.json",))
    assert not result.has_changes


def test_added_removed_and_changed_packages() -> None:
    result = compare(
        [entry(LODASH, "4.17.20", CLEAN), entry(IDNA, "3.10", CLEAN)],
        [entry(LODASH, "4.17.21", CLEAN), entry(BABEL, "7.26.0", CLEAN)],
    )
    assert result.packages_added == (BABEL,)
    assert result.packages_removed == (IDNA,)
    (change,) = result.versions_changed
    assert (change.package, change.old_versions, change.new_versions) == (
        LODASH,
        ("4.17.20",),
        ("4.17.21",),
    )


def test_versions_are_listed_in_ecosystem_order_not_text_order() -> None:
    result = compare(
        [entry(LODASH, "1.0.0", CLEAN)],
        [entry(LODASH, "10.0.0", CLEAN), entry(LODASH, "9.0.0", CLEAN)],
    )
    assert result.versions_changed[0].new_versions == ("9.0.0", "10.0.0")


def test_a_package_with_several_versions_changes_when_one_does() -> None:
    old = [entry(LODASH, "3.10.1", CLEAN), entry(LODASH, "4.17.21", CLEAN)]
    new = [entry(LODASH, "4.17.21", CLEAN)]
    (change,) = compare(old, new).versions_changed
    assert change.new_versions == ("4.17.21",)


def test_new_findings() -> None:
    result = compare(
        [entry(LODASH, "4.17.20", CLEAN)], [entry(LODASH, "4.17.20", AFFECTED, "GHSA-1")]
    )
    assert [(f.package, f.version, f.advisory_id) for f in result.new_findings] == [
        (LODASH, "4.17.20", "GHSA-1")
    ]
    assert not result.versions_changed


@pytest.mark.parametrize(
    ("new", "reason"),
    [
        ([], GoneReason.PACKAGE_REMOVED),
        ([entry(LODASH, "4.17.21", CLEAN)], GoneReason.VERSION_CHANGED),
        ([entry(LODASH, "4.17.20", CLEAN)], GoneReason.NO_LONGER_MATCHED),
        ([entry(LODASH, "4.17.20", AFFECTED, "GHSA-2")], GoneReason.NO_LONGER_MATCHED),
        ([entry(LODASH, "4.17.20", CheckStatus.LOOKUP_FAILED)], GoneReason.NOT_CHECKED),
        ([entry(LODASH, "4.17.20", CheckStatus.UNKNOWN)], GoneReason.NOT_CHECKED),
        ([entry(LODASH, "4.17.20", None)], GoneReason.NOT_CHECKED),
        ([entry(LODASH, None, CheckStatus.NOT_CHECKED)], GoneReason.NOT_CHECKED),
    ],
)
def test_why_a_finding_is_no_longer_reported(new: list[DigestEntry], reason: GoneReason) -> None:
    result = compare([entry(LODASH, "4.17.20", AFFECTED, "GHSA-1")], new)
    (gone,) = result.gone_findings
    assert gone.finding.advisory_id == "GHSA-1"
    assert gone.reason is reason


def test_a_version_the_newer_scan_could_not_check_is_listed() -> None:
    result = compare([entry(IDNA, "3.10", CLEAN)], [entry(IDNA, "3.10", CheckStatus.LOOKUP_FAILED)])
    assert result.newly_unchecked == ((IDNA, "3.10"),)
    assert result.has_changes


def test_dependency_file_changes() -> None:
    result = compare([], [], old_files=("a.txt", "b.txt"), new_files=("b.txt", "c.txt"))
    assert result.manifests_added == ("c.txt",)
    assert result.manifests_removed == ("a.txt",)


def test_digest_of_a_scan_without_a_vulnerability_check() -> None:
    scan = analyze_project(FIXTURES / "npm" / "basic_project", default_registry())
    digest = digest_scan(scan)
    assert digest.summary.vulnerability_status is VulnerabilityStatus.NOT_QUERIED
    assert digest.summary.data_source is None
    assert all(e.status is None and not e.advisories for e in digest.entries)
    versions = {(e.package.full_name, e.version) for e in digest.entries}
    assert ("express", "4.21.1") in versions
    # Declared as a range but resolved by the lockfile: only the exact version is kept.
    assert ("express", None) not in versions
    assert "package-lock.json" in digest.manifests


def test_project_names_are_validated() -> None:
    for bad in ("", " x", "-x", "123", "a\x1bb", "x" * 65):
        with pytest.raises(ValueError):
            require_project_name(bad)
    require_project_name("my app 2")


def test_register_rescan_and_compare(tmp_path: Path) -> None:
    root = tmp_path / "app"
    root.mkdir()
    (root / "package.json").write_text('{"dependencies": {"lodash": "4.17.20"}}', "utf-8")
    store = SqliteHistoryStore(open_database(":memory:"))

    with pytest.raises(ProjectRootError):
        register_project(store, tmp_path / "missing")
    project = register_project(store, root, clock=lambda: T0)
    assert project.name == "app" and project.root == root.resolve()
    with pytest.raises(DuplicateProjectError):
        register_project(store, root, "other")
    with pytest.raises(UnknownScanError):
        compare_scans(store, project)

    first = rescan_project(store, project, default_registry(), render_report=dumps_scan)
    assert first.comparison is None
    with pytest.raises(UnknownScanError):
        compare_scans(store, project)

    (root / "package.json").write_text('{"dependencies": {"lodash": "4.17.21"}}', "utf-8")
    second = rescan_project(store, project, default_registry(), render_report=dumps_scan)
    assert second.comparison is not None
    assert second.comparison.versions_changed[0].new_versions == ("4.17.21",)
    assert store.report(project.id, first.record.id) == dumps_scan(first.scan)

    again = compare_scans(store, project)
    assert (again.old.id, again.new.id) == (first.record.id, second.record.id)
    with pytest.raises(UnknownScanError):
        compare_scans(store, project, 999)


def test_checked_and_unchecked_scans_of_the_same_files_show_no_package_changes() -> None:
    # Regression: a git-installed package used to get a version only when unchecked.
    from dva.application.vulnerabilities import check_vulnerabilities
    from dva.intelligence.osv.source import OsvSource
    from dva.storage.advisory_cache import SqliteAdvisoryCache
    from tests.support.osv_fake import FakeOsvTransport

    scan = analyze_project(FIXTURES / "npm" / "basic_project", default_registry())
    cache = SqliteAdvisoryCache(open_database(":memory:"))
    checked = check_vulnerabilities(scan, OsvSource(FakeOsvTransport()), cache)
    result = compare_digests(record(1), digest_scan(checked), record(2), digest_scan(scan))
    assert not result.packages_added and not result.packages_removed
    assert not result.versions_changed
    assert all(g.reason is GoneReason.NOT_CHECKED for g in result.gone_findings)
    assert result.gone_findings  # lodash 3.10.1 was affected; unchecked now.


def test_findings_for_versions_the_older_scan_did_not_check_are_kept_apart() -> None:
    result = compare(
        [entry(LODASH, "4.17.20", None), entry(IDNA, "3.10", CheckStatus.LOOKUP_FAILED)],
        [entry(LODASH, "4.17.20", AFFECTED, "GHSA-1"), entry(IDNA, "3.10", AFFECTED, "GHSA-2")],
    )
    assert result.new_findings == ()
    assert [f.advisory_id for f in result.first_checked_findings] == ["GHSA-1", "GHSA-2"]
    assert result.reports_more
