from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from dva.application.vulnerabilities import check_vulnerabilities
from dva.contracts.intelligence import ProviderError
from dva.domain.dependency import DeclaredRequirement, ResolvedPackage, SourceKind
from dva.domain.manifest import ManifestAnalysis, ManifestKind, ParseStatus
from dva.domain.scan import ScanResult
from dva.domain.vulnerability import (
    CheckStatus,
    DataSource,
    PackageCheck,
    VulnerabilityReport,
    VulnerabilityStatus,
)
from dva.ecosystems.npm.names import identity as npm_identity
from dva.ecosystems.python.names import identity as pypi_identity
from dva.intelligence.osv.source import OsvSource
from dva.storage.advisory_cache import SqliteAdvisoryCache
from dva.storage.database import open_database
from tests.support.osv_fake import FakeOsvTransport

T0 = datetime(2026, 3, 1, tzinfo=UTC)


def lockfile(*packages: ResolvedPackage, path: str = "uv.lock") -> ManifestAnalysis:
    return ManifestAnalysis(
        path,
        "python",
        "pypi",
        ManifestKind.LOCKFILE,
        "uv-lock",
        ParseStatus.PARSED,
        packages=packages,
    )


def manifest(
    *requirements: DeclaredRequirement, path: str = "requirements.txt"
) -> ManifestAnalysis:
    return ManifestAnalysis(
        path,
        "python",
        "pypi",
        ManifestKind.MANIFEST,
        "pip-requirements",
        ParseStatus.PARSED,
        requirements=requirements,
    )


def pkg(name: str, version: str, source: SourceKind = SourceKind.REGISTRY) -> ResolvedPackage:
    return ResolvedPackage(f"{name}@{version}", pypi_identity(name), version, source=source)


def req(name: str, constraint: str | None, line: int = 1) -> DeclaredRequirement:
    return DeclaredRequirement(
        pypi_identity(name), constraint=constraint, line=line, source=SourceKind.REGISTRY
    )


def scan(*manifests: ManifestAnalysis) -> ScanResult:
    return ScanResult("0.0.1", "demo", T0, T0, manifests=manifests)


class Env:
    def __init__(self) -> None:
        self.transport = FakeOsvTransport()
        self.source = OsvSource(self.transport)
        self.cache = SqliteAdvisoryCache(open_database(":memory:"))

    def run(
        self, target: ScanResult, *, offline: bool = False, at: datetime = T0
    ) -> VulnerabilityReport:
        result = check_vulnerabilities(
            target, self.source, self.cache, offline=offline, clock=lambda: at
        )
        assert result.vulnerabilities is not None
        return result.vulnerabilities


def by_name(report: VulnerabilityReport) -> dict[tuple[str, str | None], PackageCheck]:
    return {(c.identity.name, c.version): c for c in report.checks}


@pytest.fixture
def env() -> Env:
    return Env()


def test_live_lookup_finds_affected_and_clean_versions(env: Env) -> None:
    report = env.run(scan(lockfile(pkg("requests", "2.30.0"), pkg("idna", "3.10"))))
    checks = by_name(report)
    old = checks[("requests", "2.30.0")]
    assert old.status is CheckStatus.AFFECTED
    found = {f.advisory_id: f.fixed_versions for f in old.findings}
    assert found == {
        "GHSA-j8r2-6x86-q33q": ("2.31.0",),
        "PYSEC-2023-74": ("2.31.0",),
        "GHSA-9wx4-h78v-vm56": ("2.32.0",),
    }
    assert old.data_retrieved_at == T0
    assert checks[("idna", "3.10")].status is CheckStatus.NO_MATCHING_ADVISORY
    assert {a.id for a in report.advisories} == set(found)
    assert report.data_source is DataSource.LIVE
    assert report.status is VulnerabilityStatus.COMPLETE
    assert report.oldest_data_at == T0


def test_only_ecosystem_and_name_reach_the_network(env: Env) -> None:
    env.run(scan(lockfile(pkg("requests", "2.30.0")), manifest(req("flask", "==3.0.0"))))
    assert env.transport.batch_queries() == [
        {"package": {"ecosystem": "PyPI", "name": "flask"}},
        {"package": {"ecosystem": "PyPI", "name": "requests"}},
    ]
    sent = repr(env.transport.requests)
    assert "2.30.0" not in sent and "3.0.0" not in sent and "uv.lock" not in sent


def test_records_are_fetched_once_and_reused(env: Env) -> None:
    target = scan(lockfile(pkg("requests", "2.30.0")))
    env.run(target)
    assert sorted(env.transport.fetched()) == [
        "GHSA-9wx4-h78v-vm56",
        "GHSA-j8r2-6x86-q33q",
        "PYSEC-2023-74",
    ]
    env.transport.requests.clear()
    env.run(target, at=T0 + timedelta(days=1))
    assert env.transport.fetched() == []  # the batch said nothing changed


def test_changed_records_are_fetched_again(env: Env) -> None:
    target = scan(lockfile(pkg("requests", "2.30.0")))
    env.run(target)
    env.transport.record("GHSA-j8r2-6x86-q33q")["modified"] = "2027-01-01T00:00:00Z"
    env.transport.requests.clear()
    env.run(target)
    assert env.transport.fetched() == ["GHSA-j8r2-6x86-q33q"]


def test_offline_uses_the_cache_and_reports_its_age(env: Env) -> None:
    target = scan(lockfile(pkg("requests", "2.30.0")))
    env.run(target)
    env.transport.requests.clear()
    report = env.run(target, offline=True, at=T0 + timedelta(days=3))
    assert env.transport.requests == []
    assert report.data_source is DataSource.CACHE
    assert report.oldest_data_at == T0
    assert by_name(report)[("requests", "2.30.0")].status is CheckStatus.AFFECTED


def test_offline_without_a_cache_is_a_failed_lookup_not_a_clean_result(env: Env) -> None:
    report = env.run(scan(lockfile(pkg("requests", "2.30.0"))), offline=True)
    check = by_name(report)[("requests", "2.30.0")]
    assert check.status is CheckStatus.LOOKUP_FAILED
    assert "nothing is cached" in check.reasons[0]
    assert report.status is VulnerabilityStatus.FAILED
    assert report.data_source is DataSource.NONE


def test_provider_outage_falls_back_to_the_cache(env: Env) -> None:
    target = scan(lockfile(pkg("requests", "2.30.0"), pkg("idna", "3.10")))
    env.run(scan(lockfile(pkg("requests", "2.30.0"))))
    env.transport.fail_batch = ProviderError("could not connect (URLError); gave up")
    report = env.run(target)
    checks = by_name(report)
    assert checks[("requests", "2.30.0")].status is CheckStatus.AFFECTED
    idna = checks[("idna", "3.10")]
    assert idna.status is CheckStatus.LOOKUP_FAILED
    assert "lookup failed" in idna.reasons[0]
    assert report.status is VulnerabilityStatus.PARTIAL
    assert "vulnerabilities.provider_unavailable" in {d.code for d in report.diagnostics}


def test_a_record_that_cannot_be_fetched_makes_the_package_unknown(env: Env) -> None:
    env.transport.fail_records = {"GHSA-9wx4-h78v-vm56"}
    report = env.run(scan(lockfile(pkg("requests", "2.31.0"))))
    check = by_name(report)[("requests", "2.31.0")]
    # The other two advisories are fixed in 2.31.0, but one couldn't be checked.
    assert check.status is CheckStatus.UNKNOWN
    assert "GHSA-9wx4-h78v-vm56" in check.reasons[0]


def test_an_updated_record_that_fails_to_download_uses_the_older_copy(env: Env) -> None:
    target = scan(lockfile(pkg("requests", "2.30.0")))
    env.run(target)
    env.transport.record("GHSA-j8r2-6x86-q33q")["modified"] = "2027-01-01T00:00:00Z"
    env.transport.fail_records = {"GHSA-j8r2-6x86-q33q"}
    report = env.run(target)
    assert by_name(report)[("requests", "2.30.0")].status is CheckStatus.AFFECTED
    assert "vulnerabilities.stale_records" in {d.code for d in report.diagnostics}
    assert report.status is VulnerabilityStatus.PARTIAL


def test_a_malformed_record_is_reported_and_never_counts_as_clean(env: Env) -> None:
    env.transport.records["GHSA-9wx4-h78v-vm56"] = {
        "id": "GHSA-9wx4-h78v-vm56",
        "modified": "2026-01-01T00:00:00Z",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"}, "ranges": [{}]}],
    }
    report = env.run(scan(lockfile(pkg("requests", "2.32.3"))))
    assert by_name(report)[("requests", "2.32.3")].status is CheckStatus.UNKNOWN
    assert "vulnerabilities.invalid_record" in {d.code for d in report.diagnostics}


def test_exact_pins_are_checked_and_ranges_are_not(env: Env) -> None:
    report = env.run(
        scan(
            manifest(req("requests", "==2.30.0", 1), req("flask", ">=3", 2), req("click", None, 3))
        )
    )
    checks = by_name(report)
    assert checks[("requests", "2.30.0")].status is CheckStatus.AFFECTED
    assert checks[("requests", "2.30.0")].locations[0].line == 1
    flask = checks[("flask", None)]
    assert flask.status is CheckStatus.NOT_CHECKED
    assert "range" in flask.reasons[0]
    assert "no version" in checks[("click", None)].reasons[0]
    assert report.status is VulnerabilityStatus.PARTIAL


def test_a_range_is_covered_when_a_lockfile_pins_the_same_package(env: Env) -> None:
    report = env.run(scan(manifest(req("requests", ">=2")), lockfile(pkg("requests", "2.32.3"))))
    assert set(by_name(report)) == {("requests", "2.32.3")}
    assert report.status is VulnerabilityStatus.COMPLETE


def test_the_same_version_in_several_files_is_one_check(env: Env) -> None:
    report = env.run(
        scan(manifest(req("requests", "==2.30.0")), lockfile(pkg("requests", "2.30.0")))
    )
    (check,) = report.checks
    assert {loc.path for loc in check.locations} == {"requirements.txt", "uv.lock"}
    assert len(env.transport.batch_queries()) == 1


def test_packages_from_outside_a_registry_are_not_looked_up(env: Env) -> None:
    report = env.run(scan(lockfile(pkg("internal", "1.0", SourceKind.GIT))))
    (check,) = report.checks
    assert check.status is CheckStatus.NOT_CHECKED
    assert "git repository" in check.reasons[0]
    assert env.transport.requests == []


def test_npm_scoped_names_are_sent_in_full(env: Env) -> None:
    package = ResolvedPackage(
        "node_modules/@babel/core",
        npm_identity("@babel/core"),
        "7.26.0",
        source=SourceKind.REGISTRY,
    )
    lock = ManifestAnalysis(
        "package-lock.json",
        "npm",
        "npm",
        ManifestKind.LOCKFILE,
        "package-lock",
        ParseStatus.PARSED,
        packages=(package,),
    )
    env.run(scan(lock))
    assert env.transport.batch_queries() == [
        {"package": {"ecosystem": "npm", "name": "@babel/core"}}
    ]


def test_unsupported_ecosystems_are_listed_as_not_checked(env: Env) -> None:
    from dva.domain.identity import PackageIdentity

    other = ResolvedPackage(
        "serde@1.0", PackageIdentity("cargo", "serde"), "1.0", source=SourceKind.REGISTRY
    )
    lock = ManifestAnalysis(
        "Cargo.lock",
        "rust",
        "cargo",
        ManifestKind.LOCKFILE,
        "cargo-lock",
        ParseStatus.PARSED,
        packages=(other,),
    )
    report = env.run(scan(lock))
    assert report.checks[0].status is CheckStatus.NOT_CHECKED
    assert "ecosystem" in report.checks[0].reasons[0]


def test_an_empty_scan_queries_nothing(env: Env) -> None:
    report = env.run(scan())
    assert report.checks == ()
    assert env.transport.requests == []
    assert report.data_source is DataSource.NONE


def test_the_scan_result_reports_the_status(env: Env) -> None:
    result = check_vulnerabilities(
        scan(lockfile(pkg("requests", "2.30.0"))), env.source, env.cache, clock=lambda: T0
    )
    assert result.vulnerability_status is VulnerabilityStatus.COMPLETE


def test_packages_from_another_registry_are_not_sent_by_default(env: Env) -> None:
    private = ResolvedPackage(
        "corp-secret@1.0",
        pypi_identity("corp-secret", from_registry=False),
        "1.0",
        source=SourceKind.OTHER_REGISTRY,
    )
    target = scan(lockfile(private, pkg("idna", "3.10")))
    report = env.run(target)
    names = {q["package"]["name"] for q in env.transport.batch_queries()}
    assert "corp-secret" not in names and "idna" in names
    check = by_name(report)[("corp-secret", None)]
    assert check.status is CheckStatus.NOT_CHECKED
    assert "registry other than the public one" in check.reasons[0]

    env.transport.requests.clear()
    allowed = check_vulnerabilities(
        target, env.source, env.cache, other_registries=True, clock=lambda: T0
    )
    assert allowed.vulnerabilities is not None
    names = {q["package"]["name"] for q in env.transport.batch_queries()}
    assert "corp-secret" in names
    assert by_name(allowed.vulnerabilities)[("corp-secret", "1.0")].status is (
        CheckStatus.NO_MATCHING_ADVISORY
    )


def test_a_constraints_pin_is_checked_where_the_requirement_is_written(env: Env) -> None:
    from dataclasses import replace

    ranged = replace(req("requests", ">=2", line=4), constrained_to="2.30.0", origin="base.txt")
    report = env.run(scan(manifest(ranged)))
    check = by_name(report)[("requests", "2.30.0")]
    assert check.status is CheckStatus.AFFECTED
    assert [(loc.path, loc.line) for loc in check.locations] == [("base.txt", 4)]
