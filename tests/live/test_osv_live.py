"""Checks against the real OSV service. Skipped by default; run with ``pytest -m live``."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dva.application.vulnerabilities import check_vulnerabilities
from dva.contracts.intelligence import PackageKey
from dva.domain.dependency import ResolvedPackage, SourceKind
from dva.domain.manifest import ManifestAnalysis, ManifestKind, ParseStatus
from dva.domain.scan import ScanResult
from dva.domain.vulnerability import CheckStatus
from dva.ecosystems.python.names import identity
from dva.intelligence.http import UrllibTransport
from dva.intelligence.osv.source import OsvSource
from dva.storage.advisory_cache import SqliteAdvisoryCache
from dva.storage.database import open_database

pytestmark = pytest.mark.live


def test_live_batch_lookup_by_name() -> None:
    listed = OsvSource(UrllibTransport()).list_advisories([PackageKey("pypi", "requests")])
    ids = {stamp.id for stamp in listed[PackageKey("pypi", "requests")]}
    assert "GHSA-j8r2-6x86-q33q" in ids


def test_live_end_to_end_check() -> None:
    now = datetime.now(UTC)
    package = ResolvedPackage(
        "requests@2.30.0", identity("requests"), "2.30.0", source=SourceKind.REGISTRY
    )
    lock = ManifestAnalysis(
        "uv.lock",
        "python",
        "pypi",
        ManifestKind.LOCKFILE,
        "uv-lock",
        ParseStatus.PARSED,
        packages=(package,),
    )
    scan = ScanResult("0.0.1", "live", now, now, manifests=(lock,))
    cache = SqliteAdvisoryCache(open_database(":memory:"))
    result = check_vulnerabilities(scan, OsvSource(UrllibTransport()), cache)
    assert result.vulnerabilities is not None
    (check,) = result.vulnerabilities.checks
    assert check.status is CheckStatus.AFFECTED
    assert "GHSA-j8r2-6x86-q33q" in {f.advisory_id for f in check.findings}
