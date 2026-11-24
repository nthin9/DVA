from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dva.domain.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    EventKind,
    RangeEvent,
)
from dva.intelligence.osv.records import parse_record
from dva.matching.match import MatchStatus, match

FIXTURES = Path(__file__).parents[2] / "fixtures" / "osv"
STAMP = datetime(2026, 1, 1, tzinfo=UTC)


def real(record_id: str) -> Advisory:
    return parse_record(json.loads((FIXTURES / f"{record_id}.json").read_text(encoding="utf-8")))


def advisory(
    *ranges: AffectedRange,
    versions: tuple[str, ...] = (),
    ecosystem: str = "npm",
    name: str = "pkg",
    withdrawn: datetime | None = None,
) -> Advisory:
    package = AffectedPackage(ecosystem, name, ranges=ranges, versions=versions)
    return Advisory("TEST-1", STAMP, withdrawn=withdrawn, affected=(package,))


def make_range(*pairs: tuple[str, str], range_type: str = "SEMVER") -> AffectedRange:
    return AffectedRange(range_type, tuple(RangeEvent(EventKind(k), v) for k, v in pairs))


# Real advisories, checked at and around their boundaries.
@pytest.mark.parametrize(
    ("record_id", "ecosystem", "name", "version", "status", "fixed"),
    [
        # requests: introduced 2.3.0, fixed 2.31.0
        ("GHSA-j8r2-6x86-q33q", "pypi", "requests", "2.2.1", MatchStatus.NOT_AFFECTED, ()),
        ("GHSA-j8r2-6x86-q33q", "pypi", "requests", "2.3.0", MatchStatus.AFFECTED, ("2.31.0",)),
        ("GHSA-j8r2-6x86-q33q", "pypi", "Requests", "2.30.0", MatchStatus.AFFECTED, ("2.31.0",)),
        ("GHSA-j8r2-6x86-q33q", "pypi", "requests", "2.31.0", MatchStatus.NOT_AFFECTED, ()),
        # The PyPI advisory database's copy also has a GIT range, which is ignored here.
        ("PYSEC-2023-74", "pypi", "requests", "2.30.0", MatchStatus.AFFECTED, ("2.31.0",)),
        ("PYSEC-2023-74", "pypi", "requests", "2.31.0", MatchStatus.NOT_AFFECTED, ()),
        # requests: everything before 2.32.0, including its pre-releases
        ("GHSA-9wx4-h78v-vm56", "pypi", "requests", "2.32.0rc1", MatchStatus.AFFECTED, ("2.32.0",)),
        ("GHSA-9wx4-h78v-vm56", "pypi", "requests", "2.32.0", MatchStatus.NOT_AFFECTED, ()),
        # lodash: SEMVER range, introduced 0, fixed 4.17.21
        ("GHSA-35jh-r3h4-6jhm", "npm", "lodash", "0.1.0", MatchStatus.AFFECTED, ("4.17.21",)),
        ("GHSA-35jh-r3h4-6jhm", "npm", "lodash", "4.17.20", MatchStatus.AFFECTED, ("4.17.21",)),
        ("GHSA-35jh-r3h4-6jhm", "npm", "lodash", "4.17.21", MatchStatus.NOT_AFFECTED, ()),
        ("GHSA-35jh-r3h4-6jhm", "npm", "lodash-es", "4.17.21", MatchStatus.NOT_AFFECTED, ()),
        # Same advisory, a package that isn't listed, and one in another ecosystem.
        ("GHSA-35jh-r3h4-6jhm", "npm", "underscore", "1.0.0", MatchStatus.NOT_APPLICABLE, ()),
        ("GHSA-35jh-r3h4-6jhm", "pypi", "lodash", "4.17.20", MatchStatus.NOT_APPLICABLE, ()),
    ],
)
def test_real_advisories(
    record_id: str,
    ecosystem: str,
    name: str,
    version: str,
    status: MatchStatus,
    fixed: tuple[str, ...],
) -> None:
    result = match(real(record_id), ecosystem, name, version)
    assert result.status is status
    assert result.fixed_versions == fixed


def test_last_affected_without_a_fix() -> None:
    record = real("GHSA-35jh-r3h4-6jhm")
    at_bound = match(record, "npm", "lodash.template", "4.5.0")
    assert at_bound.status is MatchStatus.AFFECTED
    assert at_bound.fixed_versions == ()
    assert at_bound.last_affected == ("4.5.0",)
    assert match(record, "npm", "lodash.template", "4.5.1").status is MatchStatus.NOT_AFFECTED


def test_explicit_versions_list_matches_by_value() -> None:
    record = advisory(versions=("1.0", "2.0.0"), ecosystem="pypi")
    assert match(record, "pypi", "pkg", "1.0.0").matched_by == ("versions",)
    assert match(record, "pypi", "pkg", "2.0").status is MatchStatus.AFFECTED
    assert match(record, "pypi", "pkg", "3.0").status is MatchStatus.NOT_AFFECTED


def test_multiple_affected_stretches_and_unsorted_events() -> None:
    affected_range = make_range(
        ("fixed", "2.0.0"),
        ("introduced", "3.0.0"),
        ("introduced", "1.0.0"),
        ("fixed", "3.1.0"),
    )
    record = advisory(affected_range)
    expected = {
        "0.9.0": MatchStatus.NOT_AFFECTED,
        "1.0.0": MatchStatus.AFFECTED,
        "1.5.0": MatchStatus.AFFECTED,
        "2.0.0": MatchStatus.NOT_AFFECTED,
        "2.5.0": MatchStatus.NOT_AFFECTED,
        "3.0.0": MatchStatus.AFFECTED,
        "3.1.0": MatchStatus.NOT_AFFECTED,
    }
    for version, status in expected.items():
        assert match(record, "npm", "pkg", version).status is status, version
    assert match(record, "npm", "pkg", "1.5.0").fixed_versions == ("2.0.0", "3.1.0")


def test_limit_bounds_the_range() -> None:
    record = advisory(make_range(("introduced", "0"), ("limit", "2.0.0")))
    assert match(record, "npm", "pkg", "1.9.9").status is MatchStatus.AFFECTED
    assert match(record, "npm", "pkg", "2.0.0").status is MatchStatus.NOT_AFFECTED
    unbounded = advisory(make_range(("introduced", "1.0.0"), ("limit", "*")))
    assert match(unbounded, "npm", "pkg", "9.0.0").status is MatchStatus.AFFECTED


def test_pre_releases_are_inside_ranges_that_contain_them() -> None:
    record = advisory(make_range(("introduced", "1.0.0"), ("fixed", "2.0.0")))
    assert match(record, "npm", "pkg", "2.0.0-rc.1").status is MatchStatus.AFFECTED
    assert match(record, "npm", "pkg", "1.0.0-rc.1").status is MatchStatus.NOT_AFFECTED


def test_plain_text_ordering_would_be_wrong_here() -> None:
    record = advisory(make_range(("introduced", "1.9.0"), ("fixed", "1.10.0")))
    assert match(record, "npm", "pkg", "1.9.5").status is MatchStatus.AFFECTED
    assert match(record, "npm", "pkg", "1.10.0").status is MatchStatus.NOT_AFFECTED


def test_unreadable_versions_are_unknown_not_safe() -> None:
    record = advisory(make_range(("introduced", "0"), ("fixed", "2.0.0")))
    assert match(record, "npm", "pkg", "next").status is MatchStatus.UNKNOWN
    bad_range = advisory(make_range(("introduced", "0"), ("fixed", "two")))
    result = match(bad_range, "npm", "pkg", "1.0.0")
    assert result.status is MatchStatus.UNKNOWN
    assert result.reasons


def test_one_affirmative_range_wins_over_an_unreadable_one() -> None:
    record = advisory(
        make_range(("introduced", "0"), ("fixed", "garbage")),
        make_range(("introduced", "0"), ("fixed", "2.0.0")),
    )
    assert match(record, "npm", "pkg", "1.0.0").status is MatchStatus.AFFECTED


def test_git_only_ranges_are_unknown() -> None:
    record = advisory(make_range(("introduced", "0"), ("fixed", "abc123"), range_type="GIT"))
    result = match(record, "npm", "pkg", "1.0.0")
    assert result.status is MatchStatus.UNKNOWN
    assert "GIT" in result.reasons[0]


def test_withdrawn_and_unsupported_ecosystems() -> None:
    withdrawn = advisory(make_range(("introduced", "0")), withdrawn=STAMP)
    assert match(withdrawn, "npm", "pkg", "1.0.0").status is MatchStatus.WITHDRAWN
    other = advisory(make_range(("introduced", "0")), ecosystem="cargo")
    assert match(other, "cargo", "pkg", "1.0.0").status is MatchStatus.UNKNOWN


def test_ecosystem_ranges_use_the_packages_own_rules() -> None:
    record = advisory(
        make_range(("introduced", "1.0"), ("fixed", "1.0.post1"), range_type="ECOSYSTEM"),
        ecosystem="pypi",
    )
    assert match(record, "pypi", "pkg", "1.0.0").status is MatchStatus.AFFECTED
    assert match(record, "pypi", "pkg", "1.0.post1").status is MatchStatus.NOT_AFFECTED
