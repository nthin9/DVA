from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from dva.domain.advisory import EventKind
from dva.intelligence.osv.records import InvalidRecordError, parse_record

FIXTURES = Path(__file__).parents[2] / "fixtures" / "osv"


def load(record_id: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / f"{record_id}.json").read_text(encoding="utf-8"))
    return data


def minimal(**extra: object) -> dict[str, Any]:
    return {"id": "TEST-1", "modified": "2026-01-01T00:00:00Z", **extra}


def test_real_github_advisory() -> None:
    advisory = parse_record(load("GHSA-j8r2-6x86-q33q"))
    assert advisory.id == "GHSA-j8r2-6x86-q33q"
    assert advisory.aliases == ("CVE-2023-32681", "PYSEC-2023-74")
    assert advisory.cve_ids == ("CVE-2023-32681",)
    assert advisory.summary == "Unintended leak of Proxy-Authorization header in requests"
    assert advisory.database_severity == "MODERATE"
    assert [(s.type, s.score[:8]) for s in advisory.severities] == [("CVSS_V3", "CVSS:3.1")]
    assert advisory.published == datetime(2023, 5, 22, 20, 36, 32, tzinfo=UTC)
    # Nanosecond timestamps are kept to the microsecond.
    assert advisory.modified == datetime(2026, 9, 10, 3, 50, 1, 756149, tzinfo=UTC)
    (package,) = advisory.affected
    assert (package.ecosystem, package.name, package.purl) == (
        "pypi",
        "requests",
        "pkg:pypi/requests",
    )
    (affected_range,) = package.ranges
    assert affected_range.type == "ECOSYSTEM"
    assert [(e.kind, e.version) for e in affected_range.events] == [
        (EventKind.INTRODUCED, "2.3.0"),
        (EventKind.FIXED, "2.31.0"),
    ]
    assert "2.30.0" in package.versions
    assert all(r.url.startswith("https://") for r in advisory.references)


def test_real_record_without_severity_and_with_git_range() -> None:
    advisory = parse_record(load("PYSEC-2023-74"))
    assert advisory.severities == ()
    assert advisory.database_severity is None
    types = [r.type for r in advisory.affected[0].ranges]
    assert types == ["GIT", "ECOSYSTEM"]
    assert advisory.affected[0].ranges[0].repo


def test_other_ecosystems_keep_their_own_name() -> None:
    advisory = parse_record(load("GHSA-35jh-r3h4-6jhm"))
    ecosystems = [p.ecosystem for p in advisory.affected]
    assert ecosystems == ["npm", "npm", "npm", "npm", "RubyGems"]


@pytest.mark.parametrize(
    "record",
    [
        [],
        "string",
        {"modified": "2026-01-01T00:00:00Z"},
        {"id": "bad id with spaces", "modified": "2026-01-01T00:00:00Z"},
        {"id": "TEST-1"},
        minimal(modified="yesterday"),
        minimal(modified="2026-13-01T00:00:00Z"),
        minimal(published="not a date"),
        minimal(affected={}),
        minimal(affected=["x"]),
        minimal(affected=[{"package": {"ecosystem": "npm"}}]),
        minimal(affected=[{"package": {"ecosystem": "npm", "name": "a"}, "ranges": "x"}]),
        minimal(affected=[{"package": {"ecosystem": "npm", "name": "a"}, "versions": [1]}]),
        minimal(affected=[{"package": {"ecosystem": "npm", "name": "a"}, "ranges": [{}]}]),
    ],
)
def test_malformed_records_are_rejected(record: object) -> None:
    with pytest.raises(InvalidRecordError):
        parse_record(record)


def range_with(*events: dict[str, Any]) -> dict[str, Any]:
    return minimal(
        affected=[
            {
                "package": {"ecosystem": "npm", "name": "a"},
                "ranges": [{"type": "SEMVER", "events": list(events)}],
            }
        ]
    )


@pytest.mark.parametrize(
    "events",
    [
        ({"fixed": "1.0.0"},),  # no introduced event
        ({"introduced": "0", "fixed": "1.0.0"},),  # two keys in one event
        ({"introduced": "0"}, {"patched": "1.0.0"}),  # unknown event kind
        ({"introduced": 0},),  # version is not a string
        ({"introduced": " "},),
    ],
)
def test_bad_range_events_reject_the_whole_record(events: tuple[dict[str, Any], ...]) -> None:
    with pytest.raises(InvalidRecordError):
        parse_record(range_with(*events))


def test_display_only_problems_are_skipped_not_fatal() -> None:
    record = minimal(
        aliases=["CVE-2026-0001", 5, "has space", "CVE-2026-0001"],
        severity=[{"type": "CVSS_V3"}, "x", {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}],
        references=[
            {"type": "WEB", "url": "javascript:alert(1)"},
            {"type": "WEB", "url": "https://example.com/a b"},
            {"type": "WEB"},
            {"type": "ADVISORY", "url": "https://example.com/advisory"},
        ],
        database_specific={"severity": 5},
    )
    advisory = parse_record(record)
    assert advisory.aliases == ("CVE-2026-0001",)
    assert [s.type for s in advisory.severities] == ["CVSS_V4"]
    assert [r.url for r in advisory.references] == ["https://example.com/advisory"]
    assert advisory.database_severity is None


def test_timezone_offsets_are_converted_to_utc() -> None:
    advisory = parse_record(minimal(modified="2026-01-01T02:30:00+02:30"))
    assert advisory.modified == datetime(2026, 1, 1, 0, 0, tzinfo=UTC)


def test_withdrawn_records_keep_their_withdrawal_time() -> None:
    advisory = parse_record(minimal(withdrawn="2026-02-01T00:00:00Z"))
    assert advisory.withdrawn == datetime(2026, 2, 1, tzinfo=UTC)


def test_parsing_does_not_modify_the_input() -> None:
    record = load("GHSA-35jh-r3h4-6jhm")
    before = copy.deepcopy(record)
    parse_record(record)
    assert record == before
