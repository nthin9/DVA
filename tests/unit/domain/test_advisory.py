from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from dva.domain.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    EventKind,
    RangeEvent,
    Reference,
    Severity,
)

STAMP = datetime(2026, 1, 1, tzinfo=UTC)


def test_timestamps_must_be_utc() -> None:
    with pytest.raises(ValueError):
        Advisory("A-1", datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        Advisory("A-1", datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=2))))
    with pytest.raises(ValueError):
        Advisory("A-1", STAMP, published=datetime(2026, 1, 1))


def test_cve_ids_come_from_id_and_aliases() -> None:
    advisory = Advisory("CVE-2026-1", STAMP, aliases=("GHSA-x", "CVE-2026-2"))
    assert advisory.cve_ids == ("CVE-2026-1", "CVE-2026-2")
    assert Advisory("GHSA-y", STAMP).cve_ids == ()


def test_parts_validate_their_fields() -> None:
    with pytest.raises(ValueError):
        RangeEvent(EventKind.FIXED, "")
    with pytest.raises(ValueError):
        AffectedRange("SEMVER", ())
    with pytest.raises(ValueError):
        AffectedPackage("npm", "")
    with pytest.raises(ValueError):
        Severity("CVSS_V3", "")
    with pytest.raises(ValueError):
        Reference("WEB", "")
    with pytest.raises(ValueError):
        Advisory("", STAMP)
