from __future__ import annotations

import json
from pathlib import Path

import pytest

from dva.application.analyze import analyze_project
from dva.application.vulnerabilities import check_vulnerabilities
from dva.domain.deserialization import ReportFormatError, loads_scan
from dva.domain.serialization import dumps_scan
from dva.ecosystems.registry import default_registry
from dva.intelligence.osv.source import OsvSource
from dva.reporting.json_report import render_json
from dva.storage.advisory_cache import SqliteAdvisoryCache
from dva.storage.database import open_database
from tests.support.osv_fake import FakeOsvTransport
from tests.unit.domain.test_serialization import build_scan
from tests.unit.reporting.test_reports import hostile_scan

FIXTURES = Path(__file__).parents[2] / "fixtures"


def checked(fixture: str):  # type: ignore[no-untyped-def]
    scan = analyze_project(FIXTURES / fixture, default_registry())
    cache = SqliteAdvisoryCache(open_database(":memory:"))
    return check_vulnerabilities(scan, OsvSource(FakeOsvTransport()), cache)


@pytest.mark.parametrize(
    "make",
    [
        build_scan,
        hostile_scan,
        lambda: checked("npm/basic_project"),
        lambda: checked("python/basic_project"),
        lambda: checked("python/poetry_project"),
        lambda: analyze_project(FIXTURES / "npm" / "basic_project", default_registry()),
    ],
)
def test_reports_load_back_into_the_same_scan(make) -> None:  # type: ignore[no-untyped-def]
    scan = make()
    text = dumps_scan(scan)
    loaded = loads_scan(text)
    # Lists come back in the report's canonical order, so compare the reports,
    # and check that a loaded scan is stable from then on.
    assert dumps_scan(loaded) == text
    assert loads_scan(dumps_scan(loaded)) == loaded
    # The full report, with its overview, loads too.
    assert dumps_scan(loads_scan(render_json(scan))) == dumps_scan(scan)


def valid() -> dict[str, object]:
    data: dict[str, object] = json.loads(dumps_scan(hostile_scan()))
    return data


def broken(change) -> str:  # type: ignore[no-untyped-def]
    data = valid()
    change(data)
    return json.dumps(data)


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        "{}",
        broken(lambda d: d.update(schema_version="dva.report/9")),
        broken(lambda d: d.update(started_at="yesterday")),
        broken(lambda d: d.update(project_name="../x")),
        broken(lambda d: d["manifests"][0].update(status="great")),
        broken(lambda d: d["manifests"][0].update(path="/etc/passwd")),
        broken(lambda d: d["manifests"][0]["packages"][0].update(version=7)),
        broken(lambda d: d["vulnerabilities"]["checks"][0].update(findings=[])),
        broken(lambda d: d["vulnerabilities"].update(advisories=[])),
        broken(lambda d: d["vulnerabilities"]["checks"][0]["locations"][0].update(line=True)),
        "[" * 100_000 + "]" * 100_000,
    ],
)
def test_invalid_reports_are_refused(text: str) -> None:
    with pytest.raises(ReportFormatError):
        loads_scan(text)
