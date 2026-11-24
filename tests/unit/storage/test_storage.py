from __future__ import annotations

import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dva.contracts.intelligence import AdvisoryStamp, PackageKey
from dva.storage.advisory_cache import SqliteAdvisoryCache
from dva.storage.database import DatabaseError, open_database
from dva.storage.locations import default_data_dir, default_database_path

T0 = datetime(2026, 1, 1, tzinfo=UTC)
KEY = PackageKey("pypi", "requests")


def test_new_database_gets_every_migration(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dva.sqlite"
    db = open_database(path)
    versions = [row[0] for row in db.execute("SELECT version FROM schema_migrations")]
    assert versions == [1]
    db.close()
    # Opening again applies nothing twice.
    again = open_database(path)
    assert [row[0] for row in again.execute("SELECT version FROM schema_migrations")] == [1]
    again.close()


def test_a_database_from_a_newer_dva_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "dva.sqlite"
    db = open_database(path)
    db.execute("INSERT INTO schema_migrations VALUES (999, 'later')")
    db.close()
    with pytest.raises(DatabaseError) as error:
        open_database(path)
    assert str(tmp_path) not in str(error.value)


def test_index_round_trip_replaces_old_entries() -> None:
    cache = SqliteAdvisoryCache(open_database(":memory:"))
    assert cache.get_index("osv", KEY) is None
    cache.put_index("osv", KEY, [AdvisoryStamp("A-1", T0), AdvisoryStamp("A-2", T0)], T0)
    cache.put_index("osv", KEY, [AdvisoryStamp("A-2", T0 + timedelta(days=1))], T0 + timedelta(1))
    index = cache.get_index("osv", KEY)
    assert index is not None
    assert index.stamps == (AdvisoryStamp("A-2", T0 + timedelta(days=1)),)
    assert index.retrieved_at == T0 + timedelta(days=1)
    assert cache.get_index("other-provider", KEY) is None


def test_an_empty_answer_is_cached_too() -> None:
    cache = SqliteAdvisoryCache(open_database(":memory:"))
    cache.put_index("osv", KEY, [], T0)
    index = cache.get_index("osv", KEY)
    assert index is not None and index.stamps == ()


def test_record_round_trip_keeps_raw_text_and_times() -> None:
    cache = SqliteAdvisoryCache(open_database(":memory:"))
    cache.put_record("osv", "A-1", T0, '{"id": "A-1", "x": "ünïcode"}', T0 + timedelta(hours=1))
    record = cache.get_record("osv", "A-1")
    assert record is not None
    assert record.raw == '{"id": "A-1", "x": "ünïcode"}'
    assert (record.modified, record.retrieved_at) == (T0, T0 + timedelta(hours=1))
    assert cache.get_record("osv", "missing") is None


def test_a_failed_write_leaves_the_cache_unchanged() -> None:
    db = open_database(":memory:")
    cache = SqliteAdvisoryCache(db)
    cache.put_index("osv", KEY, [AdvisoryStamp("A-1", T0)], T0)
    duplicate = [AdvisoryStamp("A-2", T0), AdvisoryStamp("A-2", T0)]
    db.execute(
        "CREATE TRIGGER boom BEFORE INSERT ON package_advisories"
        " WHEN NEW.advisory_id = 'A-2' BEGIN SELECT RAISE(ABORT, 'no'); END"
    )
    with pytest.raises(sqlite3.Error):
        cache.put_index("osv", KEY, duplicate, T0)
    index = cache.get_index("osv", KEY)
    assert index is not None and [s.id for s in index.stamps] == ["A-1"]


def test_data_dir_override_and_platform_defaults() -> None:
    assert default_data_dir({"DVA_DATA_DIR": "/custom"}) == Path("/custom")
    assert default_database_path({"DVA_DATA_DIR": "/custom"}) == Path("/custom/dva.sqlite")
    if sys.platform == "win32":
        assert default_data_dir({"LOCALAPPDATA": "C:/Users/x/AppData/Local"}) == Path(
            "C:/Users/x/AppData/Local/DVA"
        )
    elif sys.platform != "darwin":
        assert default_data_dir({"XDG_DATA_HOME": "/xdg"}) == Path("/xdg/dva")
