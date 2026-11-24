from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dva.contracts.history import DuplicateProjectError, HistoryError
from dva.contracts.intelligence import AdvisoryStamp, PackageKey
from dva.domain.history import DigestEntry, PackageRef, ScanDigest, ScanSummary
from dva.domain.scan import CompletionState
from dva.domain.vulnerability import CheckStatus, DataSource, VulnerabilityStatus
from dva.storage import database as database_module
from dva.storage.advisory_cache import SqliteAdvisoryCache
from dva.storage.database import open_database
from dva.storage.history import SqliteHistoryStore

T0 = datetime(2026, 1, 1, tzinfo=UTC)
LODASH = PackageRef("npm", None, "lodash")
BABEL = PackageRef("npm", "@babel", "core")


def digest() -> ScanDigest:
    return ScanDigest(
        ScanSummary(
            "0.0.1",
            T0,
            T0,
            CompletionState.PARTIAL,
            VulnerabilityStatus.PARTIAL,
            DataSource.MIXED,
            T0,
        ),
        ("package-lock.json", "package.json"),
        (  # In the order the store returns them: by ecosystem, scope, name, version.
            DigestEntry(LODASH, None, CheckStatus.NOT_CHECKED),
            DigestEntry(LODASH, "3.10.1", CheckStatus.AFFECTED, ("GHSA-1", "GHSA-2")),
            DigestEntry(BABEL, "7.26.0", CheckStatus.NO_MATCHING_ADVISORY),
        ),
    )


@pytest.fixture
def connection() -> sqlite3.Connection:
    return open_database(":memory:")


@pytest.fixture
def store(connection: sqlite3.Connection) -> SqliteHistoryStore:
    return SqliteHistoryStore(connection)


def root(tmp_path: Path, name: str = "app") -> Path:
    return (tmp_path / name).resolve()


def test_projects_are_added_found_and_listed(store: SqliteHistoryStore, tmp_path: Path) -> None:
    b = store.add_project("beta", root(tmp_path, "b"), T0)
    a = store.add_project("Alpha", root(tmp_path, "a"), T0)
    assert store.project("ALPHA") == a
    assert store.project("missing") is None
    assert store.projects() == (a, b)


def test_duplicate_names_and_folders_are_refused(store: SqliteHistoryStore, tmp_path: Path) -> None:
    store.add_project("app", root(tmp_path), T0)
    with pytest.raises(DuplicateProjectError):
        store.add_project("APP", root(tmp_path, "other"), T0)
    with pytest.raises(DuplicateProjectError):
        store.add_project("second", root(tmp_path), T0)


def test_invalid_project_is_refused_before_writing(
    store: SqliteHistoryStore, tmp_path: Path
) -> None:
    with pytest.raises(ValueError):
        store.add_project("-bad", root(tmp_path), T0)
    with pytest.raises(ValueError):
        store.add_project("app", Path("relative"), T0)
    assert store.projects() == ()


def test_saved_scan_round_trips(store: SqliteHistoryStore, tmp_path: Path) -> None:
    project = store.add_project("app", root(tmp_path), T0)
    saved = store.save_scan(project.id, digest(), '{"report": 1}\n')
    assert (saved.packages, saved.affected, saved.advisories) == (3, 1, 2)
    assert saved.summary == digest().summary
    assert store.digest(project.id, saved.id) == digest()
    assert store.report(project.id, saved.id) == '{"report": 1}\n'


def test_scans_are_listed_newest_first_and_kept_per_project(
    store: SqliteHistoryStore, tmp_path: Path
) -> None:
    app = store.add_project("app", root(tmp_path), T0)
    other = store.add_project("other", root(tmp_path, "o"), T0)
    first = store.save_scan(app.id, digest(), "1")
    second = store.save_scan(app.id, digest(), "2")
    foreign = store.save_scan(other.id, digest(), "3")
    assert [r.id for r in store.scans(app.id)] == [second.id, first.id]
    assert [r.id for r in store.scans(app.id, limit=1)] == [second.id]
    # A scan of another project can't be read through this one.
    assert store.digest(app.id, foreign.id) is None
    assert store.report(app.id, foreign.id) is None


def test_removing_a_project_deletes_its_scans(
    store: SqliteHistoryStore, connection: sqlite3.Connection, tmp_path: Path
) -> None:
    project = store.add_project("app", root(tmp_path), T0)
    store.save_scan(project.id, digest(), "1")
    store.remove_project(project.id)
    for table in ("projects", "scans", "scan_manifests", "scan_packages", "scan_findings"):
        assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)  # noqa: S608


def test_a_failed_save_leaves_nothing_behind(
    store: SqliteHistoryStore, connection: sqlite3.Connection, tmp_path: Path
) -> None:
    store.add_project("app", root(tmp_path), T0)
    with pytest.raises(sqlite3.IntegrityError):
        store.save_scan(999, digest(), "1")  # No such project.
    assert connection.execute("SELECT COUNT(*) FROM scan_packages").fetchone() == (0,)


@pytest.mark.parametrize(
    "tamper",
    [
        "UPDATE scan_packages SET status = 'safe'",
        "UPDATE scan_packages SET status = 'affected' WHERE version = '7.26.0'",
        "UPDATE scans SET completion = 'great'",
        "UPDATE scans SET started_at = 'yesterday'",
        "UPDATE scan_manifests SET path = '/etc/passwd' WHERE path = 'package.json'",
        "UPDATE scan_packages SET name = ' lodash' WHERE version = '7.26.0'",
    ],
)
def test_damaged_rows_are_refused_not_trusted(
    store: SqliteHistoryStore, connection: sqlite3.Connection, tmp_path: Path, tamper: str
) -> None:
    project = store.add_project("app", root(tmp_path), T0)
    saved = store.save_scan(project.id, digest(), "1")
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute(tamper)
    with pytest.raises(HistoryError):
        store.digest(project.id, saved.id)


def test_upgrading_a_database_keeps_cached_advisories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "dva.sqlite"
    only_first = database_module._migrations()[:1]
    monkeypatch.setattr(database_module, "_migrations", lambda: only_first)
    old = open_database(path)
    SqliteAdvisoryCache(old).put_index(
        "osv", PackageKey("npm", "lodash"), [AdvisoryStamp("GHSA-1", T0)], T0
    )
    old.close()
    monkeypatch.undo()

    upgraded = open_database(path)
    versions = [row[0] for row in upgraded.execute("SELECT version FROM schema_migrations")]
    assert versions == [1, 2, 3]
    cached = SqliteAdvisoryCache(upgraded).get_index("osv", PackageKey("npm", "lodash"))
    assert cached is not None and cached.retrieved_at == T0
    assert SqliteHistoryStore(upgraded).projects() == ()
    upgraded.close()


def test_prune_only_touches_one_project(
    store: SqliteHistoryStore, connection: sqlite3.Connection, tmp_path: Path
) -> None:
    app = store.add_project("app", root(tmp_path), T0)
    other = store.add_project("other", root(tmp_path, "o"), T0)
    kept = [store.save_scan(app.id, digest(), str(i)).id for i in range(3)][-1]
    store.save_scan(other.id, digest(), "x")
    assert store.prune(app.id, 1) == 2
    assert [r.id for r in store.scans(app.id)] == [kept]
    assert len(store.scans(other.id)) == 1
    with pytest.raises(ValueError):
        store.prune(app.id, 0)
    # The pruned scans' rows are gone too.
    (count,) = connection.execute("SELECT COUNT(DISTINCT scan_id) FROM scan_packages").fetchone()
    assert count == 2
