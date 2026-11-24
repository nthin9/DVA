"""The SQLite implementation of project and scan history.

Saved scans are only inserted, never updated. Everything read back is
checked again by building the domain objects from it, so a damaged or edited
database file produces an error instead of a wrong comparison.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from dva.contracts.history import DuplicateProjectError, HistoryError
from dva.domain.history import (
    DigestEntry,
    PackageRef,
    Project,
    ScanDigest,
    ScanRecord,
    ScanSummary,
    root_key,
)
from dva.domain.scan import CompletionState
from dva.domain.serialization import SCHEMA_VERSION
from dva.domain.vulnerability import CheckStatus, DataSource, VulnerabilityStatus

#: How a package version that wasn't checked for vulnerabilities is stored.
_NOT_QUERIED = "not_queried"


def _store(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _load(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(UTC)


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("expected text")
    return value


def _int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("expected an integer")
    return value


class SqliteHistoryStore:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._db = connection

    # Projects

    def add_project(self, name: str, root: Path, created_at: datetime) -> Project:
        project = Project(0, name, root, created_at)  # Validates before writing.
        try:
            with self._transaction():
                cursor = self._db.execute(
                    "INSERT INTO projects (name, root, root_key, created_at) VALUES (?, ?, ?, ?)",
                    (name, str(root), root_key(root), _store(created_at)),
                )
        except sqlite3.IntegrityError:
            raise DuplicateProjectError(
                "a project with that name, or for that folder, is already registered"
            ) from None
        if cursor.lastrowid is None:
            raise HistoryError("the project couldn't be saved")
        return Project(cursor.lastrowid, project.name, project.root, project.created_at)

    def project(self, name: str) -> Project | None:
        row = self._db.execute(
            "SELECT id, name, root, created_at FROM projects WHERE name = ?", (name,)
        ).fetchone()
        return self._project(row) if row is not None else None

    def projects(self) -> tuple[Project, ...]:
        rows = self._db.execute(
            "SELECT id, name, root, created_at FROM projects ORDER BY name COLLATE NOCASE, id"
        )
        return tuple(self._project(row) for row in rows)

    def remove_project(self, project_id: int) -> None:
        with self._transaction():
            self._db.execute("DELETE FROM projects WHERE id = ?", (project_id,))

    # Scans

    def save_scan(self, project_id: int, digest: ScanDigest, report: str) -> ScanRecord:
        summary = digest.summary
        with self._transaction():
            cursor = self._db.execute(
                "INSERT INTO scans (project_id, tool_version, started_at, finished_at,"
                " completion, vulnerability_status, data_source, oldest_data_at,"
                " report_format, report) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    project_id,
                    summary.tool_version,
                    _store(summary.started_at),
                    _store(summary.finished_at),
                    summary.completion.value,
                    summary.vulnerability_status.value,
                    summary.data_source.value if summary.data_source else None,
                    _store(summary.oldest_data_at) if summary.oldest_data_at else None,
                    SCHEMA_VERSION,
                    report,
                ),
            )
            scan_id = cursor.lastrowid
            self._db.executemany(
                "INSERT INTO scan_manifests (scan_id, path) VALUES (?, ?)",
                [(scan_id, path) for path in digest.manifests],
            )
            for entry in digest.entries:
                key = (
                    scan_id,
                    entry.package.ecosystem,
                    entry.package.namespace or "",
                    entry.package.name,
                    entry.version or "",
                )
                status = entry.status.value if entry.status else _NOT_QUERIED
                self._db.execute(
                    "INSERT INTO scan_packages"
                    " (scan_id, ecosystem, namespace, name, version, status)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (*key, status),
                )
                self._db.executemany(
                    "INSERT INTO scan_findings"
                    " (scan_id, ecosystem, namespace, name, version, advisory_id)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    [(*key, advisory) for advisory in entry.advisories],
                )
        if scan_id is None:
            raise HistoryError("the scan couldn't be saved")
        record = self._record(scan_id)
        if record is None:
            raise HistoryError("the scan couldn't be saved")
        return record

    def scans(self, project_id: int, limit: int | None = None) -> tuple[ScanRecord, ...]:
        rows = self._db.execute(
            "SELECT * FROM scan_records WHERE project_id = ? ORDER BY id DESC LIMIT ?",
            (project_id, -1 if limit is None else limit),
        )
        return tuple(self._scan_record(row) for row in rows)

    def digest(self, project_id: int, scan_id: int) -> ScanDigest | None:
        row = self._db.execute(
            "SELECT * FROM scan_records WHERE id = ? AND project_id = ?",
            (scan_id, project_id),
        ).fetchone()
        if row is None:
            return None
        summary = self._scan_record(row).summary
        try:
            manifests = tuple(
                _text(path)
                for (path,) in self._db.execute(
                    "SELECT path FROM scan_manifests WHERE scan_id = ? ORDER BY path", (scan_id,)
                )
            )
            advisories: dict[tuple[str, str, str, str], list[str]] = {}
            for ecosystem, namespace, name, version, advisory in self._db.execute(
                "SELECT ecosystem, namespace, name, version, advisory_id FROM scan_findings"
                " WHERE scan_id = ? ORDER BY advisory_id",
                (scan_id,),
            ):
                key = (ecosystem, namespace, name, version)
                advisories.setdefault(key, []).append(_text(advisory))
            entries = tuple(
                DigestEntry(
                    PackageRef(_text(ecosystem), _text(namespace) or None, _text(name)),
                    _text(version) or None,
                    None if status == _NOT_QUERIED else CheckStatus(_text(status)),
                    tuple(advisories.get((ecosystem, namespace, name, version), ())),
                )
                for ecosystem, namespace, name, version, status in self._db.execute(
                    "SELECT ecosystem, namespace, name, version, status FROM scan_packages"
                    " WHERE scan_id = ? ORDER BY ecosystem, namespace, name, version",
                    (scan_id,),
                )
            )
            return ScanDigest(summary, manifests, entries)
        except (ValueError, TypeError):
            raise HistoryError(f"saved scan #{scan_id} is damaged and can't be read") from None

    def report(self, project_id: int, scan_id: int) -> str | None:
        row = self._db.execute(
            "SELECT report FROM scans WHERE id = ? AND project_id = ?", (scan_id, project_id)
        ).fetchone()
        if row is None:
            return None
        if not isinstance(row[0], str):
            raise HistoryError(f"saved scan #{scan_id} is damaged and can't be read")
        return row[0]

    def prune(self, project_id: int, keep: int) -> int:
        if keep < 1:
            raise ValueError("at least one scan must be kept")
        with self._transaction():
            cursor = self._db.execute(
                "DELETE FROM scans WHERE project_id = ? AND id NOT IN"
                " (SELECT id FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT ?)",
                (project_id, project_id, keep),
            )
        return cursor.rowcount

    def latest_entries(
        self, package: PackageRef
    ) -> tuple[tuple[Project, ScanRecord, DigestEntry], ...]:
        found = []
        for project in self.projects():
            latest = self.scans(project.id, limit=1)
            if not latest:
                continue
            record = latest[0]
            hit = self._db.execute(
                "SELECT 1 FROM scan_packages WHERE scan_id = ? AND ecosystem = ?"
                " AND namespace = ? AND name = ? LIMIT 1",
                (record.id, package.ecosystem, package.namespace or "", package.name),
            ).fetchone()
            digest = self.digest(project.id, record.id) if hit else None
            if digest is not None:
                found += [(project, record, e) for e in digest.entries if e.package == package]
        return tuple(found)

    # Helpers

    def _record(self, scan_id: int) -> ScanRecord | None:
        row = self._db.execute("SELECT * FROM scan_records WHERE id = ?", (scan_id,)).fetchone()
        return self._scan_record(row) if row is not None else None

    @staticmethod
    def _project(row: tuple[object, ...]) -> Project:
        project_id, name, root, created_at = row
        try:
            if not isinstance(project_id, int) or not isinstance(name, str):
                raise TypeError
            if not isinstance(root, str) or not isinstance(created_at, str):
                raise TypeError
            return Project(project_id, name, Path(root), _load(created_at))
        except (ValueError, TypeError):
            raise HistoryError("a saved project is damaged and can't be read") from None

    @staticmethod
    def _scan_record(row: tuple[object, ...]) -> ScanRecord:
        try:
            scan_id, project_id = _int(row[0]), _int(row[1])
            summary = ScanSummary(
                tool_version=_text(row[2]),
                started_at=_load(_text(row[3])),
                finished_at=_load(_text(row[4])),
                completion=CompletionState(_text(row[5])),
                vulnerability_status=VulnerabilityStatus(_text(row[6])),
                data_source=DataSource(_text(row[7])) if row[7] is not None else None,
                oldest_data_at=_load(_text(row[8])) if row[8] is not None else None,
            )
            counts = _int(row[9]), _int(row[10]), _int(row[11])
            return ScanRecord(scan_id, project_id, summary, *counts)
        except (ValueError, TypeError):
            raise HistoryError("a saved scan is damaged and can't be read") from None

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._db.execute("BEGIN")
        try:
            yield
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")
