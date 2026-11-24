"""The SQLite implementation of the advisory cache."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from dva.contracts.intelligence import AdvisoryStamp, CachedIndex, CachedRecord, PackageKey


def _store(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _load(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(UTC)


class SqliteAdvisoryCache:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._db = connection

    def get_index(self, provider: str, key: PackageKey) -> CachedIndex | None:
        row = self._db.execute(
            "SELECT retrieved_at FROM package_lookups"
            " WHERE provider = ? AND ecosystem = ? AND name = ?",
            (provider, key.ecosystem, key.name),
        ).fetchone()
        if row is None:
            return None
        stamps = tuple(
            AdvisoryStamp(advisory_id, _load(modified))
            for advisory_id, modified in self._db.execute(
                "SELECT advisory_id, modified FROM package_advisories"
                " WHERE provider = ? AND ecosystem = ? AND name = ? ORDER BY advisory_id",
                (provider, key.ecosystem, key.name),
            )
        )
        return CachedIndex(stamps, _load(row[0]))

    def put_index(
        self,
        provider: str,
        key: PackageKey,
        stamps: Sequence[AdvisoryStamp],
        retrieved_at: datetime,
    ) -> None:
        where = (provider, key.ecosystem, key.name)
        with self._transaction():
            self._db.execute(
                "DELETE FROM package_lookups WHERE provider = ? AND ecosystem = ? AND name = ?",
                where,
            )
            self._db.execute(
                "INSERT INTO package_lookups (provider, ecosystem, name, retrieved_at)"
                " VALUES (?, ?, ?, ?)",
                (*where, _store(retrieved_at)),
            )
            self._db.executemany(
                "INSERT OR REPLACE INTO package_advisories"
                " (provider, ecosystem, name, advisory_id, modified) VALUES (?, ?, ?, ?, ?)",
                [(*where, stamp.id, _store(stamp.modified)) for stamp in stamps],
            )

    def get_record(self, provider: str, advisory_id: str) -> CachedRecord | None:
        row = self._db.execute(
            "SELECT record, modified, retrieved_at FROM advisories"
            " WHERE provider = ? AND advisory_id = ?",
            (provider, advisory_id),
        ).fetchone()
        if row is None:
            return None
        return CachedRecord(row[0], _load(row[1]), _load(row[2]))

    def put_record(
        self,
        provider: str,
        advisory_id: str,
        modified: datetime,
        raw: str,
        retrieved_at: datetime,
    ) -> None:
        with self._transaction():
            self._db.execute(
                "INSERT OR REPLACE INTO advisories"
                " (provider, advisory_id, modified, record, retrieved_at) VALUES (?, ?, ?, ?, ?)",
                (provider, advisory_id, _store(modified), raw, _store(retrieved_at)),
            )

    def _transaction(self) -> _Transaction:
        return _Transaction(self._db)


class _Transaction:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._db = connection

    def __enter__(self) -> None:
        self._db.execute("BEGIN")

    def __exit__(self, kind: object, *_: object) -> None:
        self._db.execute("ROLLBACK" if kind is not None else "COMMIT")


@dataclass(frozen=True, slots=True)
class CacheSummary:
    """What the advisory cache holds, for ``dva cache info``."""

    packages: int
    advisories: int
    oldest: datetime | None
    newest: datetime | None


def summarize(connection: sqlite3.Connection) -> CacheSummary:
    packages, oldest, newest = connection.execute(
        "SELECT COUNT(*), MIN(retrieved_at), MAX(retrieved_at) FROM package_lookups"
    ).fetchone()
    (advisories,) = connection.execute("SELECT COUNT(*) FROM advisories").fetchone()
    return CacheSummary(
        int(packages),
        int(advisories),
        _load(oldest) if isinstance(oldest, str) else None,
        _load(newest) if isinstance(newest, str) else None,
    )


def clear(connection: sqlite3.Connection) -> CacheSummary:
    """Delete every cached lookup and advisory record. Saved scans are kept."""
    before = summarize(connection)
    with _Transaction(connection):
        connection.execute("DELETE FROM package_advisories")
        connection.execute("DELETE FROM package_lookups")
        connection.execute("DELETE FROM advisories")
    return before
