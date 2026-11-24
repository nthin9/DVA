"""Opening DVA's local SQLite database and keeping its schema up to date.

The schema is built from numbered SQL scripts in ``migrations/``
(``001_*.sql``, ``002_*.sql`` ...). Each one runs once, inside a
transaction, and is recorded in ``schema_migrations``. A database created by
a newer DVA, with migrations this version doesn't know, is refused rather
than opened and possibly damaged.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

_MIGRATION_NAME = re.compile(r"^(\d{3})_[a-z0-9_]+\.sql$")


#: How long to wait for another DVA command to finish writing.
BUSY_TIMEOUT_SECONDS = 5.0


class DatabaseError(Exception):
    """The database can't be opened or upgraded. Messages contain no local paths."""


def _migrations() -> list[tuple[int, str]]:
    found = []
    for entry in files("dva.storage").joinpath("migrations").iterdir():
        match = _MIGRATION_NAME.match(entry.name)
        if match:
            found.append((int(match.group(1)), entry.read_text(encoding="utf-8")))
    found.sort()
    numbers = [number for number, _ in found]
    if numbers != list(range(1, len(numbers) + 1)):
        raise DatabaseError("migration scripts are not numbered 001, 002, ... without gaps")
    return found


def open_database(path: Path | str) -> sqlite3.Connection:
    """Open (creating if needed) the database at ``path`` and apply pending migrations.

    ``":memory:"`` gives a private in-memory database, which tests use.
    """
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    try:
        connection = sqlite3.connect(path, isolation_level=None, timeout=BUSY_TIMEOUT_SECONDS)
    except sqlite3.Error:
        raise DatabaseError("could not open the DVA database") from None
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        # Overwrite deleted content, so a cleared cache or a removed project
        # doesn't stay readable in the file's free pages.
        connection.execute("PRAGMA secure_delete = ON")
        migrate(connection)
    except sqlite3.Error:
        connection.close()
        raise DatabaseError(
            "the DVA database is in use by another DVA command, or is damaged"
        ) from None
    except BaseException:
        connection.close()
        raise
    return connection


def migrate(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    applied = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
    migrations = _migrations()
    known = {number for number, _ in migrations}
    if applied - known:
        raise DatabaseError("the database was created by a newer version of DVA")
    for number, script in migrations:
        if number in applied:
            continue
        stamp = datetime.now(UTC).isoformat()
        try:
            connection.execute("BEGIN")
            for statement in _statements(script):
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (number, stamp),
            )
            connection.execute("COMMIT")
        except sqlite3.Error:
            connection.execute("ROLLBACK")
            raise DatabaseError(f"could not apply database migration {number:03d}") from None


def _statements(script: str) -> list[str]:
    """Split a migration script into statements. Migrations are DVA's own files,
    so a plain split on ``;`` is enough: they contain no semicolons in strings."""
    lines = [line for line in script.splitlines() if not line.lstrip().startswith("--")]
    return [part.strip() for part in "\n".join(lines).split(";") if part.strip()]
