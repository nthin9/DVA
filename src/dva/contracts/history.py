"""The contract for storing registered projects and their saved scans.

The application layer uses only this protocol, so it doesn't depend on
SQLite, and a future desktop app can use the same code. Saved scans can be
added and read but never changed. Deleting a project deletes its scans, and
pruning deletes a project's oldest scans whole.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Protocol

from dva.domain.acceptance import Acceptance
from dva.domain.history import DigestEntry, PackageRef, Project, ScanDigest, ScanRecord


class HistoryError(Exception):
    """Saved history can't be read or written. Messages contain no local paths."""


class DuplicateProjectError(HistoryError):
    """A project with this name, or for this folder, is already registered."""


class HistoryStore(Protocol):
    def add_project(
        self, name: str, root: Path, created_at: datetime, excludes: Sequence[str] = ()
    ) -> Project:
        """Register ``root`` (an absolute, resolved folder) under ``name``.

        Raises :class:`DuplicateProjectError` if the name (ignoring case) or
        the folder is already registered.
        """
        ...

    def project(self, name: str) -> Project | None:
        """The project called ``name``, ignoring case."""
        ...

    def projects(self) -> tuple[Project, ...]:
        """Every registered project, sorted by name."""
        ...

    def remove_project(self, project_id: int) -> None:
        """Unregister a project and delete every scan saved for it."""
        ...

    def set_excludes(self, project_id: int, excludes: Sequence[str]) -> None:
        """Replace the paths and patterns a project's rescans skip."""
        ...

    def accept(self, project_id: int, acceptance: Acceptance, created_at: datetime) -> None:
        """Save an accepted risk, replacing one for the same advisory and package."""
        ...

    def unaccept(self, project_id: int, advisory: str, package: str | None = None) -> int:
        """Remove accepted risks; return how many were removed."""
        ...

    def acceptances(self, project_id: int) -> tuple[Acceptance, ...]:
        """A project's accepted risks."""
        ...

    def save_scan(self, project_id: int, digest: ScanDigest, report: str) -> ScanRecord:
        """Save one scan: its digest and its full JSON report text."""
        ...

    def scans(self, project_id: int, limit: int | None = None) -> tuple[ScanRecord, ...]:
        """A project's saved scans, newest first."""
        ...

    def digest(self, project_id: int, scan_id: int) -> ScanDigest | None:
        """The digest of one of the project's scans, or ``None`` if it has no such scan."""
        ...

    def report(self, project_id: int, scan_id: int) -> str | None:
        """The JSON report text saved with one of the project's scans."""
        ...

    def prune(self, project_id: int, keep: int) -> int:
        """Delete all but the newest ``keep`` saved scans; return how many were deleted."""
        ...

    def latest_entries(
        self, package: PackageRef
    ) -> tuple[tuple[Project, ScanRecord, DigestEntry], ...]:
        """Entries for exactly this package in each project's latest scan."""
        ...
