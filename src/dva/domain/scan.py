"""Scan result aggregate."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ManifestAnalysis, ParseStatus
from dva.domain.vulnerability import VulnerabilityReport, VulnerabilityStatus

__all__ = ["CompletionState", "ScanResult", "VulnerabilityStatus"]


class CompletionState(StrEnum):
    """How complete the dependency analysis is. Derived, never set directly.

    ``COMPLETE`` means every discovered file was fully parsed and no scan
    limit or discovery problem was reported. It says nothing about
    vulnerabilities.
    """

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    NO_SUPPORTED_FILES = "no_supported_files"


def _require_utc(field: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must be a timezone-aware UTC datetime")


@dataclass(frozen=True, slots=True)
class ScanResult:
    """An immutable snapshot of one analysis run.

    ``project_name`` is a display name (the root directory's name), never the
    absolute root path. ``vulnerabilities`` is ``None`` until the scan's
    packages have been checked against a vulnerability source.
    """

    tool_version: str
    project_name: str
    started_at: datetime
    finished_at: datetime
    manifests: tuple[ManifestAnalysis, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    vulnerabilities: VulnerabilityReport | None = None

    def __post_init__(self) -> None:
        if not self.tool_version:
            raise ValueError("tool_version must be non-empty")
        if not self.project_name or "/" in self.project_name or "\\" in self.project_name:
            raise ValueError(f"project_name must be a bare display name: {self.project_name!r}")
        _require_utc("started_at", self.started_at)
        _require_utc("finished_at", self.finished_at)
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")
        paths = [manifest.path for manifest in self.manifests]
        if len(set(paths)) != len(paths):
            raise ValueError("manifest paths must be unique within a scan")

    @property
    def vulnerability_status(self) -> VulnerabilityStatus:
        if self.vulnerabilities is None:
            return VulnerabilityStatus.NOT_QUERIED
        return self.vulnerabilities.status

    @property
    def completion(self) -> CompletionState:
        scan_problem = any(d.level is not DiagnosticLevel.INFO for d in self.diagnostics)
        if not self.manifests:
            return CompletionState.PARTIAL if scan_problem else CompletionState.NO_SUPPORTED_FILES
        statuses = {manifest.status for manifest in self.manifests}
        if statuses == {ParseStatus.FAILED}:
            return CompletionState.FAILED
        if statuses == {ParseStatus.PARSED} and not scan_problem:
            return CompletionState.COMPLETE
        return CompletionState.PARTIAL
