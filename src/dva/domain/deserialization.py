"""Reading a JSON report (format ``dva.report/1``) back into a scan result.

This is the reverse of :mod:`dva.domain.serialization`. DVA uses it for scans
it saved itself, to render an earlier scan's reports again, but the text is
still treated as untrusted: every value is type-checked and passed through
the domain constructors, which validate it, and anything unexpected raises
:class:`ReportFormatError` instead of producing a partial result.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TypeVar

from dva.domain.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    EventKind,
    RangeEvent,
    Reference,
    Severity,
)
from dva.domain.dependency import (
    DeclaredRequirement,
    DependencyEdge,
    ResolvedPackage,
    SourceKind,
)
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.identity import PackageIdentity
from dva.domain.manifest import ManifestAnalysis, ManifestKind, ParseStatus
from dva.domain.scan import ScanResult
from dva.domain.serialization import SCHEMA_VERSION
from dva.domain.vulnerability import (
    CheckStatus,
    DataSource,
    Finding,
    Location,
    PackageCheck,
    VulnerabilityReport,
)

T = TypeVar("T")

#: Reports larger than this are refused rather than parsed.
MAX_REPORT_BYTES = 64 * 1024 * 1024


class ReportFormatError(ValueError):
    """The text is not a valid DVA report."""


class _Object:
    """Typed access to one JSON object, with errors that say where."""

    def __init__(self, value: object, where: str) -> None:
        if not isinstance(value, dict):
            raise ReportFormatError(f"{where} is not an object")
        self._data = value
        self._where = where

    def _get(self, key: str) -> object:
        if key not in self._data:
            raise ReportFormatError(f"{self._where} has no {key!r}")
        return self._data[key]

    def text(self, key: str) -> str:
        value = self._get(key)
        if not isinstance(value, str):
            raise ReportFormatError(f"{self._where}.{key} is not text")
        return value

    def optional_text(self, key: str) -> str | None:
        value = self._data.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ReportFormatError(f"{self._where}.{key} is not text")
        return value

    def optional_int(self, key: str) -> int | None:
        value = self._data.get(key)
        if value is None:
            return None
        if not isinstance(value, int) or isinstance(value, bool):
            raise ReportFormatError(f"{self._where}.{key} is not a whole number")
        return value

    def texts(self, key: str) -> tuple[str, ...]:
        return tuple(_text(item, f"{self._where}.{key}") for item in self.items(key))

    def items(self, key: str) -> list[object]:
        value = self._data.get(key, [])
        if not isinstance(value, list):
            raise ReportFormatError(f"{self._where}.{key} is not a list")
        return value

    def objects(self, key: str) -> list[_Object]:
        return [
            _Object(item, f"{self._where}.{key}[{i}]") for i, item in enumerate(self.items(key))
        ]

    def object(self, key: str) -> _Object | None:
        value = self._data.get(key)
        return None if value is None else _Object(value, f"{self._where}.{key}")

    def enum(self, key: str, kind: Callable[[str], T]) -> T:
        try:
            return kind(self.text(key))
        except ValueError:
            raise ReportFormatError(f"{self._where}.{key} has an unknown value") from None

    def time(self, key: str) -> datetime:
        return _time(self.text(key), f"{self._where}.{key}")

    def optional_time(self, key: str) -> datetime | None:
        value = self.optional_text(key)
        return None if value is None else _time(value, f"{self._where}.{key}")


def _text(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise ReportFormatError(f"{where} contains a non-text value")
    return value


def _time(value: str, where: str) -> datetime:
    try:
        stamp = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        raise ReportFormatError(f"{where} is not a DVA timestamp") from None
    return stamp.replace(tzinfo=UTC)


def _identity(data: _Object) -> PackageIdentity:
    return PackageIdentity(
        data.text("ecosystem"),
        data.text("name"),
        data.optional_text("namespace"),
        data.optional_text("purl"),
    )


def _identity_of(data: _Object) -> PackageIdentity:
    found = data.object("identity")
    if found is None:
        raise ReportFormatError("an entry has no identity")
    return _identity(found)


def _diagnostics(data: _Object, key: str = "diagnostics") -> tuple[Diagnostic, ...]:
    return tuple(
        Diagnostic(
            d.text("code"),
            d.enum("level", DiagnosticLevel),
            d.text("message"),
            d.optional_text("path"),
        )
        for d in data.objects(key)
    )


def _requirement(data: _Object) -> DeclaredRequirement:
    return DeclaredRequirement(
        _identity_of(data),
        constraint=data.optional_text("constraint"),
        markers=data.optional_text("markers"),
        groups=data.texts("groups"),
        line=data.optional_int("line"),
        source=data.enum("source", SourceKind),
        extras=data.texts("extras"),
        alias=data.optional_text("alias"),
        origin=data.optional_text("origin"),
        constrained_to=data.optional_text("constrained_to"),
    )


def _package(data: _Object) -> ResolvedPackage:
    return ResolvedPackage(
        data.text("node_id"),
        _identity_of(data),
        data.text("version"),
        groups=data.texts("groups"),
        source=data.enum("source", SourceKind),
        markers=data.optional_text("markers"),
    )


def _edge(data: _Object) -> DependencyEdge:
    return DependencyEdge(
        data.optional_text("parent_id"),
        data.text("child_id"),
        constraint=data.optional_text("constraint"),
        markers=data.optional_text("markers"),
        groups=data.texts("groups"),
    )


def _manifest(data: _Object) -> ManifestAnalysis:
    return ManifestAnalysis(
        path=data.text("path"),
        adapter_id=data.text("adapter_id"),
        ecosystem=data.text("ecosystem"),
        kind=data.enum("kind", ManifestKind),
        format_name=data.text("format_name"),
        status=data.enum("status", ParseStatus),
        format_version=data.optional_text("format_version"),
        requirements=tuple(_requirement(r) for r in data.objects("requirements")),
        packages=tuple(_package(p) for p in data.objects("packages")),
        edges=tuple(_edge(e) for e in data.objects("edges")),
        diagnostics=_diagnostics(data),
    )


def _severities(data: _Object) -> tuple[Severity, ...]:
    return tuple(
        Severity(s.text("type"), s.text("score"), s.optional_text("source"))
        for s in data.objects("severities")
    )


def _range(data: _Object) -> AffectedRange:
    events = []
    for event in data.objects("events"):
        pairs = list(event._data.items())
        if len(pairs) != 1:
            raise ReportFormatError("a range event must have exactly one entry")
        ((kind, version),) = pairs
        try:
            events.append(RangeEvent(EventKind(kind), _text(version, "a range event")))
        except ValueError:
            raise ReportFormatError("a range event has an unknown kind") from None
    return AffectedRange(data.text("type"), tuple(events), data.optional_text("repo"))


def _affected(data: _Object) -> AffectedPackage:
    return AffectedPackage(
        data.text("ecosystem"),
        data.text("name"),
        purl=data.optional_text("purl"),
        ranges=tuple(_range(r) for r in data.objects("ranges")),
        versions=data.texts("versions"),
        severities=_severities(data),
    )


def _advisory(data: _Object) -> Advisory:
    return Advisory(
        id=data.text("id"),
        modified=data.time("modified"),
        published=data.optional_time("published"),
        withdrawn=data.optional_time("withdrawn"),
        aliases=data.texts("aliases"),
        related=data.texts("related"),
        summary=data.optional_text("summary"),
        details=data.optional_text("details"),
        severities=_severities(data),
        database_severity=data.optional_text("database_severity"),
        references=tuple(
            Reference(r.text("type"), r.text("url")) for r in data.objects("references")
        ),
        affected=tuple(_affected(a) for a in data.objects("affected")),
        schema_version=data.optional_text("schema_version"),
    )


def _check(data: _Object) -> PackageCheck:
    return PackageCheck(
        _identity_of(data),
        data.optional_text("version"),
        data.enum("status", CheckStatus),
        tuple(
            Location(loc.text("path"), loc.optional_text("node_id"), loc.optional_int("line"))
            for loc in data.objects("locations")
        ),
        findings=tuple(
            Finding(
                f.text("advisory_id"),
                f.texts("matched_by"),
                f.texts("fixed_versions"),
                f.texts("last_affected"),
                _severities(f),
            )
            for f in data.objects("findings")
        ),
        reasons=data.texts("reasons"),
        data_retrieved_at=data.optional_time("data_retrieved_at"),
    )


def _report(data: _Object | None) -> VulnerabilityReport | None:
    if data is None:
        return None
    return VulnerabilityReport(
        provider=data.text("provider"),
        checked_at=data.time("checked_at"),
        data_source=data.enum("data_source", DataSource),
        checks=tuple(_check(c) for c in data.objects("checks")),
        advisories=tuple(_advisory(a) for a in data.objects("advisories")),
        oldest_data_at=data.optional_time("oldest_data_at"),
        diagnostics=_diagnostics(data),
    )


def scan_from_dict(value: object) -> ScanResult:
    """Rebuild a scan from a parsed ``dva.report/1`` document."""
    data = _Object(value, "the report")
    if data.optional_text("schema_version") != SCHEMA_VERSION:
        raise ReportFormatError(f"the report is not in the {SCHEMA_VERSION} format")
    try:
        return ScanResult(
            tool_version=data.text("tool_version"),
            project_name=data.text("project_name"),
            started_at=data.time("started_at"),
            finished_at=data.time("finished_at"),
            manifests=tuple(_manifest(m) for m in data.objects("manifests")),
            diagnostics=_diagnostics(data),
            vulnerabilities=_report(data.object("vulnerabilities")),
        )
    except ReportFormatError:
        raise
    except (ValueError, TypeError) as error:
        raise ReportFormatError(f"the report contains an invalid value: {error}") from None


def loads_scan(text: str) -> ScanResult:
    """Rebuild a scan from JSON report text."""
    if len(text) > MAX_REPORT_BYTES:
        raise ReportFormatError("the report is too large")
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        raise ReportFormatError("the report is not valid JSON") from None
    return scan_from_dict(value)
