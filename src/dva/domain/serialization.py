"""Deterministic JSON serialization of scan results: DVA's JSON report format.

The format is versioned by ``SCHEMA_VERSION`` and documented in
``docs/REPORT_FORMAT.md``. A change that removes or renames a field, or
changes what one means, needs a new version.

Determinism: object keys are sorted, collections are emitted in a canonical
order that does not depend on input order, and timestamps use a fixed UTC
format. Sorting uses identifiers and paths, with version strings only as a
plain-text tie-breaker for a stable order; they are never compared as versions.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from dva.domain.advisory import Advisory, AffectedPackage, Severity
from dva.domain.dependency import DeclaredRequirement, DependencyEdge, ResolvedPackage
from dva.domain.diagnostics import Diagnostic
from dva.domain.identity import PackageIdentity
from dva.domain.manifest import ManifestAnalysis
from dva.domain.scan import ScanResult
from dva.domain.vulnerability import Location, PackageCheck, VulnerabilityReport

SCHEMA_VERSION = "dva.report/1"

type JsonValue = str | int | bool | None | list[JsonValue] | dict[str, JsonValue]


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identity(identity: PackageIdentity) -> dict[str, JsonValue]:
    return {
        "ecosystem": identity.ecosystem,
        "namespace": identity.namespace,
        "name": identity.name,
        "purl": identity.purl,
    }


def _identity_key(identity: PackageIdentity) -> tuple[str, str, str, str]:
    return (identity.ecosystem, identity.namespace or "", identity.name, identity.purl or "")


def _diagnostic(diagnostic: Diagnostic) -> dict[str, JsonValue]:
    return {
        "code": diagnostic.code,
        "level": diagnostic.level.value,
        "message": diagnostic.message,
        "path": diagnostic.path,
    }


def _diagnostics(items: tuple[Diagnostic, ...]) -> list[JsonValue]:
    ordered = sorted(items, key=lambda d: (d.path or "", d.code, d.level.value, d.message))
    return [_diagnostic(d) for d in ordered]


def _requirement(requirement: DeclaredRequirement) -> dict[str, JsonValue]:
    return {
        "identity": _identity(requirement.identity),
        "constraint": requirement.constraint,
        "markers": requirement.markers,
        "groups": [g for g in sorted(requirement.groups)],
        "line": requirement.line,
        "source": requirement.source.value,
        "extras": [e for e in sorted(requirement.extras)],
        "alias": requirement.alias,
        "origin": requirement.origin,
        "constrained_to": requirement.constrained_to,
    }


def _requirement_key(
    r: DeclaredRequirement,
) -> tuple[int, tuple[str, str, str, str], str, str, str, tuple[str, ...], str]:
    return (
        r.line or 0,
        _identity_key(r.identity),
        r.constraint or "",
        r.markers or "",
        r.alias or "",
        tuple(sorted(r.groups)),
        r.source.value,
    )


def _package(package: ResolvedPackage) -> dict[str, JsonValue]:
    return {
        "node_id": package.node_id,
        "identity": _identity(package.identity),
        "version": package.version,
        "groups": [g for g in sorted(package.groups)],
        "source": package.source.value,
        "markers": package.markers,
    }


def _edge(edge: DependencyEdge) -> dict[str, JsonValue]:
    return {
        "parent_id": edge.parent_id,
        "child_id": edge.child_id,
        "direct": edge.is_direct,
        "constraint": edge.constraint,
        "markers": edge.markers,
        "groups": [g for g in sorted(edge.groups)],
    }


def _manifest(manifest: ManifestAnalysis) -> dict[str, JsonValue]:
    requirements = sorted(manifest.requirements, key=_requirement_key)
    packages = sorted(manifest.packages, key=lambda p: p.node_id)
    edges = sorted(
        manifest.edges,
        key=lambda e: (
            e.parent_id or "",
            e.child_id,
            e.constraint or "",
            e.markers or "",
            tuple(sorted(e.groups)),
        ),
    )
    return {
        "path": manifest.path,
        "adapter_id": manifest.adapter_id,
        "ecosystem": manifest.ecosystem,
        "kind": manifest.kind.value,
        "format_name": manifest.format_name,
        "format_version": manifest.format_version,
        "status": manifest.status.value,
        "requirements": [_requirement(r) for r in requirements],
        "packages": [_package(p) for p in packages],
        "edges": [_edge(e) for e in edges],
        "diagnostics": _diagnostics(manifest.diagnostics),
    }


def _optional_timestamp(value: datetime | None) -> str | None:
    return _timestamp(value) if value is not None else None


def _strings(values: tuple[str, ...]) -> list[JsonValue]:
    return [v for v in values]


def _severity_list(severities: tuple[Severity, ...]) -> list[JsonValue]:
    return [{"type": s.type, "score": s.score, "source": s.source} for s in severities]


def _affected(package: AffectedPackage) -> dict[str, JsonValue]:
    return {
        "ecosystem": package.ecosystem,
        "name": package.name,
        "purl": package.purl,
        "ranges": [
            {
                "type": r.type,
                "repo": r.repo,
                "events": [{r_event.kind.value: r_event.version} for r_event in r.events],
            }
            for r in package.ranges
        ],
        "versions": _strings(package.versions),
        "severities": _severity_list(package.severities),
    }


def _advisory(advisory: Advisory) -> dict[str, JsonValue]:
    return {
        "id": advisory.id,
        "aliases": _strings(advisory.aliases),
        "related": _strings(advisory.related),
        "summary": advisory.summary,
        "details": advisory.details,
        "severities": _severity_list(advisory.severities),
        "database_severity": advisory.database_severity,
        "references": [{"type": r.type, "url": r.url} for r in advisory.references],
        "affected": [_affected(p) for p in advisory.affected],
        "published": _optional_timestamp(advisory.published),
        "modified": _timestamp(advisory.modified),
        "withdrawn": _optional_timestamp(advisory.withdrawn),
        "schema_version": advisory.schema_version,
    }


def _location(location: Location) -> dict[str, JsonValue]:
    return {"path": location.path, "node_id": location.node_id, "line": location.line}


def _location_key(location: Location) -> tuple[str, str, int]:
    return (location.path, location.node_id or "", location.line or 0)


def _check(check: PackageCheck) -> dict[str, JsonValue]:
    return {
        "identity": _identity(check.identity),
        "version": check.version,
        "status": check.status.value,
        "locations": [_location(loc) for loc in sorted(check.locations, key=_location_key)],
        "findings": [
            {
                "advisory_id": f.advisory_id,
                "matched_by": _strings(f.matched_by),
                "fixed_versions": _strings(f.fixed_versions),
                "last_affected": _strings(f.last_affected),
                "severities": _severity_list(f.severities),
            }
            for f in sorted(check.findings, key=lambda f: f.advisory_id)
        ],
        "reasons": _strings(check.reasons),
        "data_retrieved_at": _optional_timestamp(check.data_retrieved_at),
    }


def _check_key(check: PackageCheck) -> tuple[tuple[str, str, str, str], str, str, str]:
    first = min(check.locations, key=_location_key)
    return (
        _identity_key(check.identity),
        check.version or "",
        check.status.value,
        "/".join(str(part) for part in _location_key(first)),
    )


def _report(report: VulnerabilityReport | None) -> JsonValue:
    if report is None:
        return None
    return {
        "provider": report.provider,
        "checked_at": _timestamp(report.checked_at),
        "data_source": report.data_source.value,
        "oldest_data_at": _optional_timestamp(report.oldest_data_at),
        "checks": [_check(c) for c in sorted(report.checks, key=_check_key)],
        "advisories": [_advisory(a) for a in sorted(report.advisories, key=lambda a: a.id)],
        "diagnostics": _diagnostics(report.diagnostics),
    }


def scan_to_dict(scan: ScanResult) -> dict[str, JsonValue]:
    """Convert a scan result to JSON-compatible primitives in canonical order."""
    manifests = sorted(scan.manifests, key=lambda m: m.path)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": scan.tool_version,
        "project_name": scan.project_name,
        "started_at": _timestamp(scan.started_at),
        "finished_at": _timestamp(scan.finished_at),
        "completion": scan.completion.value,
        "vulnerability_status": scan.vulnerability_status.value,
        "vulnerabilities": _report(scan.vulnerabilities),
        "manifests": [_manifest(m) for m in manifests],
        "diagnostics": _diagnostics(scan.diagnostics),
        "excluded": _strings(scan.excluded),
    }


def dumps_scan(scan: ScanResult) -> str:
    """Serialize a scan result to canonical JSON text (UTF-8 safe, trailing newline)."""
    return json.dumps(scan_to_dict(scan), sort_keys=True, ensure_ascii=False, indent=2) + "\n"
