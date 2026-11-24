"""Deterministic JSON serialization of internal scan results.

This is DVA's *internal* representation (for tests, snapshots, and later
persistence). It is not the public, user-facing report schema, which is
defined separately when reporting is implemented.

Determinism: object keys are sorted, collections are emitted in a canonical
order that does not depend on input order, and timestamps use a fixed UTC
format. Sorting uses identifiers and paths only; version strings are never
compared.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from dva.domain.dependency import DeclaredRequirement, DependencyEdge, ResolvedPackage
from dva.domain.diagnostics import Diagnostic
from dva.domain.identity import PackageIdentity
from dva.domain.manifest import ManifestAnalysis
from dva.domain.scan import ScanResult

SCHEMA_VERSION = "dva.internal-scan/0"

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
    }


def _requirement_key(r: DeclaredRequirement) -> tuple[int, tuple[str, str, str, str], str, str]:
    return (r.line or 0, _identity_key(r.identity), r.constraint or "", r.markers or "")


def _package(package: ResolvedPackage) -> dict[str, JsonValue]:
    return {
        "node_id": package.node_id,
        "identity": _identity(package.identity),
        "version": package.version,
        "groups": [g for g in sorted(package.groups)],
    }


def _edge(edge: DependencyEdge) -> dict[str, JsonValue]:
    return {
        "parent_id": edge.parent_id,
        "child_id": edge.child_id,
        "direct": edge.is_direct,
        "constraint": edge.constraint,
    }


def _manifest(manifest: ManifestAnalysis) -> dict[str, JsonValue]:
    requirements = sorted(manifest.requirements, key=_requirement_key)
    packages = sorted(manifest.packages, key=lambda p: p.node_id)
    edges = sorted(
        manifest.edges, key=lambda e: (e.parent_id or "", e.child_id, e.constraint or "")
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
        "manifests": [_manifest(m) for m in manifests],
        "diagnostics": _diagnostics(scan.diagnostics),
    }


def dumps_scan(scan: ScanResult) -> str:
    """Serialize a scan result to canonical JSON text (UTF-8 safe, trailing newline)."""
    return json.dumps(scan_to_dict(scan), sort_keys=True, ensure_ascii=False, indent=2) + "\n"
