"""Per-file analysis results."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from dva.domain.dependency import DeclaredRequirement, DependencyEdge, ResolvedPackage
from dva.domain.diagnostics import Diagnostic
from dva.domain.paths import require_relative_path


class ManifestKind(StrEnum):
    MANIFEST = "manifest"
    LOCKFILE = "lockfile"


class ParseStatus(StrEnum):
    """Outcome of analyzing one file.

    Only ``PARSED`` means the adapter fully understood the file. Every other
    value means the file's dependency data is incomplete or absent.
    """

    PARSED = "parsed"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class ManifestAnalysis:
    """The analysis of one discovered manifest or lockfile.

    Packages and edges are scoped to this file, so ``node_id`` values only
    need to be unique within it. Edges must reference packages in this file.
    """

    path: str
    adapter_id: str
    ecosystem: str
    kind: ManifestKind
    format_name: str
    status: ParseStatus
    format_version: str | None = None
    requirements: tuple[DeclaredRequirement, ...] = ()
    packages: tuple[ResolvedPackage, ...] = ()
    edges: tuple[DependencyEdge, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        require_relative_path(self.path)
        for field, value in (
            ("adapter_id", self.adapter_id),
            ("ecosystem", self.ecosystem),
            ("format_name", self.format_name),
        ):
            if not value:
                raise ValueError(f"{field} must be non-empty")
        node_ids = [package.node_id for package in self.packages]
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("package node_id values must be unique within a manifest")
        known = set(node_ids)
        for edge in self.edges:
            if edge.child_id not in known:
                raise ValueError(f"edge references unknown child node: {edge.child_id!r}")
            if edge.parent_id is not None and edge.parent_id not in known:
                raise ValueError(f"edge references unknown parent node: {edge.parent_id!r}")
        if self.status is not ParseStatus.PARSED and not self.diagnostics:
            raise ValueError(f"status {self.status} requires at least one diagnostic explaining it")
        if self.status not in (ParseStatus.PARSED, ParseStatus.PARTIAL) and (
            self.requirements or self.packages or self.edges
        ):
            raise ValueError(f"status {self.status} must not carry dependency data")
