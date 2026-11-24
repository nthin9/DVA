"""Declared requirements, resolved packages, and dependency edges.

Declared constraints (what a manifest asks for) are kept separate from
resolved package instances (what a lockfile says was selected). Versions and
constraints are stored verbatim; comparing them is ecosystem-specific and is
never done in the domain layer.
"""

from __future__ import annotations

from dataclasses import dataclass

from dva.domain.identity import PackageIdentity


def _require_optional_text(field: str, value: str | None) -> None:
    if value is not None and not value.strip():
        raise ValueError(f"{field} must be None or non-empty")


def _require_groups(groups: tuple[str, ...]) -> None:
    for group in groups:
        if not group or not group.strip():
            raise ValueError("group labels must be non-empty")
    if len(set(groups)) != len(groups):
        raise ValueError(f"group labels must be unique: {groups!r}")


@dataclass(frozen=True, slots=True)
class DeclaredRequirement:
    """A dependency declaration as written in a manifest.

    ``constraint`` is the raw version constraint (``None`` when the manifest
    declares no constraint). ``markers`` holds raw environment/platform
    conditions. ``groups`` holds adapter-defined labels such as ``dev`` or
    ``optional``. ``line`` is the 1-based source line when known.
    """

    identity: PackageIdentity
    constraint: str | None = None
    markers: str | None = None
    groups: tuple[str, ...] = ()
    line: int | None = None

    def __post_init__(self) -> None:
        _require_optional_text("constraint", self.constraint)
        _require_optional_text("markers", self.markers)
        _require_groups(self.groups)
        if self.line is not None and self.line < 1:
            raise ValueError(f"line must be >= 1: {self.line}")


@dataclass(frozen=True, slots=True)
class ResolvedPackage:
    """A concrete package instance at an exact version, as recorded by a lockfile.

    ``node_id`` is unique within one manifest analysis. The same package name
    may appear several times at different versions, so a node is never keyed
    by name alone.
    """

    node_id: str
    identity: PackageIdentity
    version: str
    groups: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.node_id or not self.node_id.strip():
            raise ValueError("node_id must be non-empty")
        if not self.version or not self.version.strip():
            raise ValueError("version must be non-empty")
        _require_groups(self.groups)


@dataclass(frozen=True, slots=True)
class DependencyEdge:
    """A dependency relationship between resolved packages.

    ``parent_id`` is ``None`` when the dependency is declared directly by the
    project (the manifest root); otherwise it is the ``node_id`` of the
    depending package. ``constraint`` is the raw requested range, if recorded.
    """

    parent_id: str | None
    child_id: str
    constraint: str | None = None

    def __post_init__(self) -> None:
        if not self.child_id:
            raise ValueError("child_id must be non-empty")
        if self.parent_id is not None and not self.parent_id:
            raise ValueError("parent_id must be None or non-empty")
        if self.parent_id == self.child_id:
            raise ValueError(f"self-referencing edge: {self.child_id!r}")
        _require_optional_text("constraint", self.constraint)

    @property
    def is_direct(self) -> bool:
        return self.parent_id is None
