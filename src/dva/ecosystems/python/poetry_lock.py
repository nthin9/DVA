"""Poetry lockfiles (``poetry.lock``), ``lock-version`` 2.0 and 2.1.

A ``poetry.lock`` records every locked package and what each one depends on,
but not which packages the project itself asked for; those live in
``pyproject.toml``. So the graph has links between packages but no direct
edges, and an info diagnostic says so. Lock-version 2.1 also records the
dependency groups each package belongs to, which are kept as
``group:<name>`` labels.

When a dependency name is locked more than once (for different platforms),
the dependency's version range is checked against each candidate using
Python's version rules (PEP 440). If that doesn't single one out, the link is
reported as unresolved rather than guessed. Source URLs are not copied into
the result, because private repository URLs can contain credentials.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.dependency import ResolvedPackage, SourceKind
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ParseStatus
from dva.ecosystems.python.lockgraph import LockGraph
from dva.ecosystems.python.names import canonical, identity
from dva.ecosystems.python.tomlfile import failure, load_toml
from dva.ecosystems.text import preview

SUPPORTED_VERSIONS = ("2.0", "2.1")

_SOURCE_KINDS = {
    "git": SourceKind.GIT,
    "url": SourceKind.URL,
    "file": SourceKind.PATH,
    "directory": SourceKind.PATH,
    # A private or alternative package index: still a registry.
    "legacy": SourceKind.REGISTRY,
}


@dataclass
class _Entry:
    name: str
    version: str
    node_id: str
    table: Mapping[str, Any]


@dataclass
class _State:
    path: str
    diagnostics: list[Diagnostic] = field(default_factory=list)
    incomplete: bool = False

    def warn(self, code: str, message: str) -> None:
        self.incomplete = True
        self.diagnostics.append(Diagnostic(code, DiagnosticLevel.WARNING, message, self.path))

    def note(self, code: str, message: str) -> None:
        self.diagnostics.append(Diagnostic(code, DiagnosticLevel.INFO, message, self.path))


def parse_poetry_lock(context: ParseContext) -> AdapterResult:
    document = load_toml(context, "python.poetry_lock.invalid_toml")
    if isinstance(document, AdapterResult):
        return document

    metadata = document.get("metadata")
    lock_version = metadata.get("lock-version") if isinstance(metadata, dict) else None
    if not isinstance(lock_version, str):
        return failure(
            context, "python.poetry_lock.no_version", "the lockfile has no [metadata] lock-version"
        )
    if lock_version not in SUPPORTED_VERSIONS:
        return AdapterResult(
            status=ParseStatus.UNSUPPORTED,
            format_version=lock_version,
            diagnostics=(
                Diagnostic(
                    "python.poetry_lock.unsupported_version",
                    DiagnosticLevel.WARNING,
                    f"Poetry lock-version {preview(lock_version)} is not supported "
                    f"(supported: {', '.join(SUPPORTED_VERSIONS)})",
                    context.path,
                ),
            ),
        )

    raw_packages = document.get("package", [])
    if not isinstance(raw_packages, list):
        return failure(context, "python.poetry_lock.invalid_field", "[[package]] is not an array")

    state = _State(path=context.path)
    graph = LockGraph()
    entries = _read_entries(state, graph, raw_packages)
    by_name: dict[str, list[_Entry]] = {}
    for entry in entries:
        by_name.setdefault(entry.name, []).append(entry)
    for entry in entries:
        _add_dependencies(state, graph, entry, by_name)

    state.note(
        "python.poetry_lock.no_direct_dependencies",
        "poetry.lock does not record which packages the project depends on directly; "
        "they are declared in pyproject.toml",
    )
    packages, _ = graph.packages_with_groups()
    return AdapterResult(
        status=ParseStatus.PARTIAL if state.incomplete else ParseStatus.PARSED,
        format_version=lock_version,
        packages=packages,
        edges=graph.edges(),
        diagnostics=tuple(state.diagnostics),
    )


def _read_entries(state: _State, graph: LockGraph, raw_packages: list[object]) -> list[_Entry]:
    entries = []
    for index, table in enumerate(raw_packages):
        if not isinstance(table, dict):
            state.warn("python.poetry_lock.invalid_entry", f"package entry {index} is not a table")
            continue
        name, version = table.get("name"), table.get("version")
        if not isinstance(name, str) or not name.strip():
            state.warn("python.poetry_lock.invalid_entry", f"package entry {index} has no name")
            continue
        if not isinstance(version, str) or not version.strip():
            state.warn(
                "python.poetry_lock.invalid_entry",
                f"package {preview(name)!r} has no valid version",
            )
            continue
        name = canonical(name)
        node_id = f"{name}@{version}"
        if node_id in graph.packages:
            node_id = f"{node_id}#{index}"
        kind = _source_kind(state, name, table.get("source"))
        graph.packages[node_id] = ResolvedPackage(
            node_id,
            identity(name, from_registry=kind is SourceKind.REGISTRY),
            version,
            groups=_groups(table.get("groups")),
            source=kind,
        )
        entries.append(_Entry(name, version, node_id, table))
    return entries


def _source_kind(state: _State, name: str, source: object) -> SourceKind:
    if source is None:
        return SourceKind.REGISTRY
    kind = source.get("type") if isinstance(source, dict) else None
    if isinstance(kind, str) and kind in _SOURCE_KINDS:
        return _SOURCE_KINDS[kind]
    state.note(
        "python.poetry_lock.unknown_source",
        f"package {preview(name)!r} has a source type DVA does not recognise",
    )
    return SourceKind.UNKNOWN


def _groups(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(sorted({f"group:{canonical(g)}" for g in value if isinstance(g, str) and g}))


def _extras_by_dependency(table: Mapping[str, Any]) -> dict[str, list[str]]:
    """Which of a package's extras pull in each optional dependency."""
    found: dict[str, list[str]] = {}
    extras = table.get("extras")
    if not isinstance(extras, dict):
        return found
    for extra, requirements in extras.items():
        if not isinstance(requirements, list):
            continue
        for text in requirements:
            if not isinstance(text, str):
                continue
            try:
                name = canonical(Requirement(text).name)
            except InvalidRequirement:
                continue
            found.setdefault(name, []).append(f"optional:{canonical(extra)}")
    return found


def _add_dependencies(
    state: _State, graph: LockGraph, entry: _Entry, by_name: Mapping[str, list[_Entry]]
) -> None:
    dependencies = entry.table.get("dependencies")
    if dependencies is None:
        return
    if not isinstance(dependencies, dict):
        state.warn(
            "python.poetry_lock.invalid_field",
            f"dependencies of {preview(entry.name)!r} is not a table",
        )
        return
    extras = _extras_by_dependency(entry.table)
    for raw_name, spec in dependencies.items():
        name = canonical(raw_name)
        specs = spec if isinstance(spec, list) else [spec]
        for item in specs:
            constraint, markers, optional = _spec_fields(item)
            target = _pick(state, entry, name, constraint, by_name)
            if target is None:
                continue
            groups = tuple(sorted(set(extras.get(name, ["optional"])))) if optional else ()
            graph.add_edge(
                entry.node_id,
                target.node_id,
                constraint=constraint,
                markers=markers,
                groups=groups,
            )


def _spec_fields(item: object) -> tuple[str | None, str | None, bool]:
    if isinstance(item, str):
        return (item.strip() or None), None, False
    if not isinstance(item, dict):
        return None, None, False
    version, markers = item.get("version"), item.get("markers")
    return (
        version.strip() or None if isinstance(version, str) else None,
        markers.strip() or None if isinstance(markers, str) else None,
        item.get("optional") is True,
    )


def _pick(
    state: _State,
    entry: _Entry,
    name: str,
    constraint: str | None,
    by_name: Mapping[str, list[_Entry]],
) -> _Entry | None:
    candidates = by_name.get(name, [])
    if len(candidates) > 1 and constraint and constraint != "*":
        candidates = [c for c in candidates if _satisfies(c.version, constraint)]
    if len(candidates) == 1:
        return candidates[0]
    reason = "is not in the lockfile" if not candidates else "matches more than one entry"
    state.warn(
        "python.poetry_lock.unresolved_dependency",
        f"dependency {preview(name)!r} of {preview(entry.name)!r} {reason}",
    )
    return None


def _satisfies(version: str, constraint: str) -> bool:
    """Whether ``version`` is inside ``constraint`` under PEP 440 rules.

    Poetry writes ranges in PEP 440 form inside lockfiles. A range or version
    that doesn't parse counts as no match, which leaves the link unresolved.
    """
    try:
        return SpecifierSet(constraint).contains(Version(version), prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        return False
