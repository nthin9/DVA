"""uv lockfiles (``uv.lock``), lockfile ``version = 1``.

A ``uv.lock`` lists every package uv resolved, including the project itself.
The project's own entry (``source = { editable = "." }`` or ``{ virtual = "." }``,
or the workspace members listed under ``[manifest]``) is not a dependency: its
dependencies become the direct edges of the graph. Its optional dependencies
are labelled ``optional:<extra>`` and its development groups ``group:<name>``.

When a name appears more than once (uv can lock different versions for
different platforms), a dependency entry carries the version and source that
pick the right one. Anything that can't be matched is reported, not guessed.
Registry URLs and hashes are not copied into the result.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.dependency import ResolvedPackage, SourceKind
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ParseStatus
from dva.ecosystems.python.lockgraph import LockGraph
from dva.ecosystems.python.names import canonical, identity
from dva.ecosystems.python.tomlfile import failure, load_toml
from dva.ecosystems.text import preview

SUPPORTED_VERSION = 1

_SOURCE_KINDS = {
    "registry": SourceKind.REGISTRY,
    "git": SourceKind.GIT,
    "url": SourceKind.URL,
    "path": SourceKind.PATH,
    "directory": SourceKind.PATH,
    "editable": SourceKind.WORKSPACE,
    "virtual": SourceKind.WORKSPACE,
}


@dataclass
class _Entry:
    index: int
    name: str
    version: str | None
    source_key: tuple[tuple[str, str], ...]
    kind: SourceKind
    table: Mapping[str, Any]
    node_id: str | None = None
    is_root: bool = False


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


def parse_uv_lock(context: ParseContext) -> AdapterResult:
    document = load_toml(context, "python.uv_lock.invalid_toml")
    if isinstance(document, AdapterResult):
        return document

    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        return failure(context, "python.uv_lock.no_version", "the lockfile has no version number")
    if version != SUPPORTED_VERSION:
        return AdapterResult(
            status=ParseStatus.UNSUPPORTED,
            format_version=str(version),
            diagnostics=(
                Diagnostic(
                    "python.uv_lock.unsupported_version",
                    DiagnosticLevel.WARNING,
                    f"uv lockfile version {version} is not supported (supported: 1)",
                    context.path,
                ),
            ),
        )

    state = _State(path=context.path)
    raw_packages = document.get("package", [])
    if not isinstance(raw_packages, list):
        return failure(context, "python.uv_lock.invalid_field", "[[package]] is not an array")

    entries = _read_entries(state, raw_packages)
    roots = _find_roots(entries, document.get("manifest"))
    for root in roots:
        root.is_root = True
    if not roots:
        state.warn(
            "python.uv_lock.no_project",
            "could not find the project's own entry, so direct dependencies are unknown",
        )

    graph = LockGraph()
    used: set[str] = set()
    for entry in entries:
        if entry.is_root:
            continue
        if entry.version is None:
            state.warn(
                "python.uv_lock.missing_version",
                f"package {preview(entry.name)!r} has no version; not included",
            )
            continue
        node_id = f"{entry.name}@{entry.version}"
        if node_id in used:
            node_id = f"{node_id}#{entry.index}"
        used.add(node_id)
        entry.node_id = node_id
        graph.packages[node_id] = ResolvedPackage(
            node_id,
            identity(entry.name, from_registry=entry.kind is SourceKind.REGISTRY),
            entry.version,
            source=entry.kind,
        )

    by_name: dict[str, list[_Entry]] = {}
    for entry in entries:
        by_name.setdefault(entry.name, []).append(entry)
    for entry in entries:
        if entry.is_root or entry.node_id is not None:
            _add_dependencies(state, graph, entry, by_name)

    packages, unreachable = graph.packages_with_groups()
    if unreachable:
        state.note(
            "python.uv_lock.unreachable",
            f"{len(unreachable)} locked package(s) are not reachable from the project's "
            "dependencies",
        )
    return AdapterResult(
        status=ParseStatus.PARTIAL if state.incomplete else ParseStatus.PARSED,
        format_version=str(version),
        packages=packages,
        edges=graph.edges(),
        diagnostics=tuple(state.diagnostics),
    )


def _read_entries(state: _State, raw_packages: list[object]) -> list[_Entry]:
    entries = []
    for index, table in enumerate(raw_packages):
        if not isinstance(table, dict):
            state.warn("python.uv_lock.invalid_entry", f"package entry {index} is not a table")
            continue
        name = table.get("name")
        version = table.get("version")
        if not isinstance(name, str) or not name.strip():
            state.warn("python.uv_lock.invalid_entry", f"package entry {index} has no name")
            continue
        if version is not None and (not isinstance(version, str) or not version.strip()):
            state.warn(
                "python.uv_lock.invalid_entry",
                f"package {preview(name)!r} has an invalid version",
            )
            continue
        kind, source_key = _source(table.get("source"))
        entries.append(_Entry(index, canonical(name), version, source_key, kind, table))
    return entries


def _source(value: object) -> tuple[SourceKind, tuple[tuple[str, str], ...]]:
    if not isinstance(value, dict):
        return SourceKind.UNKNOWN, ()
    key = tuple(sorted((str(k), str(v)) for k, v in value.items()))
    kinds = [_SOURCE_KINDS[k] for k in value if k in _SOURCE_KINDS]
    return (kinds[0] if len(kinds) == 1 else SourceKind.UNKNOWN), key


def _is_project_itself(entry: _Entry) -> bool:
    source = dict(entry.source_key)
    return entry.kind is SourceKind.WORKSPACE and "." in (
        source.get("editable"),
        source.get("virtual"),
    )


def _find_roots(entries: list[_Entry], manifest: object) -> list[_Entry]:
    own = [entry for entry in entries if _is_project_itself(entry)]
    if own:
        return own
    members = manifest.get("members") if isinstance(manifest, dict) else None
    if isinstance(members, list):
        names = {canonical(m) for m in members if isinstance(m, str)}
        return [e for e in entries if e.name in names and e.kind is SourceKind.WORKSPACE]
    return []


def _add_dependencies(
    state: _State,
    graph: LockGraph,
    entry: _Entry,
    by_name: Mapping[str, list[_Entry]],
) -> None:
    parent = None if entry.is_root else entry.node_id
    sections: list[tuple[str, object, str | None]] = [
        ("dependencies", entry.table.get("dependencies"), None)
    ]
    for table_name, prefix in (
        ("optional-dependencies", "optional"),
        ("dev-dependencies", "group"),
    ):
        table = entry.table.get(table_name)
        if table is None:
            continue
        if not isinstance(table, dict):
            state.warn(
                "python.uv_lock.invalid_field",
                f"{table_name} of {preview(entry.name)!r} is not a table",
            )
            continue
        for label, items in table.items():
            sections.append((table_name, items, f"{prefix}:{canonical(label)}"))

    for table_name, items, label in sections:
        if items is None:
            continue
        if not isinstance(items, list):
            state.warn(
                "python.uv_lock.invalid_field",
                f"{table_name} of {preview(entry.name)!r} is not an array",
            )
            continue
        for item in items:
            target = _resolve(state, entry, item, by_name)
            if target is None or target.node_id is None:
                continue
            marker = item.get("marker") if isinstance(item, dict) else None
            graph.add_edge(
                parent,
                target.node_id,
                markers=marker if isinstance(marker, str) and marker.strip() else None,
                groups=(label,) if label else (),
            )


def _resolve(
    state: _State, entry: _Entry, item: object, by_name: Mapping[str, list[_Entry]]
) -> _Entry | None:
    if not isinstance(item, dict) or not isinstance(item.get("name"), str):
        state.warn(
            "python.uv_lock.invalid_entry",
            f"a dependency of {preview(entry.name)!r} has no name",
        )
        return None
    name = canonical(item["name"])
    candidates = by_name.get(name, [])
    version = item.get("version")
    if isinstance(version, str):
        candidates = [c for c in candidates if c.version == version]
    _, source_key = _source(item.get("source"))
    if source_key:
        candidates = [c for c in candidates if c.source_key == source_key]
    if len(candidates) == 1:
        return candidates[0]
    reason = "is not in the lockfile" if not candidates else "matches more than one entry"
    state.warn(
        "python.uv_lock.unresolved_dependency",
        f"dependency {preview(name)!r} of {preview(entry.name)!r} {reason}",
    )
    return None
