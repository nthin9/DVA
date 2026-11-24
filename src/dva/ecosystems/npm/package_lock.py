"""npm lockfiles (``package-lock.json`` and ``npm-shrinkwrap.json``), versions 2 and 3.

Both versions describe the installed tree in a ``packages`` object keyed by
folder: ``""`` is the project, ``node_modules/a`` is a package, and
``node_modules/a/node_modules/b`` is a copy of ``b`` nested inside ``a``.
Each folder is a node of the graph, so the same package at two versions is two
nodes. Links between them are found the way Node.js finds a module: starting
from the depending package's folder, look in its ``node_modules``, then in
each parent folder's, up to the project root.

The project itself and workspace members (folders outside ``node_modules``)
are not packages. Their dependencies are the project's direct dependencies.
Packages keep npm's ``dev``, ``optional`` and ``peer`` flags as group labels.
Version 1 lockfiles use a different layout and are reported as unsupported.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.dependency import DependencyEdge, ResolvedPackage, SourceKind
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ParseStatus
from dva.ecosystems.npm.jsonfile import failure, load_json_object
from dva.ecosystems.npm.names import identity, is_valid_name
from dva.ecosystems.text import preview, redact_url

SUPPORTED_VERSIONS = (2, 3)
_NODE_MODULES = "node_modules"
_SEGMENT = "/node_modules/"

#: Dependency fields of a lockfile entry and the labels their links get.
_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("dependencies", ()),
    ("optionalDependencies", ("optional",)),
    ("devDependencies", ("dev",)),
    ("peerDependencies", ("peer",)),
)


@dataclass
class _State:
    path: str
    diagnostics: list[Diagnostic] = field(default_factory=list)
    incomplete: bool = False
    _counts: dict[str, int] = field(default_factory=dict)

    def warn(self, code: str, message: str) -> None:
        self.incomplete = True
        self.diagnostics.append(Diagnostic(code, DiagnosticLevel.WARNING, message, self.path))

    def note(self, code: str, message: str) -> None:
        self.diagnostics.append(Diagnostic(code, DiagnosticLevel.INFO, message, self.path))

    def count(self, code: str) -> None:
        self._counts[code] = self._counts.get(code, 0) + 1

    def counted(self, code: str) -> int:
        return self._counts.get(code, 0)


def parse_package_lock(context: ParseContext) -> AdapterResult:
    loaded = load_json_object(context, "npm.package_lock.invalid_json")
    if isinstance(loaded, AdapterResult):
        return loaded
    document, duplicates = loaded

    version = document.get("lockfileVersion")
    if not isinstance(version, int) or isinstance(version, bool):
        return failure(
            context, "npm.package_lock.no_version", "the lockfile has no lockfileVersion"
        )
    if version not in SUPPORTED_VERSIONS:
        return AdapterResult(
            status=ParseStatus.UNSUPPORTED,
            format_version=str(version),
            diagnostics=(
                Diagnostic(
                    "npm.package_lock.unsupported_version",
                    DiagnosticLevel.WARNING,
                    f"lockfileVersion {version} is not supported (supported: 2, 3)",
                    context.path,
                ),
            ),
        )
    entries = document.get("packages")
    if not isinstance(entries, dict):
        return failure(context, "npm.package_lock.invalid_field", "the lockfile has no packages")

    state = _State(path=context.path)
    if duplicates:
        state.warn(
            "npm.duplicate_keys",
            f"{duplicates} key(s) appear more than once; the last value was used, as npm does",
        )
    tables = {key: value for key, value in entries.items() if _valid_entry(state, key, value)}
    if "" not in tables:
        state.warn(
            "npm.package_lock.no_project",
            "the lockfile has no entry for the project itself, so direct dependencies are unknown",
        )

    packages = _packages(state, tables)
    edges: dict[tuple[str | None, str, str | None], DependencyEdge] = {}
    for key, table in tables.items():
        if table.get("link") is True:
            continue
        if _is_project(key) or key in packages:
            _add_edges(state, key, table, tables, packages, edges)

    for code, message in (
        ("npm.package_lock.optional_missing", "optional dependencies are not installed"),
        ("npm.package_lock.extraneous", "packages are marked extraneous (nothing depends on them)"),
    ):
        if state.counted(code):
            state.note(code, f"{state.counted(code)} {message}")

    return AdapterResult(
        status=ParseStatus.PARTIAL if state.incomplete else ParseStatus.PARSED,
        format_version=str(version),
        packages=tuple(packages.values()),
        edges=tuple(edges.values()),
        diagnostics=tuple(state.diagnostics),
    )


def _valid_entry(state: _State, key: object, value: object) -> bool:
    if not isinstance(key, str) or not isinstance(value, dict):
        state.warn(
            "npm.package_lock.invalid_entry", f"entry {preview(str(key))!r} is not an object"
        )
        return False
    return True


def _is_project(key: str) -> bool:
    """The project root or a workspace member: a folder that isn't inside node_modules."""
    return key == "" or (not key.startswith(_NODE_MODULES + "/") and _SEGMENT not in key)


def _name_from_key(key: str) -> str:
    index = key.rfind(_NODE_MODULES + "/")
    return key[index + len(_NODE_MODULES) + 1 :]


def _packages(state: _State, tables: Mapping[str, Mapping[str, Any]]) -> dict[str, ResolvedPackage]:
    packages: dict[str, ResolvedPackage] = {}
    for key, table in tables.items():
        if _is_project(key) or table.get("link") is True:
            continue
        name = table.get("name")
        if not isinstance(name, str):
            name = _name_from_key(key)
        version = table.get("version")
        if not is_valid_name(name):
            state.warn(
                "npm.package_lock.invalid_entry",
                f"entry {preview(key)!r} does not name a valid package",
            )
            continue
        if not isinstance(version, str) or not version.strip():
            state.warn(
                "npm.package_lock.missing_version",
                f"entry {preview(key)!r} has no version; not included",
            )
            continue
        if table.get("extraneous") is True:
            state.count("npm.package_lock.extraneous")
        source = _source(table)
        packages[key] = ResolvedPackage(
            key,
            identity(name, from_registry=source is SourceKind.REGISTRY),
            version,
            groups=_flags(table),
            source=source,
        )
    return packages


def _source(table: Mapping[str, Any]) -> SourceKind:
    resolved = table.get("resolved")
    if not isinstance(resolved, str) or not resolved:
        return SourceKind.UNKNOWN
    lowered = resolved.lower()
    if lowered.startswith(("git+", "git://", "github:")):
        return SourceKind.GIT
    if lowered.startswith("file:"):
        return SourceKind.PATH
    if lowered.startswith(("http://", "https://")):
        # Registry tarballs live under "<registry>/<name>/-/<file>.tgz".
        return SourceKind.REGISTRY if "/-/" in resolved else SourceKind.URL
    return SourceKind.UNKNOWN


def _flags(table: Mapping[str, Any]) -> tuple[str, ...]:
    groups = set()
    if table.get("dev") is True:
        groups.add("dev")
    if table.get("optional") is True:
        groups.add("optional")
    if table.get("devOptional") is True:
        groups.update(("dev", "optional"))
    if table.get("peer") is True:
        groups.add("peer")
    return tuple(sorted(groups))


def _lookup(parent_key: str, name: str, tables: Mapping[str, Mapping[str, Any]]) -> str | None:
    """The folder Node.js would load ``name`` from, starting at ``parent_key``."""
    parts = parent_key.split("/") if parent_key else []
    while True:
        if not parts or parts[-1] != _NODE_MODULES:
            prefix = "/".join(parts)
            candidate = f"{prefix}/{_NODE_MODULES}/{name}" if prefix else f"{_NODE_MODULES}/{name}"
            if candidate in tables:
                return candidate
        if not parts:
            return None
        parts.pop()


def _follow_link(
    key: str, tables: Mapping[str, Mapping[str, Any]], packages: Mapping[str, ResolvedPackage]
) -> str | None:
    """Where a dependency's folder really points: itself, or a link's target."""
    table = tables[key]
    if table.get("link") is not True:
        return key
    target = table.get("resolved")
    if isinstance(target, str) and (
        target in packages or (target in tables and _is_project(target))
    ):
        return target
    return None


def _add_edges(
    state: _State,
    key: str,
    table: Mapping[str, Any],
    tables: Mapping[str, Mapping[str, Any]],
    packages: Mapping[str, ResolvedPackage],
    edges: dict[tuple[str | None, str, str | None], DependencyEdge],
) -> None:
    parent = None if _is_project(key) else key
    peer_meta = table.get("peerDependenciesMeta")
    where = "the project" if key == "" else repr(preview(key))
    for section, labels in _SECTIONS:
        if section == "devDependencies" and parent is not None:
            continue  # only the project's own dev dependencies are installed
        declared = table.get(section)
        if declared is None:
            continue
        if not isinstance(declared, dict):
            state.warn("npm.package_lock.invalid_field", f"{section} of {where} is not an object")
            continue
        for name, spec in declared.items():
            if not isinstance(name, str) or not is_valid_name(name):
                state.warn(
                    "npm.package_lock.invalid_entry",
                    f"{section} of {where} names an invalid package",
                )
                continue
            optional = section == "optionalDependencies" or (
                section == "peerDependencies"
                and isinstance(peer_meta, dict)
                and isinstance(peer_meta.get(name), dict)
                and peer_meta[name].get("optional") is True
            )
            found = _lookup(key, name, tables)
            child = _follow_link(found, tables, packages) if found else None
            if child is None:
                if optional:
                    state.count("npm.package_lock.optional_missing")
                else:
                    state.warn(
                        "npm.package_lock.unresolved_dependency",
                        f"{preview(name)!r} required by {where} is not in the lockfile",
                    )
                continue
            if child not in packages:
                continue  # a workspace member: part of the project, not a package
            raw = spec.strip() if isinstance(spec, str) else ""
            constraint = redact_url(raw) if raw else None
            groups = set(labels)
            if optional:
                groups.add("optional")
            previous = edges.get((parent, child, constraint))
            if previous is not None:
                groups.update(previous.groups)
            edges[(parent, child, constraint)] = DependencyEdge(
                parent, child, constraint=constraint, groups=tuple(sorted(groups))
            )
