"""npm ``package.json`` dependency declarations.

Reads ``dependencies``, ``devDependencies`` (labelled ``dev``),
``optionalDependencies`` (``optional``) and ``peerDependencies`` (``peer``,
plus ``optional`` when ``peerDependenciesMeta`` marks the peer optional).
Packages listed in ``bundleDependencies`` are also labelled ``bundled``.
As npm does, an entry in ``optionalDependencies`` replaces an entry of the
same name in ``dependencies``.

``workspaces``, ``overrides`` and ``resolutions`` are noted: workspace
members have their own ``package.json`` that is scanned separately, and
overrides change resolution, which only a lockfile shows.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.dependency import DeclaredRequirement, SourceKind
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ParseStatus
from dva.ecosystems.npm.jsonfile import load_json_object
from dva.ecosystems.npm.names import identity, is_valid_name
from dva.ecosystems.npm.spec import InvalidSpecError, classify
from dva.ecosystems.text import preview

#: Dependency fields and the group labels their entries get.
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

    def warn(self, code: str, message: str) -> None:
        self.incomplete = True
        self.diagnostics.append(Diagnostic(code, DiagnosticLevel.WARNING, message, self.path))

    def note(self, code: str, message: str) -> None:
        self.diagnostics.append(Diagnostic(code, DiagnosticLevel.INFO, message, self.path))


def parse_package_json(context: ParseContext) -> AdapterResult:
    loaded = load_json_object(context, "npm.package_json.invalid_json")
    if isinstance(loaded, AdapterResult):
        return loaded
    document, duplicates = loaded
    state = _State(path=context.path)
    if duplicates:
        state.warn(
            "npm.duplicate_keys",
            f"{duplicates} key(s) appear more than once; the last value was used, as npm does",
        )

    bundled = _bundled(state, document)
    peer_meta = document.get("peerDependenciesMeta")
    entries: dict[tuple[str, str], DeclaredRequirement] = {}
    for section, labels in _SECTIONS:
        table = document.get(section)
        if table is None:
            continue
        if not isinstance(table, dict):
            state.warn("npm.package_json.invalid_field", f"{section} is not an object")
            continue
        for name, value in table.items():
            requirement = _requirement(state, section, name, value, labels, bundled, peer_meta)
            if requirement is None:
                continue
            if section == "optionalDependencies":
                entries.pop(("dependencies", name), None)
            entries[(section, name)] = requirement

    for key, description in (
        ("workspaces", "workspace members are scanned from their own package.json files"),
        ("overrides", "overrides change which versions get installed; see the lockfile"),
        ("resolutions", "resolutions change which versions get installed; see the lockfile"),
    ):
        if key in document:
            state.note(f"npm.package_json.{key}", f"{key} found: {description}")

    return AdapterResult(
        status=ParseStatus.PARTIAL if state.incomplete else ParseStatus.PARSED,
        requirements=tuple(entries.values()),
        diagnostics=tuple(state.diagnostics),
    )


def _bundled(state: _State, document: Mapping[str, Any]) -> set[str]:
    value = document.get("bundleDependencies", document.get("bundledDependencies"))
    if value is None or isinstance(value, bool):
        return set()
    if not isinstance(value, list):
        state.warn("npm.package_json.invalid_field", "bundleDependencies is not an array")
        return set()
    return {name for name in value if isinstance(name, str)}


def _requirement(
    state: _State,
    section: str,
    name: object,
    value: object,
    labels: tuple[str, ...],
    bundled: set[str],
    peer_meta: object,
) -> DeclaredRequirement | None:
    if not isinstance(name, str) or not is_valid_name(name):
        state.warn(
            "npm.package_json.invalid_name",
            f"{section}: {preview(str(name))!r} is not a valid package name",
        )
        return None
    if not isinstance(value, str):
        state.warn(
            "npm.package_json.invalid_spec",
            f"{section}.{name}: the version spec is not a string",
        )
        return None
    try:
        spec = classify(value)
    except InvalidSpecError as error:
        state.warn("npm.package_json.invalid_spec", f"{section}.{name}: {error}")
        return None

    groups = set(labels)
    if name in bundled:
        groups.add("bundled")
    if section == "peerDependencies" and _optional_peer(peer_meta, name):
        groups.add("optional")
    real_name = spec.target_name or name
    return DeclaredRequirement(
        identity=identity(real_name, from_registry=spec.source is SourceKind.REGISTRY),
        constraint=spec.constraint,
        groups=tuple(sorted(groups)),
        source=spec.source,
        alias=name if spec.target_name and spec.target_name != name else None,
    )


def _optional_peer(meta: object, name: str) -> bool:
    if not isinstance(meta, dict):
        return False
    entry = meta.get(name)
    return isinstance(entry, dict) and entry.get("optional") is True
