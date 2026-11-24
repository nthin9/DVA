"""``pyproject.toml`` dependency declarations.

Reads the standard tables only:

* ``[project] dependencies`` and ``optional-dependencies`` (PEP 621), with
  optional dependencies labelled ``optional:<extra>``;
* ``[dependency-groups]`` (PEP 735), labelled ``group:<name>``, following
  ``include-group`` entries so a requirement carries every group it belongs to.

Tool-specific tables (Poetry, PDM, uv's older ``dev-dependencies``) are
reported as not analyzed. Dependencies a build backend computes at build time
(``dynamic``) cannot be known without running project code, so they are
reported rather than guessed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.dependency import DeclaredRequirement
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ParseStatus
from dva.ecosystems.python.names import canonical
from dva.ecosystems.python.requirement import RequirementSyntaxError, parse_requirement
from dva.ecosystems.python.tomlfile import load_toml
from dva.ecosystems.text import preview

_TOOL_TABLES = {
    ("poetry", "dependencies"): "Poetry dependencies ([tool.poetry.dependencies])",
    ("poetry", "group"): "Poetry dependency groups ([tool.poetry.group])",
    ("poetry", "dev-dependencies"): "Poetry dev dependencies ([tool.poetry.dev-dependencies])",
    ("pdm", "dev-dependencies"): "PDM dev dependencies ([tool.pdm.dev-dependencies])",
    ("uv", "dev-dependencies"): "uv dev dependencies ([tool.uv.dev-dependencies])",
}


@dataclass
class _State:
    path: str
    project_name: str | None = None
    requirements: list[DeclaredRequirement] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    incomplete: bool = False

    def warn(self, code: str, message: str) -> None:
        self.incomplete = True
        self.diagnostics.append(Diagnostic(code, DiagnosticLevel.WARNING, message, self.path))

    def add(self, text: object, where: str, groups: tuple[str, ...]) -> None:
        if not isinstance(text, str):
            self.warn("python.pyproject.invalid_entry", f"{where}: entry is not a string")
            return
        try:
            requirement = parse_requirement(text, groups=groups, project_name=self.project_name)
        except RequirementSyntaxError as error:
            self.warn("python.pyproject.invalid_requirement", f"{where}: {error}")
            return
        self.requirements.append(requirement)


def parse_pyproject(context: ParseContext) -> AdapterResult:
    document = load_toml(context, "python.pyproject.invalid_toml")
    if isinstance(document, AdapterResult):
        return document

    state = _State(path=context.path)
    project = document.get("project")
    if project is not None and not isinstance(project, dict):
        state.warn("python.pyproject.invalid_field", "[project] is not a table")
        project = None
    if project is not None:
        _read_project(state, project)
    if "dependency-groups" in document:
        _read_dependency_groups(state, document["dependency-groups"])
    _report_tool_tables(state, document.get("tool"))

    return AdapterResult(
        status=ParseStatus.PARTIAL if state.incomplete else ParseStatus.PARSED,
        requirements=tuple(state.requirements),
        diagnostics=tuple(state.diagnostics),
    )


def _read_project(state: _State, project: Mapping[str, Any]) -> None:
    name = project.get("name")
    if isinstance(name, str) and name.strip():
        state.project_name = name

    dynamic = project.get("dynamic", [])
    if isinstance(dynamic, list):
        for key in ("dependencies", "optional-dependencies"):
            if key in dynamic:
                state.warn(
                    "python.pyproject.dynamic",
                    f"[project] {key} are computed by the build backend at build time; "
                    "DVA does not run it, so they are not analyzed",
                )

    dependencies = project.get("dependencies")
    if dependencies is not None:
        if isinstance(dependencies, list):
            for index, entry in enumerate(dependencies):
                state.add(entry, f"project.dependencies[{index}]", ())
        else:
            state.warn("python.pyproject.invalid_field", "project.dependencies is not an array")

    optional = project.get("optional-dependencies")
    if optional is not None:
        if not isinstance(optional, dict):
            state.warn(
                "python.pyproject.invalid_field", "project.optional-dependencies is not a table"
            )
            return
        for extra, entries in optional.items():
            where = f"project.optional-dependencies.{preview(extra)}"
            if not isinstance(entries, list):
                state.warn("python.pyproject.invalid_field", f"{where} is not an array")
                continue
            label = f"optional:{canonical(extra)}"
            for index, entry in enumerate(entries):
                state.add(entry, f"{where}[{index}]", (label,))


def _read_dependency_groups(state: _State, groups: object) -> None:
    if not isinstance(groups, dict):
        state.warn("python.pyproject.invalid_field", "[dependency-groups] is not a table")
        return

    by_name: dict[str, tuple[str, list[object]]] = {}
    for raw_name, entries in groups.items():
        name = canonical(raw_name)
        if name in by_name:
            state.warn(
                "python.pyproject.duplicate_group",
                f"dependency group {preview(raw_name)!r} is defined twice (names are normalized)",
            )
            continue
        if not isinstance(entries, list):
            state.warn(
                "python.pyproject.invalid_field",
                f"dependency-groups.{preview(raw_name)} is not an array",
            )
            continue
        by_name[name] = (raw_name, entries)

    includes = {name: _includes(state, name, by_name) for name in by_name}
    reach = {name: _reachable(name, includes) for name in by_name}
    for name, (raw_name, _) in by_name.items():
        if any(name in reach[included] for included in includes[name]):
            state.warn(
                "python.pyproject.group_cycle",
                f"dependency group {preview(raw_name)!r} includes itself through include-group",
            )

    for name, (raw_name, entries) in by_name.items():
        labels = tuple(sorted(f"group:{root}" for root in by_name if name in reach[root]))
        for index, entry in enumerate(entries):
            if isinstance(entry, dict):
                continue
            state.add(entry, f"dependency-groups.{preview(raw_name)}[{index}]", labels)


def _includes(
    state: _State, name: str, by_name: Mapping[str, tuple[str, list[object]]]
) -> list[str]:
    """Normalized names of the groups ``name`` includes directly; bad entries are reported."""
    raw_name, entries = by_name[name]
    found: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        where = f"dependency-groups.{preview(raw_name)}[{index}]"
        target = entry.get("include-group")
        if set(entry) != {"include-group"} or not isinstance(target, str):
            state.warn(
                "python.pyproject.invalid_entry",
                f'{where}: only {{include-group = "..."}} tables are allowed',
            )
        elif canonical(target) not in by_name:
            state.warn(
                "python.pyproject.unknown_group",
                f"{where}: includes group {preview(target)!r}, which does not exist",
            )
        else:
            found.append(canonical(target))
    return found


def _reachable(root: str, includes: Mapping[str, list[str]]) -> set[str]:
    """Groups whose requirements ``root`` pulls in (``root`` itself included)."""
    reached = {root}
    pending = [root]
    while pending:
        for included in includes[pending.pop()]:
            if included not in reached:
                reached.add(included)
                pending.append(included)
    return reached


def _report_tool_tables(state: _State, tool: object) -> None:
    if not isinstance(tool, dict):
        return
    for (tool_name, key), description in _TOOL_TABLES.items():
        section = tool.get(tool_name)
        if isinstance(section, dict) and key in section:
            state.warn(
                "python.pyproject.tool_table",
                f"{description} use a tool-specific format that DVA does not read yet",
            )
