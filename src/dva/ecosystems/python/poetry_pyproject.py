"""Poetry's own dependency tables in ``pyproject.toml``.

Reads ``[tool.poetry.dependencies]``, ``[tool.poetry.group.<name>.dependencies]``
and the older ``[tool.poetry.dev-dependencies]``. Poetry writes version
constraints in its own syntax, so they are translated to the standard form
(PEP 440) the rest of DVA understands:

* ``^1.2.3`` means ``>=1.2.3,<2.0.0`` (the first non-zero part may not change);
* ``~1.2.3`` means ``>=1.2.3,<1.3.0``;
* a bare version, ``1.2.3``, means exactly that version: ``==1.2.3``;
* ``*`` means any version; ``1.2.*`` and comparisons (``>=1,<2``) are kept.

A constraint Poetry allows but the standard form can't express (``||``
alternatives) is kept as written and reported, so it is never mistaken for a
pin. Dependencies from git, a path or a URL are marked as such, with any
credentials removed from the URL. When a project's primary package source
isn't PyPI, or a dependency names a source that isn't, the dependency is
marked as coming from another registry, whose package names may be private.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version

from dva.domain.dependency import DeclaredRequirement, SourceKind
from dva.ecosystems.python.names import canonical, identity, is_public_index
from dva.ecosystems.python.requirement import RequirementSyntaxError, parse_requirement
from dva.ecosystems.text import preview, redact_url

type Warn = Callable[[str, str], None]

_OPERATOR = re.compile(r"^(===|==|!=|<=|>=|<|>|~=)\s*(\S+)$")
#: Source priorities that make Poetry stop using PyPI for other packages.
_PRIMARY_PRIORITIES = {"primary", "default"}


class ConstraintError(ValueError):
    """A Poetry constraint that has no standard equivalent."""


def _release(text: str) -> list[int]:
    try:
        version = Version(text)
    except InvalidVersion:
        raise ConstraintError(f"not a version: {text!r}") from None
    if version.is_prerelease or version.is_postrelease or version.is_devrelease:
        raise ConstraintError(f"pre- or post-release in a range: {text!r}")
    return list(version.release)


def _join(parts: list[int]) -> str:
    return ".".join(str(part) for part in parts)


def _caret(text: str) -> str:
    parts = _release(text)
    index = next((i for i, part in enumerate(parts) if part != 0), len(parts) - 1)
    upper = parts[: index + 1]
    upper[-1] += 1
    upper += [0] * (len(parts) - len(upper))
    return f">={text},<{_join(upper)}"


def _tilde(text: str) -> str:
    parts = _release(text)
    keep = 1 if len(parts) == 1 else 2
    upper = parts[:keep]
    upper[-1] += 1
    upper += [0] * (len(parts) - len(upper))
    return f">={text},<{_join(upper)}"


def to_pep440(constraint: str) -> str | None:
    """The standard form of a Poetry version constraint; ``None`` means any version."""
    text = constraint.strip()
    if text in ("", "*"):
        return None
    if "||" in text or "|" in text:
        raise ConstraintError("alternatives ('||') have no standard form")
    clauses = []
    for raw in re.split(r"\s*,\s*|\s+(?=[<>=!~^])", text):
        clause = raw.strip()
        if not clause:
            continue
        if clause.startswith("^"):
            clauses.append(_caret(clause[1:].strip()))
        elif clause.startswith("~") and not clause.startswith("~="):
            clauses.append(_tilde(clause[1:].strip()))
        elif match := _OPERATOR.match(clause):
            clauses.append(f"{match.group(1)}{match.group(2)}")
        elif clause.endswith(".*"):
            clauses.append(f"=={clause}")
        else:
            _release_any(clause)
            clauses.append(f"=={clause}")
    return ",".join(clauses) or None


def _release_any(text: str) -> None:
    """Accept any valid version, pre-releases included, as an exact pin."""
    try:
        Version(text)
    except InvalidVersion:
        raise ConstraintError(f"not a version: {text!r}") from None


def _python_markers(constraint: str) -> str:
    """``python = "^3.9"`` as an environment marker."""
    standard = to_pep440(constraint)
    if standard is None:
        return ""
    parts = []
    for clause in standard.split(","):
        match = re.match(r"^(===|==|!=|<=|>=|<|>|~=)(.+)$", clause)
        if match is None:
            raise ConstraintError(f"python constraint {constraint!r}")
        operator, version = match.groups()
        parts.append(f'python_version {operator} "{version}"')
    return " and ".join(parts)


@dataclass(frozen=True, slots=True)
class _Sources:
    """The package sources a Poetry project declares."""

    private_names: frozenset[str]
    private_primary: bool


def _sources(poetry: Mapping[str, Any]) -> _Sources:
    private: set[str] = set()
    primary = False
    raw = poetry.get("source")
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        name, url = entry.get("name"), entry.get("url")
        if not isinstance(name, str):
            continue
        public = isinstance(url, str) and is_public_index(url)
        if not public:
            private.add(name.lower())
            priority = entry.get("priority")
            if priority is None:
                # Before priorities existed, ``default = true`` replaced PyPI,
                # and a source without either was used alongside it.
                priority = "default" if entry.get("default") is True else "primary"
                if entry.get("secondary") is True:
                    priority = "secondary"
            if isinstance(priority, str) and priority.lower() in _PRIMARY_PRIORITIES:
                primary = True
    return _Sources(frozenset(private), primary)


def read_poetry(
    poetry: Mapping[str, Any],
    *,
    skip: frozenset[str],
    project_name: str | None,
    warn: Warn,
) -> list[DeclaredRequirement]:
    """Requirements from the ``[tool.poetry]`` table.

    ``skip`` holds normalized names already declared in ``[project]``; Poetry 2
    uses ``tool.poetry.dependencies`` only to add details to those.
    """
    sources = _sources(poetry)
    extras = _extras(poetry.get("extras"))
    found: list[DeclaredRequirement] = []

    def table(value: object, groups: tuple[str, ...], where: str) -> None:
        if value is None:
            return
        if not isinstance(value, dict):
            warn("python.pyproject.invalid_field", f"{where} is not a table")
            return
        for name, spec in value.items():
            if not isinstance(name, str) or canonical(name) == "python":
                continue
            if canonical(name) in skip and not groups:
                continue
            entries = spec if isinstance(spec, list) else [spec]
            for entry in entries:
                requirement = _requirement(
                    name,
                    entry,
                    groups,
                    extras,
                    sources,
                    project_name,
                    f"{where}.{preview(name)}",
                    warn,
                )
                if requirement is not None:
                    found.append(requirement)

    table(poetry.get("dependencies"), (), "tool.poetry.dependencies")
    table(poetry.get("dev-dependencies"), ("group:dev",), "tool.poetry.dev-dependencies")
    groups = poetry.get("group")
    if isinstance(groups, dict):
        for group, body in groups.items():
            label = f"group:{canonical(str(group))}"
            where = f"tool.poetry.group.{preview(str(group))}.dependencies"
            if isinstance(body, dict):
                table(body.get("dependencies"), (label,), where)
            else:
                warn(
                    "python.pyproject.invalid_field",
                    f"tool.poetry.group.{preview(str(group))} is not a table",
                )
    elif groups is not None:
        warn("python.pyproject.invalid_field", "tool.poetry.group is not a table")
    return found


def mark_private_sources(
    requirements: list[DeclaredRequirement], poetry: Mapping[str, Any]
) -> list[DeclaredRequirement]:
    """Registry requirements of a project whose primary Poetry source isn't
    PyPI come from that other registry."""
    if not _sources(poetry).private_primary:
        return requirements
    return [
        DeclaredRequirement(
            identity(r.identity.name, from_registry=False),
            constraint=r.constraint,
            markers=r.markers,
            groups=r.groups,
            line=r.line,
            source=SourceKind.OTHER_REGISTRY,
            extras=r.extras,
        )
        if r.source is SourceKind.REGISTRY
        else r
        for r in requirements
    ]


def _extras(value: object) -> dict[str, list[str]]:
    """Normalized dependency name -> the extras that install it."""
    by_name: dict[str, list[str]] = {}
    if isinstance(value, dict):
        for extra, names in value.items():
            for name in names if isinstance(names, list) else []:
                if isinstance(name, str):
                    by_name.setdefault(canonical(name), []).append(canonical(str(extra)))
    return by_name


def _requirement(
    name: str,
    spec: object,
    groups: tuple[str, ...],
    extras: Mapping[str, list[str]],
    sources: _Sources,
    project_name: str | None,
    where: str,
    warn: Warn,
) -> DeclaredRequirement | None:
    if isinstance(spec, str):
        spec = {"version": spec}
    if not isinstance(spec, dict):
        warn("python.pyproject.invalid_entry", f"{where}: not a version or a table")
        return None

    labels = list(groups)
    if spec.get("optional") is True:
        labels += [f"optional:{extra}" for extra in extras.get(canonical(name), [])] or ["optional"]
    labels = list(dict.fromkeys(labels))

    for key, kind in (("git", SourceKind.GIT), ("path", SourceKind.PATH), ("url", SourceKind.URL)):
        location = spec.get(key)
        if isinstance(location, str):
            return DeclaredRequirement(
                identity(name, from_registry=False),
                constraint=redact_url(location) if key != "path" else None,
                groups=tuple(labels),
                source=kind,
            )

    markers = []
    try:
        if isinstance(spec.get("python"), str):
            python = _python_markers(spec["python"])
            if python:
                markers.append(python)
        constraint = to_pep440(spec["version"]) if isinstance(spec.get("version"), str) else None
    except ConstraintError as error:
        warn(
            "python.pyproject.poetry_constraint",
            f"{where}: {error}; the requirement is kept without a usable version",
        )
        constraint = None
    if isinstance(spec.get("markers"), str) and spec["markers"].strip():
        markers.append(spec["markers"].strip())
    if isinstance(spec.get("platform"), str) and spec["platform"].strip():
        markers.append(f'sys_platform == "{spec["platform"].strip()}"')

    extra_list = spec.get("extras")
    extra_text = ""
    if isinstance(extra_list, list) and all(isinstance(e, str) for e in extra_list) and extra_list:
        extra_text = f"[{','.join(extra_list)}]"
    marker_text = " and ".join(f"({m})" if " or " in m else m for m in markers)
    text = f"{name}{extra_text}{constraint or ''}" + (f"; {marker_text}" if marker_text else "")
    try:
        requirement = parse_requirement(text, groups=tuple(labels), project_name=project_name)
    except RequirementSyntaxError as error:
        warn("python.pyproject.invalid_requirement", f"{where}: {error}")
        return None

    source = spec.get("source")
    private = (isinstance(source, str) and source.lower() in sources.private_names) or (
        not isinstance(source, str) and sources.private_primary
    )
    if private and requirement.source is SourceKind.REGISTRY:
        return DeclaredRequirement(
            identity(name, from_registry=False),
            constraint=requirement.constraint,
            markers=requirement.markers,
            groups=requirement.groups,
            source=SourceKind.OTHER_REGISTRY,
            extras=requirement.extras,
        )
    return requirement
