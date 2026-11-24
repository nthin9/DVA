from __future__ import annotations

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.dependency import DeclaredRequirement, SourceKind
from dva.domain.manifest import ParseStatus
from dva.ecosystems.python.adapter import PYPROJECT_TOML, PythonAdapter
from tests.support.readers import MemoryReader


def parse(text: str | bytes) -> AdapterResult:
    content = text.encode("utf-8") if isinstance(text, str) else text
    context = ParseContext("pyproject.toml", content, PYPROJECT_TOML, MemoryReader())
    return PythonAdapter().parse(context)


def codes(result: AdapterResult) -> set[str]:
    return {d.code for d in result.diagnostics}


def by_name(result: AdapterResult) -> dict[str, list[DeclaredRequirement]]:
    found: dict[str, list[DeclaredRequirement]] = {}
    for requirement in result.requirements:
        found.setdefault(requirement.identity.name, []).append(requirement)
    return found


def test_project_dependencies_and_optional_dependencies() -> None:
    result = parse(
        """
[project]
name = "demo"
dependencies = ["requests>=2", 'tomli; python_version < "3.11"']

[project.optional-dependencies]
Socks = ["PySocks"]
all = ["demo[socks]"]
"""
    )
    assert result.status is ParseStatus.PARSED
    found = by_name(result)
    assert found["requests"][0].groups == ()
    assert found["requests"][0].constraint == ">=2"
    assert found["tomli"][0].markers == 'python_version < "3.11"'
    assert found["pysocks"][0].groups == ("optional:socks",)
    own = found["demo"][0]
    assert own.source is SourceKind.WORKSPACE
    assert own.extras == ("socks",)
    assert all(r.line is None for r in result.requirements)


def test_dependency_groups_follow_includes() -> None:
    result = parse(
        """
[dependency-groups]
test = ["pytest>=8"]
Lint = ["ruff"]
dev = [{include-group = "test"}, {include-group = "lint"}, "ipython"]
"""
    )
    assert result.status is ParseStatus.PARSED
    found = by_name(result)
    assert found["pytest"][0].groups == ("group:dev", "group:test")
    assert found["ruff"][0].groups == ("group:dev", "group:lint")
    assert found["ipython"][0].groups == ("group:dev",)


def test_dependency_group_problems_are_reported() -> None:
    result = parse(
        """
[dependency-groups]
a = [{include-group = "b"}, {include-group = "missing"}, {other = 1}, 5, "ok"]
b = [{include-group = "a"}, "x"]
"""
    )
    assert result.status is ParseStatus.PARTIAL
    assert {
        "python.pyproject.group_cycle",
        "python.pyproject.unknown_group",
        "python.pyproject.invalid_entry",
    } <= codes(result)
    assert by_name(result)["x"][0].groups == ("group:a", "group:b")


def test_duplicate_normalized_group_names() -> None:
    result = parse('[dependency-groups]\n"Dev_Tools" = ["a"]\n"dev.tools" = ["b"]\n')
    assert result.status is ParseStatus.PARTIAL
    assert "python.pyproject.duplicate_group" in codes(result)


def test_dynamic_dependencies_are_reported() -> None:
    result = parse('[project]\nname = "x"\ndynamic = ["dependencies", "version"]\n')
    assert result.status is ParseStatus.PARTIAL
    assert "python.pyproject.dynamic" in codes(result)
    assert not result.requirements


def test_tool_specific_tables_are_reported_not_read() -> None:
    result = parse(
        """
[tool.poetry.dependencies]
python = "^3.12"
requests = "^2"

[tool.uv]
dev-dependencies = ["pytest"]
"""
    )
    assert result.status is ParseStatus.PARTIAL
    messages = [d.message for d in result.diagnostics if d.code == "python.pyproject.tool_table"]
    assert len(messages) == 2
    assert not result.requirements


def test_file_without_dependencies_is_parsed_and_empty() -> None:
    result = parse("[tool.ruff]\nline-length = 100\n")
    assert result.status is ParseStatus.PARSED
    assert not result.requirements
    assert not result.diagnostics


def test_wrong_types_and_bad_requirements() -> None:
    result = parse(
        """
[project]
name = "x"
dependencies = "requests"
optional-dependencies = {a = "nope", b = ["fine", "bad =="]}
"""
    )
    assert result.status is ParseStatus.PARTIAL
    assert [r.identity.name for r in result.requirements] == ["fine"]
    assert {"python.pyproject.invalid_field", "python.pyproject.invalid_requirement"} <= codes(
        result
    )


def test_invalid_toml_and_encoding_fail() -> None:
    assert parse("[project\n").status is ParseStatus.FAILED
    assert "python.pyproject.invalid_toml" in codes(parse("[project\n"))
    assert parse(b"\xff").status is ParseStatus.FAILED


def test_deeply_nested_toml_fails_cleanly() -> None:
    result = parse("x = " + "[" * 50_000 + "]" * 50_000 + "\n")
    assert result.status is ParseStatus.FAILED
