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


def test_other_tool_specific_tables_are_reported_not_read() -> None:
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
    assert len(messages) == 1 and "uv" in messages[0]
    # Poetry's table is read; "python" is the interpreter, not a package.
    assert [(r.identity.name, r.constraint) for r in result.requirements] == [
        ("requests", ">=2,<3")
    ]


def test_poetry_tables_are_read() -> None:
    result = parse(
        """
[tool.poetry]
name = "app"

[tool.poetry.dependencies]
python = "^3.10"
exact = "1.2.3"
caret = "^0.2.3"
tilde = { version = "~1.4", extras = ["fast"], python = ">=3.11" }
star = "*"
optional-one = { version = "^1", optional = true }
from-git = { git = "https://user:token@example.com/x.git", branch = "main" }
local = { path = "../local", develop = true }
multi = [
    { version = "<2", python = "<3.11" },
    { version = ">=2", python = ">=3.11" },
]
odd = "1.0 || 2.0"
app = { path = ".", extras = ["x"] }

[tool.poetry.extras]
speed = ["optional-one"]

[tool.poetry.group.test.dependencies]
pytest = "^8.3"

[tool.poetry.dev-dependencies]
black = "24.1.0"
"""
    )
    found = {
        (r.identity.name, r.constraint, r.markers, r.groups, r.source.value, r.extras)
        for r in result.requirements
    }
    assert ("exact", "==1.2.3", None, (), "registry", ()) in found
    assert ("caret", ">=0.2.3,<0.3.0", None, (), "registry", ()) in found
    assert (
        "tilde",
        ">=1.4,<1.5",
        'python_version >= "3.11"',
        (),
        "registry",
        ("fast",),
    ) in found
    assert ("star", None, None, (), "registry", ()) in found
    assert ("optional-one", ">=1,<2", None, ("optional:speed",), "registry", ()) in found
    assert ("pytest", ">=8.3,<9.0", None, ("group:test",), "registry", ()) in found
    assert ("black", "==24.1.0", None, ("group:dev",), "registry", ()) in found
    multi = sorted(r.markers or "" for r in result.requirements if r.identity.name == "multi")
    assert multi == ['python_version < "3.11"', 'python_version >= "3.11"']
    git = next(r for r in result.requirements if r.identity.name == "from-git")
    assert git.source.value == "git" and "token" not in (git.constraint or "")
    assert next(r for r in result.requirements if r.identity.name == "local").source.value == "path"
    # An alternative ("||") has no standard form: kept without a version, and reported.
    odd = next(r for r in result.requirements if r.identity.name == "odd")
    assert odd.constraint is None
    assert "python.pyproject.poetry_constraint" in {d.code for d in result.diagnostics}
    assert result.status is ParseStatus.PARTIAL
    assert "python" not in {r.identity.name for r in result.requirements}


def test_poetry_2_details_for_project_dependencies_are_not_repeated() -> None:
    result = parse(
        """
[project]
name = "app"
dependencies = ["requests>=2"]

[tool.poetry.dependencies]
requests = { source = "pypi" }
"""
    )
    assert [r.identity.name for r in result.requirements] == ["requests"]


def test_a_private_primary_poetry_source_marks_registry_packages() -> None:
    result = parse(
        """
[project]
name = "app"
dependencies = ["corp-lib==1.0"]

[tool.poetry.dependencies]
other = { version = "1.0", source = "pypi" }

[[tool.poetry.source]]
name = "corp"
url = "https://pkgs.corp.example/simple"
priority = "primary"
"""
    )
    sources = {r.identity.name: (r.source.value, r.identity.purl) for r in result.requirements}
    assert sources["corp-lib"] == ("other_registry", None)


def test_a_supplemental_private_source_only_marks_packages_that_name_it() -> None:
    result = parse(
        """
[tool.poetry.dependencies]
public = "1.0"
corp-lib = { version = "1.0", source = "corp" }

[[tool.poetry.source]]
name = "corp"
url = "https://pkgs.corp.example/simple"
priority = "supplemental"
"""
    )
    sources = {r.identity.name: r.source.value for r in result.requirements}
    assert sources == {"public": "registry", "corp-lib": "other_registry"}


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
