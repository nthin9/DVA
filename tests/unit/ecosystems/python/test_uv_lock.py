from __future__ import annotations

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.dependency import SourceKind
from dva.domain.manifest import ManifestAnalysis, ParseStatus
from dva.ecosystems.python.adapter import UV_LOCK, PythonAdapter
from tests.support.readers import MemoryReader

PROJECT = """
version = 1
revision = 3

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "lib" }]
"""


def parse(text: str) -> AdapterResult:
    context = ParseContext("uv.lock", text.encode("utf-8"), UV_LOCK, MemoryReader())
    result = PythonAdapter().parse(context)
    ManifestAnalysis(
        path="uv.lock",
        adapter_id="python",
        ecosystem="pypi",
        kind=UV_LOCK.kind,
        format_name=UV_LOCK.format_name,
        status=result.status,
        packages=result.packages,
        edges=result.edges,
        diagnostics=result.diagnostics,
    )
    return result


def codes(result: AdapterResult) -> set[str]:
    return {d.code for d in result.diagnostics}


def package(name: str, version: str, source: str, deps: str = "") -> str:
    lines = [
        "[[package]]",
        f'name = "{name}"',
        f'version = "{version}"',
        f"source = {source}",
    ]
    if deps:
        lines.append(f"dependencies = [{deps}]")
    return "\n" + "\n".join(lines) + "\n"


REGISTRY = '{ registry = "https://pypi.org/simple" }'


def test_unsupported_and_missing_versions() -> None:
    newer = parse("version = 2\n")
    assert newer.status is ParseStatus.UNSUPPORTED
    assert newer.format_version == "2"
    assert "python.uv_lock.unsupported_version" in codes(newer)
    missing = parse("[[package]]\nname = 'x'\n")
    assert missing.status is ParseStatus.FAILED
    assert "python.uv_lock.no_version" in codes(missing)
    assert parse("version = true\n").status is ParseStatus.FAILED


def test_same_name_at_two_versions_is_picked_by_version() -> None:
    text = (
        PROJECT.replace('[{ name = "lib" }]', '[{ name = "lib", version = "2.0" }]')
        + package("lib", "1.0", REGISTRY)
        + package("lib", "2.0", REGISTRY)
        + package("user", "1.0", REGISTRY, '{ name = "lib", version = "1.0" }')
    )
    result = parse(text)
    assert result.status is ParseStatus.PARSED
    edges = {(e.parent_id, e.child_id) for e in result.edges}
    assert (None, "lib@2.0") in edges
    assert ("user@1.0", "lib@1.0") in edges
    assert "python.uv_lock.unreachable" in codes(result)


def test_ambiguous_and_missing_dependencies_are_reported() -> None:
    text = (
        PROJECT.replace('[{ name = "lib" }]', '[{ name = "lib" }, { name = "ghost" }]')
        + package("lib", "1.0", REGISTRY)
        + package("lib", "2.0", REGISTRY)
    )
    result = parse(text)
    assert result.status is ParseStatus.PARTIAL
    unresolved = [d.message for d in result.diagnostics if d.code.endswith("unresolved_dependency")]
    assert len(unresolved) == 2
    assert not result.edges


def test_sources_are_mapped_and_only_registry_packages_get_a_purl() -> None:
    text = (
        PROJECT.replace('[{ name = "lib" }]', '[{ name = "lib" }, { name = "local" }]')
        + package("lib", "1.0", '{ git = "https://user:token@example.com/lib.git?rev=v1#abc" }')
        + package("local", "0.1", '{ path = "../local" }')
    )
    result = parse(text)
    packages = {p.identity.name: p for p in result.packages}
    assert packages["lib"].source is SourceKind.GIT
    assert packages["lib"].identity.purl is None
    assert packages["local"].source is SourceKind.PATH
    assert "token" not in repr(result)


def test_workspace_members_are_roots_when_there_is_no_project_at_the_root() -> None:
    text = (
        '\nversion = 1\n\n[manifest]\nmembers = ["alpha", "beta"]\n'
        + package("alpha", "0.1", '{ editable = "packages/alpha" }', '{ name = "beta" }')
        + package("beta", "0.1", '{ editable = "packages/beta" }', '{ name = "lib" }')
        + package("lib", "1.0", REGISTRY)
    )
    result = parse(text)
    assert result.status is ParseStatus.PARSED
    assert [p.node_id for p in result.packages] == ["lib@1.0"]
    assert [(e.parent_id, e.child_id) for e in result.edges] == [(None, "lib@1.0")]


def test_no_project_entry_is_reported() -> None:
    result = parse("version = 1\n" + package("lib", "1.0", REGISTRY))
    assert result.status is ParseStatus.PARTIAL
    assert "python.uv_lock.no_project" in codes(result)


def test_cycles_and_self_references_do_not_break_the_graph() -> None:
    text = (
        PROJECT
        + package("lib", "1.0", REGISTRY, '{ name = "other" }, { name = "lib" }')
        + package("other", "1.0", REGISTRY, '{ name = "lib" }')
    )
    result = parse(text)
    assert result.status is ParseStatus.PARSED
    edges = {(e.parent_id, e.child_id) for e in result.edges}
    assert edges == {(None, "lib@1.0"), ("lib@1.0", "other@1.0"), ("other@1.0", "lib@1.0")}


def test_malformed_entries_are_reported_and_skipped() -> None:
    text = (
        PROJECT
        + "\n[[package]]\nversion = '1'\n"
        + package("lib", "1.0", REGISTRY, '"not-a-table"')
        + "\n[[package]]\nname = 'noversion'\nsource = { registry = 'x' }\n"
    )
    result = parse(text)
    assert result.status is ParseStatus.PARTIAL
    assert {"python.uv_lock.invalid_entry", "python.uv_lock.missing_version"} <= codes(result)
    assert [p.node_id for p in result.packages] == ["lib@1.0"]


def test_wrong_table_types() -> None:
    assert parse("version = 1\npackage = 3\n").status is ParseStatus.FAILED
    text = (
        PROJECT + "\n[package.optional-dependencies]\nx = 'nope'\n" + package("lib", "1", REGISTRY)
    )
    result = parse(text)
    assert result.status is ParseStatus.PARTIAL
    assert "python.uv_lock.invalid_field" in codes(result)


def test_packages_from_another_index_are_marked() -> None:
    text = (
        PROJECT.replace('[{ name = "lib" }]', '[{ name = "lib" }, { name = "corp" }]')
        + package("lib", "1.0", REGISTRY)
        + package("corp", "2.0", '{ registry = "https://pkgs.corp.example/simple" }')
    )
    packages = {p.identity.name: p for p in parse(text).packages}
    assert packages["lib"].source is SourceKind.REGISTRY
    assert packages["corp"].source is SourceKind.OTHER_REGISTRY
    assert packages["corp"].identity.purl is None
