from __future__ import annotations

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.dependency import SourceKind
from dva.domain.manifest import ManifestAnalysis, ParseStatus
from dva.ecosystems.python.adapter import POETRY_LOCK, PythonAdapter
from tests.support.readers import MemoryReader

METADATA = '\n[metadata]\nlock-version = "2.0"\npython-versions = ">=3.12"\ncontent-hash = "x"\n'


def parse(text: str) -> AdapterResult:
    context = ParseContext("poetry.lock", text.encode("utf-8"), POETRY_LOCK, MemoryReader())
    result = PythonAdapter().parse(context)
    ManifestAnalysis(
        path="poetry.lock",
        adapter_id="python",
        ecosystem="pypi",
        kind=POETRY_LOCK.kind,
        format_name=POETRY_LOCK.format_name,
        status=result.status,
        packages=result.packages,
        edges=result.edges,
        diagnostics=result.diagnostics,
    )
    return result


def codes(result: AdapterResult) -> set[str]:
    return {d.code for d in result.diagnostics}


def package(name: str, version: str, extra: str = "") -> str:
    return f'\n[[package]]\nname = "{name}"\nversion = "{version}"\noptional = false\n{extra}\n'


def test_unsupported_and_missing_lock_versions() -> None:
    old = parse('[metadata]\nlock-version = "1.1"\n')
    assert old.status is ParseStatus.UNSUPPORTED
    assert old.format_version == "1.1"
    assert parse("[[package]]\nname = 'x'\n").status is ParseStatus.FAILED
    assert parse("[metadata]\nlock-version = 2\n").status is ParseStatus.FAILED


def test_lock_version_2_0_without_groups() -> None:
    text = package("a", "1.0", '[package.dependencies]\nB_lib = ">=1"') + package("b-lib", "1.5")
    result = parse(text + METADATA)
    assert result.status is ParseStatus.PARSED
    assert result.format_version == "2.0"
    assert all(p.groups == () for p in result.packages)
    assert [(e.parent_id, e.child_id, e.constraint) for e in result.edges] == [
        ("a@1.0", "b-lib@1.5", ">=1")
    ]


def test_multiple_locked_versions_are_picked_by_pep_440_range() -> None:
    text = (
        package(
            "a",
            "1.0",
            "[package.dependencies]\nb = [\n"
            '  {version = ">=2.0", markers = "os_name == \'nt\'"},\n'
            '  {version = "<2.0", markers = "os_name != \'nt\'"},\n]',
        )
        + package("b", "1.10")
        + package("b", "2.0")
    )
    result = parse(text + METADATA)
    assert result.status is ParseStatus.PARSED
    picked = {(e.child_id, e.markers) for e in result.edges}
    assert picked == {("b@2.0", "os_name == 'nt'"), ("b@1.10", "os_name != 'nt'")}


def test_unresolvable_dependencies_are_reported() -> None:
    text = (
        package("a", "1.0", '[package.dependencies]\nmissing = "*"\nb = "*"\nc = ">=9"')
        + package("b", "1.0")
        + package("b", "2.0")
        + package("c", "1.0")
        + package("c", "1.1")
    )
    result = parse(text + METADATA)
    assert result.status is ParseStatus.PARTIAL
    assert not result.edges
    unresolved = [d for d in result.diagnostics if d.code.endswith("unresolved_dependency")]
    assert len(unresolved) == 3


def test_sources_are_mapped() -> None:
    text = (
        package(
            "g",
            "1.0",
            '[package.source]\ntype = "git"\nurl = "https://u:secret@example.com/g.git"\n'
            'reference = "main"\nresolved_reference = "abc"',
        )
        + package("d", "1.0", '[package.source]\ntype = "directory"\nurl = "../d"')
        + package(
            "p",
            "1.0",
            '[package.source]\ntype = "legacy"\nurl = "https://private.example/simple"\n'
            'reference = "private"',
        )
        + package("w", "1.0", '[package.source]\ntype = "weird"\nurl = "x"')
    )
    result = parse(text + METADATA)
    sources = {p.identity.name: (p.source, p.identity.purl) for p in result.packages}
    assert sources == {
        "g": (SourceKind.GIT, None),
        "d": (SourceKind.PATH, None),
        # A private index: a real registry, but not PyPI, so no pkg:pypi URL.
        "p": (SourceKind.OTHER_REGISTRY, None),
        "w": (SourceKind.UNKNOWN, None),
    }
    assert "python.poetry_lock.unknown_source" in codes(result)
    assert "secret" not in repr(result)


def test_malformed_packages_are_skipped() -> None:
    text = "\n[[package]]\nversion = '1'\n" + package("x", "") + package("ok", "1.0")
    result = parse(text + METADATA)
    assert result.status is ParseStatus.PARTIAL
    assert [p.node_id for p in result.packages] == ["ok@1.0"]


def test_lock_version_2_1_keeps_per_package_markers() -> None:
    text = (
        package("a", "1.0", 'markers = "python_version < \\"3.13\\""')
        + package(
            "b",
            "1.0",
            'markers = { main = "sys_platform == \\"win32\\"", dev = "os_name == \\"nt\\"" }',
        )
        + package("c", "1.0")
    )
    result = parse(text + METADATA.replace('"2.0"', '"2.1"'))
    markers = {p.identity.name: p.markers for p in result.packages}
    assert markers == {
        "a": 'python_version < "3.13"',
        "b": '(sys_platform == "win32") or (os_name == "nt")',
        "c": None,
    }
