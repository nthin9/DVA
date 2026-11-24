"""Scanning local Python projects end to end with the built-in adapters (offline)."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from dva.application.analyze import analyze_project
from dva.domain.dependency import SourceKind
from dva.domain.manifest import ManifestAnalysis, ParseStatus
from dva.domain.scan import CompletionState
from dva.domain.serialization import dumps_scan
from dva.ecosystems.registry import default_registry

FIXTURES = Path(__file__).parents[1] / "fixtures" / "python"
BASIC = FIXTURES / "basic_project"
POETRY = FIXTURES / "poetry_project"


def scan(tmp_path: Path, fixture: Path = BASIC) -> dict[str, ManifestAnalysis]:
    root = tmp_path / "project"
    shutil.copytree(fixture, root)
    result = analyze_project(root, default_registry())
    assert result.completion is CompletionState.PARTIAL
    assert not (root / "SETUP_PY_WAS_EXECUTED").exists()
    return {m.path: m for m in result.manifests}


def test_every_python_file_is_accounted_for(tmp_path: Path) -> None:
    manifests = scan(tmp_path)
    assert {path: m.status for path, m in manifests.items()} == {
        "pyproject.toml": ParseStatus.PARSED,
        "requirements.txt": ParseStatus.PARSED,
        "requirements-dev.txt": ParseStatus.PARTIAL,
        "setup.py": ParseStatus.UNSUPPORTED,
        "uv.lock": ParseStatus.PARSED,
    }


def test_pyproject_requirements(tmp_path: Path) -> None:
    pyproject = scan(tmp_path)["pyproject.toml"]
    found = {(r.identity.name, r.constraint, r.groups) for r in pyproject.requirements}
    assert found == {
        ("requests", ">=2.31,<3", ()),
        ("tomli", ">=2", ()),
        ("pysocks", ">=1.7", ("optional:socks",)),
        ("pytest", ">=8", ("group:dev", "group:test")),
        ("ruff", None, ("group:dev",)),
    }


def test_requirements_includes_are_merged(tmp_path: Path) -> None:
    dev = scan(tmp_path)["requirements-dev.txt"]
    assert [r.identity.name for r in dev.requirements] == ["requests", "idna", "pytest"]
    assert {d.code for d in dev.diagnostics} >= {
        "python.requirements.included",
        "python.requirements.editable",
    }


def test_uv_lock_graph(tmp_path: Path) -> None:
    lock = scan(tmp_path)["uv.lock"]
    assert lock.format_version == "1"
    assert not lock.diagnostics
    packages = {p.node_id: p for p in lock.packages}
    assert "basic-project@1.0" not in packages
    assert len(packages) == 13
    assert all(p.source is SourceKind.REGISTRY for p in packages.values())
    assert packages["requests@2.32.3"].identity.purl == "pkg:pypi/requests"

    direct = {(e.child_id, e.markers, e.groups) for e in lock.edges if e.is_direct}
    assert direct == {
        ("requests@2.32.3", None, ()),
        ("tomli@2.2.1", "python_full_version < '3.11'", ()),
        ("pysocks@1.7.1", None, ("optional:socks",)),
        ("pytest@8.3.4", None, ("group:dev", "group:test")),
        ("ruff@0.8.4", None, ("group:dev",)),
    }
    transitive = {(e.parent_id, e.child_id) for e in lock.edges if not e.is_direct}
    assert ("requests@2.32.3", "urllib3@2.2.3") in transitive
    assert ("pytest@8.3.4", "colorama@0.4.6") in transitive

    assert packages["urllib3@2.2.3"].groups == ()
    assert packages["tomli@2.2.1"].groups == ()
    assert packages["pysocks@1.7.1"].groups == ("optional:socks",)
    assert packages["pluggy@1.5.0"].groups == ("group:dev", "group:test")
    assert packages["ruff@0.8.4"].groups == ("group:dev",)


def test_poetry_lock_graph(tmp_path: Path) -> None:
    manifests = scan(tmp_path, POETRY)
    assert manifests["pyproject.toml"].status is ParseStatus.PARTIAL
    lock = manifests["poetry.lock"]
    assert lock.status is ParseStatus.PARSED
    assert lock.format_version == "2.1"
    assert not any(e.is_direct for e in lock.edges)
    assert "python.poetry_lock.no_direct_dependencies" in {d.code for d in lock.diagnostics}

    packages = {p.node_id: p for p in lock.packages}
    assert packages["requests@2.32.3"].groups == ("group:main",)
    assert packages["pytest@8.3.4"].groups == ("group:dev",)
    edges = {(e.parent_id, e.child_id): e for e in lock.edges}
    socks = edges[("requests@2.32.3", "pysocks@1.7.1")]
    assert socks.groups == ("optional:socks",)
    assert socks.constraint == ">=1.5.6,!=1.5.7"
    assert socks.markers == 'extra == "socks"'
    assert edges[("pytest@8.3.4", "colorama@0.4.6")].markers == 'sys_platform == "win32"'


def test_scan_output_is_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "project"
    shutil.copytree(BASIC, root)

    def stamp() -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC)

    first = dumps_scan(analyze_project(root, default_registry(), clock=stamp))
    second = dumps_scan(analyze_project(root, default_registry(), clock=stamp))
    assert first == second
    assert "sha256" not in first
    assert "files.pythonhosted.org" not in first
