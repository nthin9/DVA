"""Scanning a local Python project end to end with the built-in adapters (offline)."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from dva.application.analyze import analyze_project
from dva.domain.manifest import ManifestAnalysis, ParseStatus
from dva.domain.scan import CompletionState
from dva.domain.serialization import dumps_scan
from dva.ecosystems.registry import default_registry

FIXTURE = Path(__file__).parents[1] / "fixtures" / "python" / "basic_project"


def scan(tmp_path: Path) -> dict[str, ManifestAnalysis]:
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root)
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
        "uv.lock": ParseStatus.UNSUPPORTED,
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


def test_scan_output_is_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root)

    def stamp() -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC)

    first = dumps_scan(analyze_project(root, default_registry(), clock=stamp))
    second = dumps_scan(analyze_project(root, default_registry(), clock=stamp))
    assert first == second
    assert "sha256" not in first
