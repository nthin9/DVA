from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from dva.discovery.limits import ScanLimits
from dva.discovery.walker import discover
from dva.ecosystems.registry import AdapterRegistry
from tests.support.example_adapter import ExampleAdapter


def make(root: Path, *relative: str) -> None:
    for item in relative:
        path = root / item
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("alpha==1.0\n", encoding="utf-8")


def registry() -> AdapterRegistry:
    return AdapterRegistry([ExampleAdapter()])


def codes(result: object) -> list[str]:
    return [d.code for d in result.diagnostics]  # type: ignore[attr-defined]


def test_finds_declared_files_with_relative_posix_paths(tmp_path: Path) -> None:
    make(tmp_path, "example-deps.txt", "a/b/example-deps.txt", "a/example.lock", "a/other.txt")
    result = discover(tmp_path, registry(), ScanLimits())
    assert sorted(f.path for f in result.files) == [
        "a/b/example-deps.txt",
        "a/example.lock",
        "example-deps.txt",
    ]
    assert result.diagnostics == ()


def test_pattern_matching_is_case_sensitive(tmp_path: Path) -> None:
    make(tmp_path, "Example-Deps.TXT")
    assert discover(tmp_path, registry(), ScanLimits()).files == ()


@pytest.mark.parametrize(
    "folder", ["node_modules", "Node_Modules", ".git", ".venv", "venv", "__pycache__"]
)
def test_dependency_and_vcs_folders_are_skipped(tmp_path: Path, folder: str) -> None:
    make(tmp_path, f"{folder}/pkg/example-deps.txt")
    result = discover(tmp_path, registry(), ScanLimits())
    assert result.files == ()
    assert result.diagnostics == ()


def test_depth_limit_reports_unsearched_folder(tmp_path: Path) -> None:
    make(tmp_path, "l1/example-deps.txt", "l1/l2/example-deps.txt")
    result = discover(tmp_path, registry(), ScanLimits(max_depth=1))
    assert [f.path for f in result.files] == ["l1/example-deps.txt"]
    assert codes(result) == ["discovery.depth_limit"]
    assert result.diagnostics[0].path == "l1/l2"


def test_entry_limit_stops_and_reports(tmp_path: Path) -> None:
    make(tmp_path, *(f"d{i}/example-deps.txt" for i in range(5)))
    result = discover(tmp_path, registry(), ScanLimits(max_entries=3))
    assert codes(result) == ["discovery.entry_limit"]
    assert len(result.files) < 5


def test_manifest_limit_stops_and_reports(tmp_path: Path) -> None:
    make(tmp_path, *(f"d{i}/example-deps.txt" for i in range(5)))
    result = discover(tmp_path, registry(), ScanLimits(max_manifests=2))
    assert len(result.files) == 2
    assert codes(result) == ["discovery.manifest_limit"]


def test_file_claimed_by_two_adapters_is_skipped_with_diagnostic(tmp_path: Path) -> None:
    make(tmp_path, "example-deps.txt")
    both = AdapterRegistry([ExampleAdapter(), ExampleAdapter("greedy", patterns=("*.txt",))])
    result = discover(tmp_path, both, ScanLimits())
    assert result.files == ()
    assert codes(result) == ["discovery.ambiguous_format"]
    assert "example, greedy" in result.diagnostics[0].message


def test_results_are_deterministic(tmp_path: Path) -> None:
    make(tmp_path, "b/example-deps.txt", "a/example-deps.txt", "c/example-deps.txt")
    first = discover(tmp_path, registry(), ScanLimits())
    second = discover(tmp_path, registry(), ScanLimits())
    assert [f.path for f in first.files] == [f.path for f in second.files]


def _symlink(link: Path, target: Path, *, directory: bool) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create symlinks here: {exc}")


def test_symlinked_directory_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    make(outside, "example-deps.txt")
    project = tmp_path / "project"
    project.mkdir()
    _symlink(project / "linked", outside, directory=True)
    result = discover(project, registry(), ScanLimits())
    assert result.files == ()
    assert codes(result) == ["discovery.link_skipped"]
    assert result.diagnostics[0].path == "linked"


def test_symlinked_manifest_is_not_read(tmp_path: Path) -> None:
    make(tmp_path, "outside/example-deps.txt")
    project = tmp_path / "project"
    project.mkdir()
    _symlink(project / "example-deps.txt", tmp_path / "outside/example-deps.txt", directory=False)
    result = discover(project, registry(), ScanLimits())
    assert result.files == ()
    assert codes(result) == ["discovery.link_skipped"]


@pytest.mark.skipif(sys.platform == "win32", reason="backslash is a separator on Windows")
def test_names_with_backslash_are_skipped_not_crashing(tmp_path: Path) -> None:
    (tmp_path / "odd\\name").mkdir()
    result = discover(tmp_path, registry(), ScanLimits())
    assert codes(result) == ["discovery.unsupported_name"]


def test_limits_must_be_positive() -> None:
    with pytest.raises(ValueError):
        ScanLimits(max_depth=0)
    with pytest.raises(ValueError):
        ScanLimits(max_file_bytes=True)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are Windows-only")
def test_windows_junction_is_not_followed(tmp_path: Path) -> None:
    if sys.platform == "win32":  # narrows the platform for type checkers
        import _winapi

        outside = tmp_path / "outside"
        make(outside, "example-deps.txt")
        project = tmp_path / "project"
        project.mkdir()
        _winapi.CreateJunction(str(outside), str(project / "junction"))
        result = discover(project, registry(), ScanLimits())
        assert result.files == ()
        assert codes(result) == ["discovery.link_skipped"]


def test_entry_limit_applies_within_one_large_directory(tmp_path: Path) -> None:
    for i in range(50):
        (tmp_path / f"f{i}.txt").write_text("x", encoding="utf-8")
    make(tmp_path, "example-deps.txt")
    result = discover(tmp_path, registry(), ScanLimits(max_entries=10))
    assert codes(result) == ["discovery.entry_limit"]


def test_environments_are_skipped_whatever_they_are_called(tmp_path: Path) -> None:
    from dva.application.analyze import analyze_project
    from dva.ecosystems.registry import default_registry

    for name, marker in (("env", "pyvenv.cfg"), ("py312", "pyvenv.cfg"), ("conda", "conda-meta")):
        folder = tmp_path / name
        folder.mkdir()
        (folder / marker).mkdir() if marker == "conda-meta" else (folder / marker).write_text("")
        (folder / "requirements.txt").write_text("x==1\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("y==1\n", encoding="utf-8")
    scan = analyze_project(tmp_path, default_registry())
    assert [m.path for m in scan.manifests] == ["requirements.txt"]
