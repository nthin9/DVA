"""End-to-end tests of the analysis pipeline against local fixture trees (offline)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dva.application.analyze import InvalidProjectRootError, analyze_project
from dva.discovery.limits import ScanLimits
from dva.domain.manifest import ManifestAnalysis, ParseStatus
from dva.domain.scan import CompletionState
from dva.domain.serialization import dumps_scan
from dva.ecosystems.registry import AdapterRegistry, default_registry
from tests.support.example_adapter import ExampleAdapter, InvalidResultAdapter, RaisingAdapter


def fixed_clock() -> Iterator[datetime]:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    for tick in range(1_000):
        yield start + timedelta(seconds=tick)


def clock() -> datetime:
    return next(_TICKS)


_TICKS = fixed_clock()


def write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def by_path(manifests: tuple[ManifestAnalysis, ...]) -> dict[str, ManifestAnalysis]:
    return {m.path: m for m in manifests}


def test_adapter_registered_at_runtime_is_used_without_core_changes(tmp_path: Path) -> None:
    """The engine runs any registered adapter; adding one needs no change to the core."""
    write(tmp_path, "app/example-deps.txt", "# deps\nalpha==1.0\nbeta==2.0\n")
    registry = AdapterRegistry()
    registry.register(ExampleAdapter())

    result = analyze_project(tmp_path, registry)

    (manifest,) = result.manifests
    assert manifest.path == "app/example-deps.txt"
    assert manifest.adapter_id == "example"
    assert manifest.status is ParseStatus.PARSED
    assert [r.identity.name for r in manifest.requirements] == ["alpha", "beta"]
    assert [r.line for r in manifest.requirements] == [2, 3]
    assert all(edge.is_direct for edge in manifest.edges)
    assert result.completion is CompletionState.COMPLETE


def test_project_without_supported_files_is_not_reported_complete(tmp_path: Path) -> None:
    write(tmp_path, "README.md", "hello")
    result = analyze_project(tmp_path, AdapterRegistry([ExampleAdapter()]))
    assert result.manifests == ()
    assert result.completion is CompletionState.NO_SUPPORTED_FILES


def test_default_registry_ignores_files_no_builtin_adapter_claims(tmp_path: Path) -> None:
    write(tmp_path, "example-deps.txt", "alpha==1.0\n")
    result = analyze_project(tmp_path, default_registry())
    assert result.completion is CompletionState.NO_SUPPORTED_FILES


def test_recognized_unsupported_file_is_reported(tmp_path: Path) -> None:
    write(tmp_path, "example-deps.txt", "alpha==1.0\n")
    write(tmp_path, "example.lock", "anything")
    result = analyze_project(tmp_path, AdapterRegistry([ExampleAdapter()]))
    lock = by_path(result.manifests)["example.lock"]
    assert lock.status is ParseStatus.UNSUPPORTED
    assert lock.diagnostics[0].code == "manifest.unsupported_format"
    assert result.completion is CompletionState.PARTIAL


def test_adapter_exception_is_contained_and_reported_without_its_message(tmp_path: Path) -> None:
    write(tmp_path, "raise.txt", "x")
    write(tmp_path, "example-deps.txt", "alpha==1.0\n")
    result = analyze_project(tmp_path, AdapterRegistry([ExampleAdapter(), RaisingAdapter()]))
    failed = by_path(result.manifests)["raise.txt"]
    assert failed.status is ParseStatus.FAILED
    (diagnostic,) = failed.diagnostics
    assert diagnostic.code == "adapter.exception"
    assert "RuntimeError" in diagnostic.message
    assert "secret" not in diagnostic.message
    assert by_path(result.manifests)["example-deps.txt"].status is ParseStatus.PARSED
    assert result.completion is CompletionState.PARTIAL


def test_all_files_failing_gives_failed_scan(tmp_path: Path) -> None:
    write(tmp_path, "raise.txt", "x")
    result = analyze_project(tmp_path, AdapterRegistry([RaisingAdapter()]))
    assert result.completion is CompletionState.FAILED


def test_invalid_adapter_result_is_reported_as_failure(tmp_path: Path) -> None:
    write(tmp_path, "invalid.txt", "x")
    result = analyze_project(tmp_path, AdapterRegistry([InvalidResultAdapter()]))
    (manifest,) = result.manifests
    assert manifest.status is ParseStatus.FAILED
    assert manifest.diagnostics[0].code == "adapter.invalid_result"


def test_include_inside_project_is_followed(tmp_path: Path) -> None:
    write(tmp_path, "app/example-deps.txt", "-r common/base.txt\n")
    write(tmp_path, "app/common/base.txt", "gamma==3.0\n")
    result = analyze_project(tmp_path, AdapterRegistry([ExampleAdapter()]))
    (manifest,) = result.manifests
    assert manifest.status is ParseStatus.PARSED
    assert [p.identity.name for p in manifest.packages] == ["gamma"]


def test_include_escaping_project_is_denied(tmp_path: Path) -> None:
    project = tmp_path / "project"
    write(project, "example-deps.txt", "-r ../outside.txt\nalpha==1.0\n")
    write(tmp_path, "outside.txt", "stolen==6.6.6\n")
    result = analyze_project(project, AdapterRegistry([ExampleAdapter()]))
    (manifest,) = result.manifests
    assert manifest.status is ParseStatus.PARTIAL
    assert [p.identity.name for p in manifest.packages] == ["alpha"]
    assert manifest.diagnostics[0].code == "example.include_denied"


def test_oversized_file_is_skipped(tmp_path: Path) -> None:
    write(tmp_path, "example-deps.txt", "alpha==1.0\n" * 10)
    result = analyze_project(
        tmp_path, AdapterRegistry([ExampleAdapter()]), limits=ScanLimits(max_file_bytes=16)
    )
    (manifest,) = result.manifests
    assert manifest.status is ParseStatus.SKIPPED
    assert manifest.diagnostics[0].code == "manifest.too_large"
    assert result.completion is CompletionState.PARTIAL


def test_malformed_content_is_partial_not_a_crash(tmp_path: Path) -> None:
    (tmp_path / "example-deps.txt").write_bytes(b"\xff\xfe not utf-8")
    result = analyze_project(tmp_path, AdapterRegistry([ExampleAdapter()]))
    assert result.manifests[0].status is ParseStatus.FAILED
    assert result.completion is CompletionState.FAILED


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_invalid_root_is_rejected(tmp_path: Path, kind: str) -> None:
    root = tmp_path / "nope"
    if kind == "file":
        root.write_text("x", encoding="utf-8")
    with pytest.raises(InvalidProjectRootError) as exc:
        analyze_project(root, AdapterRegistry())
    assert str(tmp_path) not in str(exc.value)


def test_scan_output_is_deterministic_and_has_no_absolute_paths(tmp_path: Path) -> None:
    write(tmp_path, "b/example-deps.txt", "beta==2.0\n")
    write(tmp_path, "a/example-deps.txt", "alpha==1.0\nnot a requirement\n")
    write(tmp_path, "example.lock", "x")
    registry = AdapterRegistry([ExampleAdapter()])
    start = datetime(2026, 1, 1, tzinfo=UTC)

    first = dumps_scan(analyze_project(tmp_path, registry, clock=lambda: start))
    second = dumps_scan(analyze_project(tmp_path, registry, clock=lambda: start))

    assert first == second
    assert str(tmp_path) not in first
    assert str(tmp_path).replace("\\", "/") not in first
    assert json.loads(first)["project_name"] == tmp_path.name


def test_timestamps_come_from_the_injected_clock(tmp_path: Path) -> None:
    result = analyze_project(tmp_path, AdapterRegistry(), clock=clock)
    assert result.started_at < result.finished_at
    assert result.started_at.tzinfo is UTC
