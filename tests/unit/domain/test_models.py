from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta, timezone

import pytest

from dva.domain.dependency import (
    DeclaredRequirement,
    DependencyEdge,
    ResolvedPackage,
    SourceKind,
)
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.identity import PackageIdentity
from dva.domain.manifest import ManifestAnalysis, ManifestKind, ParseStatus
from dva.domain.scan import CompletionState, ScanResult, VulnerabilityStatus

T0 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
IDENTITY = PackageIdentity("example", "alpha")
WARN = Diagnostic("x.warn", DiagnosticLevel.WARNING, "something was skipped", "a.txt")


def manifest(
    path: str = "a.txt",
    status: ParseStatus = ParseStatus.PARSED,
    **kwargs: object,
) -> ManifestAnalysis:
    defaults: dict[str, object] = {
        "adapter_id": "example",
        "ecosystem": "example",
        "kind": ManifestKind.MANIFEST,
        "format_name": "example-deps",
    }
    defaults.update(kwargs)
    return ManifestAnalysis(path=path, status=status, **defaults)  # type: ignore[arg-type]


def scan(*manifests: ManifestAnalysis, diagnostics: tuple[Diagnostic, ...] = ()) -> ScanResult:
    return ScanResult("0.0.1", "demo", T0, T0, manifests=manifests, diagnostics=diagnostics)


# --- identity / dependency -------------------------------------------------


def test_domain_objects_are_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        IDENTITY.name = "beta"  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ecosystem": "", "name": "a"},
        {"ecosystem": "npm", "name": " "},
        {"ecosystem": "npm", "name": " padded"},
        {"ecosystem": "npm", "name": "a", "namespace": ""},
        {"ecosystem": "npm", "name": "a", "purl": "npm/a"},
    ],
)
def test_package_identity_rejects_invalid_fields(kwargs: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        PackageIdentity(**kwargs)


def test_package_identity_keeps_namespace_and_purl() -> None:
    identity = PackageIdentity("npm", "core", namespace="@babel", purl="pkg:npm/%40babel/core")
    assert identity.namespace == "@babel"
    assert identity.purl == "pkg:npm/%40babel/core"


def test_requirement_rejects_bad_line_and_duplicate_groups() -> None:
    with pytest.raises(ValueError):
        DeclaredRequirement(IDENTITY, line=0)
    with pytest.raises(ValueError):
        DeclaredRequirement(IDENTITY, groups=("dev", "dev"))
    with pytest.raises(ValueError):
        DeclaredRequirement(IDENTITY, constraint="  ")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"extras": ("socks", "socks")},
        {"extras": ("",)},
        {"extras": (" socks",)},
        {"alias": ""},
        {"alias": " foo"},
    ],
)
def test_requirement_rejects_bad_extras_and_alias(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        DeclaredRequirement(IDENTITY, **kwargs)  # type: ignore[arg-type]


def test_source_defaults_to_unknown() -> None:
    assert DeclaredRequirement(IDENTITY).source is SourceKind.UNKNOWN
    assert ResolvedPackage("n1", IDENTITY, "1.0").source is SourceKind.UNKNOWN


def test_edge_rejects_blank_markers_and_duplicate_groups() -> None:
    with pytest.raises(ValueError):
        DependencyEdge("a", "b", markers=" ")
    with pytest.raises(ValueError):
        DependencyEdge("a", "b", groups=("dev", "dev"))


def test_requirement_without_constraint_is_allowed() -> None:
    assert DeclaredRequirement(IDENTITY).constraint is None


def test_resolved_package_requires_version_and_node_id() -> None:
    with pytest.raises(ValueError):
        ResolvedPackage("n1", IDENTITY, "")
    with pytest.raises(ValueError):
        ResolvedPackage("", IDENTITY, "1.0")


def test_edge_directness_and_self_reference() -> None:
    assert DependencyEdge(None, "a").is_direct
    assert not DependencyEdge("a", "b").is_direct
    with pytest.raises(ValueError):
        DependencyEdge("a", "a")


def test_diagnostic_validates_code_and_path() -> None:
    with pytest.raises(ValueError):
        Diagnostic("Bad Code", DiagnosticLevel.INFO, "msg")
    with pytest.raises(ValueError):
        Diagnostic("ok.code", DiagnosticLevel.INFO, "msg", "/abs/path")
    with pytest.raises(ValueError):
        Diagnostic("ok.code", DiagnosticLevel.INFO, "   ")


# --- manifest ----------------------------------------------------------------


def test_same_package_name_at_two_versions_is_two_nodes() -> None:
    packages = (
        ResolvedPackage("alpha@1", IDENTITY, "1.0"),
        ResolvedPackage("alpha@2", IDENTITY, "2.0"),
    )
    edges = (DependencyEdge(None, "alpha@1"), DependencyEdge("alpha@1", "alpha@2"))
    result = manifest(packages=packages, edges=edges)
    assert len(result.packages) == 2


def test_manifest_rejects_duplicate_node_ids() -> None:
    packages = (ResolvedPackage("n", IDENTITY, "1.0"), ResolvedPackage("n", IDENTITY, "2.0"))
    with pytest.raises(ValueError, match="unique"):
        manifest(packages=packages)


@pytest.mark.parametrize("edge", [DependencyEdge(None, "missing"), DependencyEdge("missing", "n")])
def test_manifest_rejects_edges_to_unknown_nodes(edge: DependencyEdge) -> None:
    with pytest.raises(ValueError, match="unknown"):
        manifest(packages=(ResolvedPackage("n", IDENTITY, "1.0"),), edges=(edge,))


@pytest.mark.parametrize(
    "status",
    [ParseStatus.PARTIAL, ParseStatus.FAILED, ParseStatus.UNSUPPORTED, ParseStatus.SKIPPED],
)
def test_non_parsed_status_requires_a_diagnostic(status: ParseStatus) -> None:
    with pytest.raises(ValueError, match="diagnostic"):
        manifest(status=status)


@pytest.mark.parametrize(
    "status", [ParseStatus.FAILED, ParseStatus.UNSUPPORTED, ParseStatus.SKIPPED]
)
def test_status_without_data_cannot_carry_dependencies(status: ParseStatus) -> None:
    with pytest.raises(ValueError, match="must not carry"):
        manifest(
            status=status,
            requirements=(DeclaredRequirement(IDENTITY),),
            diagnostics=(WARN,),
        )


def test_partial_status_may_carry_data() -> None:
    result = manifest(
        status=ParseStatus.PARTIAL,
        requirements=(DeclaredRequirement(IDENTITY),),
        diagnostics=(WARN,),
    )
    assert result.requirements


def test_manifest_path_must_be_relative() -> None:
    with pytest.raises(ValueError):
        manifest(path="C:/project/a.txt")


# --- scan --------------------------------------------------------------------


@pytest.mark.parametrize(
    "stamp",
    [datetime(2026, 1, 1), datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=2)))],  # noqa: DTZ001
)
def test_scan_requires_utc_timestamps(stamp: datetime) -> None:
    with pytest.raises(ValueError, match="UTC"):
        ScanResult("0.0.1", "demo", stamp, T0)


def test_scan_rejects_finish_before_start_and_path_like_names() -> None:
    with pytest.raises(ValueError):
        ScanResult("0.0.1", "demo", T0, T0 - timedelta(seconds=1))
    with pytest.raises(ValueError):
        ScanResult("0.0.1", "C:\\Users\\me\\demo", T0, T0)
    with pytest.raises(ValueError):
        scan(manifest("a.txt"), manifest("a.txt"))


def test_vulnerabilities_are_explicitly_not_queried() -> None:
    assert scan().vulnerability_status is VulnerabilityStatus.NOT_QUERIED


def test_completion_states() -> None:
    parsed = manifest("a.txt")
    partial = manifest("b.txt", ParseStatus.PARTIAL, diagnostics=(WARN,))
    failed = manifest("c.txt", ParseStatus.FAILED, diagnostics=(WARN,))
    failed2 = manifest("d.txt", ParseStatus.FAILED, diagnostics=(WARN,))
    unsupported = manifest("e.txt", ParseStatus.UNSUPPORTED, diagnostics=(WARN,))
    info = Diagnostic("x.info", DiagnosticLevel.INFO, "just so you know")
    limit = Diagnostic("discovery.depth_limit", DiagnosticLevel.WARNING, "not searched", "deep")

    assert scan().completion is CompletionState.NO_SUPPORTED_FILES
    assert scan(diagnostics=(info,)).completion is CompletionState.NO_SUPPORTED_FILES
    assert scan(diagnostics=(limit,)).completion is CompletionState.PARTIAL
    assert scan(parsed).completion is CompletionState.COMPLETE
    assert scan(parsed, diagnostics=(info,)).completion is CompletionState.COMPLETE
    assert scan(parsed, diagnostics=(limit,)).completion is CompletionState.PARTIAL
    assert scan(parsed, partial).completion is CompletionState.PARTIAL
    assert scan(parsed, unsupported).completion is CompletionState.PARTIAL
    assert scan(parsed, failed).completion is CompletionState.PARTIAL
    assert scan(failed, failed2).completion is CompletionState.FAILED
