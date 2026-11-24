from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from dva.domain.dependency import (
    DeclaredRequirement,
    DependencyEdge,
    ResolvedPackage,
    SourceKind,
)
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.identity import PackageIdentity
from dva.domain.manifest import ManifestAnalysis, ManifestKind, ParseStatus
from dva.domain.scan import ScanResult
from dva.domain.serialization import SCHEMA_VERSION, dumps_scan, scan_to_dict

GOLDEN = Path(__file__).parents[2] / "fixtures" / "serialization" / "scan_minimal.json"


def build_scan(*, reverse: bool = False) -> ScanResult:
    def order[T](items: tuple[T, ...]) -> tuple[T, ...]:
        return tuple(reversed(items)) if reverse else items

    alpha = PackageIdentity("example", "alpha", purl="pkg:example/alpha")
    beta = PackageIdentity("example", "bêta")
    lock = ManifestAnalysis(
        path="sub/example-deps.txt",
        adapter_id="example",
        ecosystem="example",
        kind=ManifestKind.MANIFEST,
        format_name="example-deps",
        status=ParseStatus.PARTIAL,
        format_version="1",
        requirements=order(
            (
                DeclaredRequirement(alpha, constraint="==1.0", line=1, groups=("dev", "a")),
                DeclaredRequirement(
                    beta,
                    constraint="==2.0",
                    line=2,
                    source=SourceKind.REGISTRY,
                    extras=("zeta", "eta"),
                    alias="b",
                ),
            )
        ),
        packages=order(
            (
                ResolvedPackage("alpha@1.0", alpha, "1.0"),
                ResolvedPackage("bêta@2.0", beta, "2.0", source=SourceKind.REGISTRY),
            )
        ),
        edges=order(
            (
                DependencyEdge(None, "alpha@1.0"),
                DependencyEdge(
                    "alpha@1.0",
                    "bêta@2.0",
                    constraint=">=2",
                    markers='os_name == "nt"',
                    groups=("dev",),
                ),
            )
        ),
        diagnostics=order(
            (
                Diagnostic(
                    "example.malformed_line",
                    DiagnosticLevel.WARNING,
                    "line 3",
                    "sub/example-deps.txt",
                ),
                Diagnostic(
                    "example.include_denied",
                    DiagnosticLevel.WARNING,
                    "denied",
                    "sub/example-deps.txt",
                ),
            )
        ),
    )
    other = ManifestAnalysis(
        path="example.lock",
        adapter_id="example",
        ecosystem="example",
        kind=ManifestKind.LOCKFILE,
        format_name="example-lock",
        status=ParseStatus.UNSUPPORTED,
        diagnostics=(
            Diagnostic(
                "manifest.unsupported_format",
                DiagnosticLevel.WARNING,
                "not supported",
                "example.lock",
            ),
        ),
    )
    return ScanResult(
        tool_version="0.0.1",
        project_name="demo",
        started_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        finished_at=datetime(2026, 1, 2, 3, 4, 6, 500, tzinfo=UTC),
        manifests=order((lock, other)),
    )


def test_output_matches_golden_file() -> None:
    assert dumps_scan(build_scan()) == GOLDEN.read_text(encoding="utf-8")


def test_output_does_not_depend_on_input_order() -> None:
    assert dumps_scan(build_scan()) == dumps_scan(build_scan(reverse=True))


def test_output_is_valid_json_with_schema_version_and_derived_state() -> None:
    data = json.loads(dumps_scan(build_scan()))
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["completion"] == "partial"
    assert data["vulnerability_status"] == "not_queried"
    assert data["finished_at"] == "2026-01-02T03:04:06.000500Z"


def test_non_ascii_text_is_preserved() -> None:
    assert "bêta" in dumps_scan(build_scan())


def test_edges_record_directness() -> None:
    edges = scan_to_dict(build_scan())["manifests"]
    assert isinstance(edges, list)
    lock = edges[1]
    assert isinstance(lock, dict)
    assert lock["edges"] == [
        {
            "parent_id": None,
            "child_id": "alpha@1.0",
            "direct": True,
            "constraint": None,
            "markers": None,
            "groups": [],
        },
        {
            "parent_id": "alpha@1.0",
            "child_id": "bêta@2.0",
            "direct": False,
            "constraint": ">=2",
            "markers": 'os_name == "nt"',
            "groups": ["dev"],
        },
    ]


def test_requirements_and_packages_record_source_extras_and_alias() -> None:
    manifests = scan_to_dict(build_scan())["manifests"]
    assert isinstance(manifests, list)
    lock = manifests[1]
    assert isinstance(lock, dict)
    requirements = lock["requirements"]
    assert isinstance(requirements, list)
    alpha, beta = requirements
    assert isinstance(alpha, dict) and isinstance(beta, dict)
    assert (alpha["source"], alpha["extras"], alpha["alias"]) == ("unknown", [], None)
    assert (beta["source"], beta["extras"], beta["alias"]) == ("registry", ["eta", "zeta"], "b")
    packages = lock["packages"]
    assert isinstance(packages, list)
    assert [p["source"] for p in packages if isinstance(p, dict)] == ["unknown", "registry"]
