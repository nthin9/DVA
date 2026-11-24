"""Behaviour every ecosystem adapter must satisfy.

Runs against every built-in adapter in ``default_registry()`` (none yet) and
against the test-only example adapter, which proves the checks themselves
work. New adapters are covered automatically once they are registered.
"""

from __future__ import annotations

import pytest

from dva.contracts.ecosystem import (
    AdapterResult,
    EcosystemAdapter,
    FileFormat,
    ParseContext,
    SupportLevel,
)
from dva.contracts.files import FileAccessDeniedError
from dva.domain.manifest import ManifestAnalysis, ParseStatus
from dva.ecosystems.registry import AdapterRegistry, default_registry
from tests.support.example_adapter import ExampleAdapter

ADAPTERS: list[EcosystemAdapter] = [*default_registry().adapters, ExampleAdapter()]

HOSTILE_INPUTS: dict[str, bytes] = {
    "empty": b"",
    "binary": b"\x00\xff\xfe\x80garbage\x00",
    "bom": b"\xef\xbb\xbf",
    "deep_nesting": b"[" * 10_000 + b"]" * 10_000,
    "long_line": b"a" * 200_000,
    "path_reference": b"-r ../../../../etc/passwd\n-r C:/Windows/win.ini\n",
}


class DenyAllReader:
    """Records every attempted read and refuses all of them."""

    def __init__(self) -> None:
        self.requested: list[str] = []

    def read(self, relative_path: str) -> bytes:
        self.requested.append(relative_path)
        raise FileAccessDeniedError("reads are denied in contract tests")


def supported_formats(adapter: EcosystemAdapter) -> list[FileFormat]:
    return [f for f in adapter.formats if f.support is SupportLevel.SUPPORTED]


def as_manifest(adapter: EcosystemAdapter, fmt: FileFormat, result: AdapterResult) -> None:
    """The pipeline must be able to accept the result without it being invalid."""
    ManifestAnalysis(
        path=fmt.pattern.replace("*", "x"),
        adapter_id=adapter.adapter_id,
        ecosystem=adapter.ecosystem,
        kind=fmt.kind,
        format_name=fmt.format_name,
        status=result.status,
        format_version=result.format_version,
        requirements=result.requirements,
        packages=result.packages,
        edges=result.edges,
        diagnostics=result.diagnostics,
    )


@pytest.fixture(params=ADAPTERS, ids=lambda adapter: adapter.adapter_id)
def adapter(request: pytest.FixtureRequest) -> EcosystemAdapter:
    value: EcosystemAdapter = request.param
    return value


def test_declares_identity_and_formats(adapter: EcosystemAdapter) -> None:
    assert adapter.display_name.strip()
    assert adapter.ecosystem.strip()
    assert adapter.formats
    assert supported_formats(adapter), "an adapter must support at least one format"
    for fmt in adapter.formats:
        if fmt.support is SupportLevel.SUPPORTED:
            assert fmt.format_versions, f"{fmt.format_name}: list the supported format versions"


def test_registers_in_a_fresh_registry(adapter: EcosystemAdapter) -> None:
    AdapterRegistry([adapter])


@pytest.mark.parametrize("name", sorted(HOSTILE_INPUTS))
def test_hostile_input_yields_a_valid_result_without_raising(
    adapter: EcosystemAdapter, name: str
) -> None:
    for fmt in supported_formats(adapter):
        reader = DenyAllReader()
        path = fmt.pattern.replace("*", "x")
        result = adapter.parse(ParseContext(path, HOSTILE_INPUTS[name], fmt, reader))
        assert isinstance(result, AdapterResult)
        as_manifest(adapter, fmt, result)
        if result.status is not ParseStatus.PARSED:
            assert result.diagnostics


def test_every_reported_path_is_project_relative(adapter: EcosystemAdapter) -> None:
    for fmt in supported_formats(adapter):
        path = fmt.pattern.replace("*", "x")
        result = adapter.parse(
            ParseContext(path, HOSTILE_INPUTS["path_reference"], fmt, DenyAllReader())
        )
        for diagnostic in result.diagnostics:
            assert diagnostic.path is None or not diagnostic.path.startswith("/")
