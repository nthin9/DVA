"""Ecosystem adapter contract.

Adapters are pure parsers: they receive a file's (size-bounded) bytes plus a
root-confined reader for referenced files, and return normalized domain data.
They never walk the filesystem, open paths directly, execute project code, or
run package managers. Core discovery decides which files an adapter receives,
based only on the formats the adapter declares.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from dva.contracts.files import ProjectFileReader
from dva.domain.dependency import DeclaredRequirement, DependencyEdge, ResolvedPackage
from dva.domain.diagnostics import Diagnostic
from dva.domain.manifest import ManifestKind, ParseStatus
from dva.domain.paths import require_relative_path


class SupportLevel(StrEnum):
    SUPPORTED = "supported"
    #: Known file format the adapter deliberately does not parse. Discovering
    #: such a file is reported as unsupported instead of being silently ignored.
    RECOGNIZED_UNSUPPORTED = "recognized_unsupported"


@dataclass(frozen=True, slots=True)
class FileFormat:
    """A file format an adapter declares.

    ``pattern`` is a case-sensitive :mod:`fnmatch` pattern matched against the
    file's base name (for example ``package.json`` or ``requirements*.txt``).
    ``format_versions`` lists the exact format versions that are supported.
    ``note`` explains limitations or why a format is unsupported.
    """

    pattern: str
    format_name: str
    kind: ManifestKind
    support: SupportLevel = SupportLevel.SUPPORTED
    format_versions: tuple[str, ...] = ()
    note: str | None = None

    def __post_init__(self) -> None:
        if not self.pattern or "/" in self.pattern or "\\" in self.pattern:
            raise ValueError(f"pattern must be a non-empty base-name pattern: {self.pattern!r}")
        if not self.format_name:
            raise ValueError("format_name must be non-empty")
        if self.support is SupportLevel.RECOGNIZED_UNSUPPORTED and not self.note:
            raise ValueError("an unsupported format must explain itself in note")

    def matches(self, filename: str) -> bool:
        return fnmatch.fnmatchcase(filename, self.pattern)


@dataclass(frozen=True, slots=True)
class ParseContext:
    """Input handed to an adapter for one discovered file."""

    path: str
    content: bytes
    file_format: FileFormat
    reader: ProjectFileReader

    def __post_init__(self) -> None:
        require_relative_path(self.path)


@dataclass(frozen=True, slots=True)
class AdapterResult:
    """An adapter's normalized output for one file.

    Any status other than ``PARSED`` must be explained by a diagnostic; the
    pipeline enforces this when building the manifest analysis.
    """

    status: ParseStatus
    format_version: str | None = None
    requirements: tuple[DeclaredRequirement, ...] = ()
    packages: tuple[ResolvedPackage, ...] = ()
    edges: tuple[DependencyEdge, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()


class EcosystemAdapter(Protocol):
    """Contract every ecosystem adapter implements.

    ``adapter_id`` is a stable lowercase identifier; ``ecosystem`` is the
    identifier written into :class:`~dva.domain.identity.PackageIdentity`.
    ``parse`` should report malformed input through diagnostics and a
    non-``PARSED`` status; an exception is still contained by the pipeline,
    but is reported as an adapter failure.
    """

    @property
    def adapter_id(self) -> str: ...

    @property
    def display_name(self) -> str: ...

    @property
    def ecosystem(self) -> str: ...

    @property
    def formats(self) -> tuple[FileFormat, ...]: ...

    def parse(self, context: ParseContext) -> AdapterResult: ...
