"""Test-only ecosystem adapters. Never shipped and never in the default registry.

``ExampleAdapter`` parses a toy format, ``example-deps.txt``:

    # comment
    name==1.0         -> a direct dependency at an exact version
    -r other.txt      -> include another file (relative to this one)

It exists to prove that the pipeline works with any adapter that satisfies
the contract, without the core knowing anything about the format.
"""

from __future__ import annotations

import posixpath

from dva.contracts.ecosystem import AdapterResult, FileFormat, ParseContext, SupportLevel
from dva.contracts.files import FileAccessError
from dva.domain.dependency import DeclaredRequirement, DependencyEdge, ResolvedPackage
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.identity import PackageIdentity
from dva.domain.manifest import ManifestKind, ParseStatus

EXAMPLE_DEPS = FileFormat(
    pattern="example-deps.txt",
    format_name="example-deps",
    kind=ManifestKind.MANIFEST,
    format_versions=("1",),
)
EXAMPLE_LOCK = FileFormat(
    pattern="example.lock",
    format_name="example-lock",
    kind=ManifestKind.LOCKFILE,
    support=SupportLevel.RECOGNIZED_UNSUPPORTED,
    note="lockfile parsing is not implemented",
)


class ExampleAdapter:
    def __init__(self, adapter_id: str = "example", patterns: tuple[str, ...] = ()) -> None:
        self.adapter_id = adapter_id
        self.display_name = "Example (test only)"
        self.ecosystem = "example"
        if patterns:
            self.formats: tuple[FileFormat, ...] = tuple(
                FileFormat(p, "example-deps", ManifestKind.MANIFEST) for p in patterns
            )
        else:
            self.formats = (EXAMPLE_DEPS, EXAMPLE_LOCK)

    def parse(self, context: ParseContext) -> AdapterResult:
        try:
            text = context.content.decode("utf-8")
        except UnicodeDecodeError:
            return AdapterResult(
                status=ParseStatus.FAILED,
                diagnostics=(
                    Diagnostic(
                        "example.decode_error",
                        DiagnosticLevel.ERROR,
                        "file is not valid UTF-8",
                        context.path,
                    ),
                ),
            )

        requirements: list[DeclaredRequirement] = []
        packages: dict[str, ResolvedPackage] = {}
        diagnostics: list[Diagnostic] = []

        lines = list(enumerate(text.splitlines(), start=1))
        for number, raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-r "):
                target = posixpath.normpath(
                    posixpath.join(posixpath.dirname(context.path), line[3:].strip())
                )
                try:
                    included = context.reader.read(target).decode("utf-8", errors="replace")
                except FileAccessError as exc:
                    diagnostics.append(
                        Diagnostic(
                            "example.include_denied",
                            DiagnosticLevel.WARNING,
                            str(exc),
                            context.path,
                        )
                    )
                    continue
                lines_included = [entry.strip() for entry in included.splitlines() if "==" in entry]
                for entry in lines_included:
                    self._add(entry, None, requirements, packages)
                continue
            if "==" not in line:
                diagnostics.append(
                    Diagnostic(
                        "example.malformed_line",
                        DiagnosticLevel.WARNING,
                        f"line {number} is not 'name==version'",
                        context.path,
                    )
                )
                continue
            self._add(line, number, requirements, packages)

        edges = tuple(DependencyEdge(None, node_id) for node_id in packages)
        return AdapterResult(
            status=ParseStatus.PARTIAL if diagnostics else ParseStatus.PARSED,
            format_version="1",
            requirements=tuple(requirements),
            packages=tuple(packages.values()),
            edges=edges,
            diagnostics=tuple(diagnostics),
        )

    def _add(
        self,
        entry: str,
        line: int | None,
        requirements: list[DeclaredRequirement],
        packages: dict[str, ResolvedPackage],
    ) -> None:
        name, version = (part.strip() for part in entry.split("==", 1))
        identity = PackageIdentity(self.ecosystem, name)
        requirements.append(DeclaredRequirement(identity, constraint=f"=={version}", line=line))
        node_id = f"{name}@{version}"
        packages[node_id] = ResolvedPackage(node_id, identity, version)


class RaisingAdapter:
    """Raises from ``parse``; the message deliberately contains a fake absolute path."""

    adapter_id = "raising"
    display_name = "Raising (test only)"
    ecosystem = "example"
    formats = (FileFormat("raise.txt", "raise", ManifestKind.MANIFEST),)

    def parse(self, context: ParseContext) -> AdapterResult:
        raise RuntimeError("boom at C:\\Users\\someone\\secret\\raise.txt")


class InvalidResultAdapter:
    """Returns a FAILED status without the required explanatory diagnostic."""

    adapter_id = "invalid"
    display_name = "Invalid (test only)"
    ecosystem = "example"
    formats = (FileFormat("invalid.txt", "invalid", ManifestKind.MANIFEST),)

    def parse(self, context: ParseContext) -> AdapterResult:
        return AdapterResult(status=ParseStatus.FAILED)
