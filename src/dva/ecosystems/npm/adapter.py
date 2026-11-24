"""The npm ecosystem adapter (JavaScript and TypeScript projects)."""

from __future__ import annotations

from collections.abc import Callable

from dva.contracts.ecosystem import AdapterResult, FileFormat, ParseContext, SupportLevel
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ManifestKind, ParseStatus
from dva.ecosystems.npm.names import ECOSYSTEM
from dva.ecosystems.npm.package_json import parse_package_json
from dva.ecosystems.npm.package_lock import SUPPORTED_VERSIONS, parse_package_lock

_LOCK_VERSIONS = tuple(str(v) for v in SUPPORTED_VERSIONS)

PACKAGE_JSON = FileFormat(
    pattern="package.json",
    format_name="package-json",
    kind=ManifestKind.MANIFEST,
    format_versions=("unversioned",),
    note="npm's package.json has no format version.",
)
PACKAGE_LOCK = FileFormat(
    pattern="package-lock.json",
    format_name="package-lock",
    kind=ManifestKind.LOCKFILE,
    format_versions=_LOCK_VERSIONS,
)
SHRINKWRAP = FileFormat(
    pattern="npm-shrinkwrap.json",
    format_name="npm-shrinkwrap",
    kind=ManifestKind.LOCKFILE,
    format_versions=_LOCK_VERSIONS,
)


def _unsupported(pattern: str, name: str, note: str) -> FileFormat:
    return FileFormat(
        pattern, name, ManifestKind.LOCKFILE, SupportLevel.RECOGNIZED_UNSUPPORTED, note=note
    )


UNSUPPORTED_FORMATS = (
    _unsupported("yarn.lock", "yarn-lock", "Yarn lockfiles are not supported."),
    _unsupported("pnpm-lock.yaml", "pnpm-lock", "pnpm lockfiles are not supported."),
    _unsupported("bun.lock", "bun-lock", "Bun lockfiles are not supported."),
    _unsupported("bun.lockb", "bun-lockb", "Bun's binary lockfiles are not supported."),
)

_PARSERS: dict[str, Callable[[ParseContext], AdapterResult]] = {
    PACKAGE_JSON.format_name: parse_package_json,
    PACKAGE_LOCK.format_name: parse_package_lock,
    SHRINKWRAP.format_name: parse_package_lock,
}


class NpmAdapter:
    adapter_id = "npm"
    display_name = "npm"
    ecosystem = ECOSYSTEM
    formats: tuple[FileFormat, ...] = (PACKAGE_JSON, PACKAGE_LOCK, SHRINKWRAP, *UNSUPPORTED_FORMATS)

    def parse(self, context: ParseContext) -> AdapterResult:
        parser = _PARSERS.get(context.file_format.format_name)
        if parser is not None and context.file_format in self.formats:
            return parser(context)
        return AdapterResult(
            status=ParseStatus.UNSUPPORTED,
            diagnostics=(
                Diagnostic(
                    "npm.unsupported_format",
                    DiagnosticLevel.WARNING,
                    f"{context.file_format.format_name} files are not supported",
                    context.path,
                ),
            ),
        )
