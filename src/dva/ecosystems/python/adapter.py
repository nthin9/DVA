"""The Python (PyPI) ecosystem adapter."""

from __future__ import annotations

from dva.contracts.ecosystem import AdapterResult, FileFormat, ParseContext, SupportLevel
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ManifestKind, ParseStatus
from dva.ecosystems.python.names import ECOSYSTEM
from dva.ecosystems.python.pyproject import parse_pyproject
from dva.ecosystems.python.requirements_txt import parse_requirements_file

REQUIREMENTS_TXT = FileFormat(
    pattern="requirements*.txt",
    format_name="pip-requirements",
    kind=ManifestKind.MANIFEST,
    format_versions=("unversioned",),
    note="pip's requirements file syntax, which has no version number.",
)
PYPROJECT_TOML = FileFormat(
    pattern="pyproject.toml",
    format_name="pyproject",
    kind=ManifestKind.MANIFEST,
    format_versions=("pep-621", "pep-735"),
    note="Standard [project] dependencies and [dependency-groups]; tool-specific tables are "
    "reported, not read.",
)


def _unsupported(pattern: str, name: str, kind: ManifestKind, note: str) -> FileFormat:
    return FileFormat(pattern, name, kind, SupportLevel.RECOGNIZED_UNSUPPORTED, note=note)


UNSUPPORTED_FORMATS = (
    _unsupported(
        "uv.lock", "uv-lock", ManifestKind.LOCKFILE, "uv lockfiles are not supported yet."
    ),
    _unsupported(
        "poetry.lock",
        "poetry-lock",
        ManifestKind.LOCKFILE,
        "Poetry lockfiles are not supported yet.",
    ),
    _unsupported("Pipfile", "pipfile", ManifestKind.MANIFEST, "Pipfiles are not supported."),
    _unsupported(
        "Pipfile.lock", "pipfile-lock", ManifestKind.LOCKFILE, "Pipfile.lock is not supported."
    ),
    _unsupported(
        "pylock.toml", "pylock", ManifestKind.LOCKFILE, "pylock.toml (PEP 751) is not supported."
    ),
    _unsupported(
        "pylock.*.toml", "pylock", ManifestKind.LOCKFILE, "pylock.toml (PEP 751) is not supported."
    ),
    _unsupported(
        "setup.py",
        "setup-py",
        ManifestKind.MANIFEST,
        "setup.py is a program; reading its dependencies would mean running it.",
    ),
    _unsupported("setup.cfg", "setup-cfg", ManifestKind.MANIFEST, "setup.cfg is not supported."),
)


class PythonAdapter:
    adapter_id = "python"
    display_name = "Python"
    ecosystem = ECOSYSTEM
    formats: tuple[FileFormat, ...] = (REQUIREMENTS_TXT, PYPROJECT_TOML, *UNSUPPORTED_FORMATS)

    def parse(self, context: ParseContext) -> AdapterResult:
        if context.file_format == REQUIREMENTS_TXT:
            return parse_requirements_file(context)
        if context.file_format == PYPROJECT_TOML:
            return parse_pyproject(context)
        return AdapterResult(
            status=ParseStatus.UNSUPPORTED,
            diagnostics=(
                Diagnostic(
                    "python.unsupported_format",
                    DiagnosticLevel.WARNING,
                    f"{context.file_format.format_name} files are not supported",
                    context.path,
                ),
            ),
        )
