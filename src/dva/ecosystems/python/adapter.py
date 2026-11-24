"""The Python (PyPI) ecosystem adapter."""

from __future__ import annotations

from collections.abc import Callable

from dva.contracts.ecosystem import AdapterResult, FileFormat, ParseContext, SupportLevel
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ManifestKind, ParseStatus
from dva.ecosystems.python.names import ECOSYSTEM
from dva.ecosystems.python.poetry_lock import SUPPORTED_VERSIONS as POETRY_LOCK_VERSIONS
from dva.ecosystems.python.poetry_lock import parse_poetry_lock
from dva.ecosystems.python.pyproject import parse_pyproject
from dva.ecosystems.python.requirements_txt import parse_requirements_file
from dva.ecosystems.python.uv_lock import SUPPORTED_VERSION as UV_LOCK_VERSION
from dva.ecosystems.python.uv_lock import parse_uv_lock

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

UV_LOCK = FileFormat(
    pattern="uv.lock",
    format_name="uv-lock",
    kind=ManifestKind.LOCKFILE,
    format_versions=(str(UV_LOCK_VERSION),),
)
POETRY_LOCK = FileFormat(
    pattern="poetry.lock",
    format_name="poetry-lock",
    kind=ManifestKind.LOCKFILE,
    format_versions=POETRY_LOCK_VERSIONS,
    note="Records package-to-package links but not the project's direct dependencies.",
)


def _unsupported(pattern: str, name: str, kind: ManifestKind, note: str) -> FileFormat:
    return FileFormat(pattern, name, kind, SupportLevel.RECOGNIZED_UNSUPPORTED, note=note)


UNSUPPORTED_FORMATS = (
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
    formats: tuple[FileFormat, ...] = (
        REQUIREMENTS_TXT,
        PYPROJECT_TOML,
        UV_LOCK,
        POETRY_LOCK,
        *UNSUPPORTED_FORMATS,
    )

    def parse(self, context: ParseContext) -> AdapterResult:
        parser = _PARSERS.get(context.file_format.format_name)
        if parser is not None and context.file_format in self.formats:
            return parser(context)
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


_PARSERS: dict[str, Callable[[ParseContext], AdapterResult]] = {
    REQUIREMENTS_TXT.format_name: parse_requirements_file,
    PYPROJECT_TOML.format_name: parse_pyproject,
    UV_LOCK.format_name: parse_uv_lock,
    POETRY_LOCK.format_name: parse_poetry_lock,
}
