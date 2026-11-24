"""The dependency-analysis use case: discover files, dispatch to adapters, aggregate.

The pipeline knows nothing about specific ecosystems. It only uses the
adapters in the registry it is given, so adding an adapter never requires
changing this module. Adapter failures are contained per file and always
reported; they never turn into a clean result.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from dva import __version__
from dva.contracts.ecosystem import AdapterResult, ParseContext, SupportLevel
from dva.contracts.files import FileAccessError, FileTooLargeError
from dva.discovery.limits import ScanLimits
from dva.discovery.reader import BoundedFileReader
from dva.discovery.walker import DiscoveredFile, discover
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ManifestAnalysis, ParseStatus
from dva.domain.scan import ScanResult
from dva.ecosystems.registry import AdapterRegistry

type Clock = Callable[[], datetime]


class InvalidProjectRootError(ValueError):
    """The requested project root does not exist or is not a directory."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def analyze_project(
    root: Path,
    registry: AdapterRegistry,
    *,
    limits: ScanLimits | None = None,
    clock: Clock = _utc_now,
) -> ScanResult:
    """Analyze the dependency files under ``root`` with the adapters in ``registry``.

    Reads files only; never executes project code. Raises
    :class:`InvalidProjectRootError` if ``root`` is not an existing directory.
    """
    limits = limits if limits is not None else ScanLimits()
    started_at = clock()
    resolved_root = _validate_root(root)
    reader = BoundedFileReader(resolved_root, limits.max_file_bytes)
    discovery = discover(resolved_root, registry, limits)
    manifests = tuple(_analyze_file(item, reader) for item in discovery.files)
    finished_at = clock()
    return ScanResult(
        tool_version=__version__,
        project_name=resolved_root.name or "project",
        started_at=started_at,
        finished_at=finished_at,
        manifests=manifests,
        diagnostics=discovery.diagnostics,
    )


def _validate_root(root: Path) -> Path:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise InvalidProjectRootError("project root does not exist or cannot be accessed") from exc
    if not resolved.is_dir():
        raise InvalidProjectRootError("project root is not a directory")
    return resolved


def _without_data(
    item: DiscoveredFile, status: ParseStatus, diagnostic: Diagnostic
) -> ManifestAnalysis:
    return ManifestAnalysis(
        path=item.path,
        adapter_id=item.adapter.adapter_id,
        ecosystem=item.adapter.ecosystem,
        kind=item.file_format.kind,
        format_name=item.file_format.format_name,
        status=status,
        diagnostics=(diagnostic,),
    )


def _analyze_file(item: DiscoveredFile, reader: BoundedFileReader) -> ManifestAnalysis:
    adapter_id = item.adapter.adapter_id
    file_format = item.file_format

    if file_format.support is SupportLevel.RECOGNIZED_UNSUPPORTED:
        return _without_data(
            item,
            ParseStatus.UNSUPPORTED,
            Diagnostic(
                "manifest.unsupported_format",
                DiagnosticLevel.WARNING,
                f"{file_format.format_name} is recognized but not supported: {file_format.note}",
                item.path,
            ),
        )

    try:
        content = reader.read(item.path)
    except FileTooLargeError as exc:
        return _without_data(
            item,
            ParseStatus.SKIPPED,
            Diagnostic("manifest.too_large", DiagnosticLevel.WARNING, str(exc), item.path),
        )
    except FileAccessError as exc:
        return _without_data(
            item,
            ParseStatus.FAILED,
            Diagnostic("manifest.unreadable", DiagnosticLevel.ERROR, str(exc), item.path),
        )

    context = ParseContext(path=item.path, content=content, file_format=file_format, reader=reader)
    try:
        result = item.adapter.parse(context)
    except Exception as exc:
        # The exception message may echo file content or absolute paths, so only
        # its type is reported.
        return _without_data(
            item,
            ParseStatus.FAILED,
            Diagnostic(
                "adapter.exception",
                DiagnosticLevel.ERROR,
                f"adapter {adapter_id!r} raised {type(exc).__name__} while parsing",
                item.path,
            ),
        )

    if not isinstance(result, AdapterResult):
        return _invalid_result(item, "it is not an AdapterResult")
    try:
        return ManifestAnalysis(
            path=item.path,
            adapter_id=adapter_id,
            ecosystem=item.adapter.ecosystem,
            kind=file_format.kind,
            format_name=file_format.format_name,
            status=result.status,
            format_version=result.format_version,
            requirements=result.requirements,
            packages=result.packages,
            edges=result.edges,
            diagnostics=result.diagnostics,
        )
    except ValueError as exc:
        return _invalid_result(item, str(exc))


def _invalid_result(item: DiscoveredFile, reason: str) -> ManifestAnalysis:
    return _without_data(
        item,
        ParseStatus.FAILED,
        Diagnostic(
            "adapter.invalid_result",
            DiagnosticLevel.ERROR,
            f"adapter {item.adapter.adapter_id!r} returned an invalid result: {reason}",
            item.path,
        ),
    )
