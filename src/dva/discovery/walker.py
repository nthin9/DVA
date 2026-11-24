"""Walk a project folder and select files that registered adapters declare.

The walk is read-only, never follows symlinks or junctions, skips dependency,
VCS and cache folders, and stops at the configured limits. Every limit hit or
skipped item that could hide dependency data produces a diagnostic, so a
truncated discovery is never mistaken for a complete one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dva.contracts.ecosystem import EcosystemAdapter, FileFormat
from dva.discovery.exclude import ExcludeRules
from dva.discovery.limits import ScanLimits
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.ecosystems.registry import AdapterRegistry

#: Folder names skipped during discovery (compared case-insensitively). They
#: hold installed packages, VCS data, or tool caches rather than the project's
#: own dependency declarations.
EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "site-packages",
    }
)
_EXCLUDED_FOLDED = frozenset(name.casefold() for name in EXCLUDED_DIR_NAMES)
#: Files that mark a folder as an environment of installed packages, whatever
#: the folder is called: a Python virtual environment, or a conda environment.
ENVIRONMENT_MARKERS = ("pyvenv.cfg", "conda-meta")


def _is_environment(directory: str) -> bool:
    return any(os.path.exists(os.path.join(directory, marker)) for marker in ENVIRONMENT_MARKERS)


@dataclass(frozen=True, slots=True)
class DiscoveredFile:
    path: str
    adapter: EcosystemAdapter
    file_format: FileFormat


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    files: tuple[DiscoveredFile, ...]
    diagnostics: tuple[Diagnostic, ...]


def _warning(code: str, message: str, path: str | None = None) -> Diagnostic:
    return Diagnostic(code, DiagnosticLevel.WARNING, message, path)


def discover(
    root: Path,
    registry: AdapterRegistry,
    limits: ScanLimits,
    exclude: ExcludeRules | None = None,
) -> DiscoveryResult:
    """Find files under ``root`` that match a format declared in ``registry``,
    skipping anything ``exclude`` matches."""
    exclude = exclude or ExcludeRules()
    files: list[DiscoveredFile] = []
    diagnostics: list[Diagnostic] = []
    entries_seen = 0
    # Depth-first, in sorted name order, so results are deterministic.
    stack: list[tuple[Path, str, int]] = [(root, "", 0)]

    def result() -> DiscoveryResult:
        return DiscoveryResult(tuple(files), tuple(diagnostics))

    while stack:
        directory, rel_dir, depth = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                # Stop collecting once the entry budget is exceeded, so one huge
                # directory can't exhaust memory; the limit check below reports it.
                budget = limits.max_entries - entries_seen + 1
                entries = []
                for entry in iterator:
                    entries.append(entry)
                    if len(entries) >= budget:
                        break
                entries.sort(key=lambda entry: entry.name)
        except OSError as exc:
            reason = exc.strerror or type(exc).__name__
            diagnostics.append(
                _warning(
                    "discovery.unreadable_directory",
                    f"could not list directory: {reason}",
                    rel_dir or None,
                )
            )
            continue

        subdirectories: list[tuple[Path, str, int]] = []
        for entry in entries:
            entries_seen += 1
            if entries_seen > limits.max_entries:
                diagnostics.append(
                    _warning(
                        "discovery.entry_limit",
                        f"stopped after examining {limits.max_entries} directory entries",
                    )
                )
                return result()

            if "\\" in entry.name or ":" in entry.name:
                diagnostics.append(
                    _warning(
                        "discovery.unsupported_name",
                        "skipped an entry whose name contains '\\' or ':'",
                        rel_dir or None,
                    )
                )
                continue
            rel_path = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            if exclude and exclude.matches(rel_path):
                continue

            try:
                if entry.is_symlink() or entry.is_junction():
                    if registry.match(entry.name) or entry.is_dir():
                        diagnostics.append(
                            _warning(
                                "discovery.link_skipped",
                                "symbolic link or junction was not followed",
                                rel_path,
                            )
                        )
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.casefold() in _EXCLUDED_FOLDED or _is_environment(entry.path):
                        continue
                    if depth + 1 > limits.max_depth:
                        diagnostics.append(
                            _warning(
                                "discovery.depth_limit",
                                f"not searched: deeper than {limits.max_depth} levels",
                                rel_path,
                            )
                        )
                        continue
                    subdirectories.append((Path(entry.path), rel_path, depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError as exc:
                reason = exc.strerror or type(exc).__name__
                diagnostics.append(
                    _warning("discovery.unreadable_entry", f"could not inspect: {reason}", rel_path)
                )
                continue

            matches = registry.match(entry.name)
            if not matches:
                continue
            if len(matches) > 1:
                claimants = ", ".join(sorted(adapter.adapter_id for adapter, _ in matches))
                diagnostics.append(
                    _warning(
                        "discovery.ambiguous_format",
                        f"skipped: file name matches formats of several adapters ({claimants})",
                        rel_path,
                    )
                )
                continue
            if len(files) >= limits.max_manifests:
                diagnostics.append(
                    _warning(
                        "discovery.manifest_limit",
                        f"stopped after finding {limits.max_manifests} dependency files",
                    )
                )
                return result()
            adapter, file_format = matches[0]
            files.append(DiscoveredFile(rel_path, adapter, file_format))

        stack.extend(reversed(subdirectories))

    return result()
