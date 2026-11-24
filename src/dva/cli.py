"""Command-line entry point.

Presentation only: the CLI parses arguments, calls the application layer and
writes output. It contains no analysis logic.

Exit codes of ``dva scan``:

* 0: finished, nothing affected, and everything was checked.
* 1: at least one package is affected by an advisory.
* 3: nothing affected was found, but the analysis or the check was incomplete.
* 4: the scan couldn't run (for example, the folder doesn't exist).
* 2: invalid command-line arguments (argparse's own code).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from dva import __version__
from dva.application.analyze import InvalidProjectRootError, analyze_project
from dva.application.vulnerabilities import check_vulnerabilities
from dva.domain.scan import CompletionState, ScanResult
from dva.domain.vulnerability import CheckStatus, VulnerabilityStatus
from dva.ecosystems.registry import default_registry
from dva.intelligence.http import UrllibTransport
from dva.intelligence.osv.source import OsvSource
from dva.reporting.html import render_html
from dva.reporting.json_report import render_json
from dva.reporting.text import render_text
from dva.storage.advisory_cache import SqliteAdvisoryCache
from dva.storage.database import DatabaseError, open_database
from dva.storage.locations import DATABASE_NAME, default_data_dir

EXIT_CLEAN = 0
EXIT_AFFECTED = 1
EXIT_INCOMPLETE = 3
EXIT_ERROR = 4

_DESCRIPTION = (
    "DVA (Dependency Vulnerability Analysis): find a project's dependencies and check "
    "them against public vulnerability advisories. Nothing from the project is run "
    "or uploaded."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dva", description=_DESCRIPTION)
    parser.add_argument("--version", action="version", version=f"dva {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    scan = commands.add_parser(
        "scan",
        help="scan a project folder",
        description="Scan a project folder and check its dependencies against OSV.",
    )
    scan.add_argument("path", nargs="?", default=".", help="project folder (default: current)")
    scan.add_argument("--json", metavar="FILE", type=Path, help="also write a JSON report")
    scan.add_argument("--html", metavar="FILE", type=Path, help="also write an HTML report")
    lookups = scan.add_mutually_exclusive_group()
    lookups.add_argument(
        "--offline",
        action="store_true",
        help="don't contact OSV; use only advisory data cached by earlier scans",
    )
    lookups.add_argument(
        "--no-vulnerabilities",
        action="store_true",
        help="only analyze dependencies; skip the vulnerability check",
    )
    scan.add_argument(
        "--data-dir",
        metavar="DIR",
        type=Path,
        help="where DVA keeps its database (default: your user data folder, or DVA_DATA_DIR)",
    )
    scan.add_argument("--quiet", action="store_true", help="don't print the summary")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help()
        return EXIT_CLEAN
    _safe_stdout()
    return _scan(args)


def _safe_stdout() -> None:
    """Never crash on a package name the console's encoding can't show."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")


def _error(message: str) -> int:
    print(f"dva: error: {message}", file=sys.stderr)
    return EXIT_ERROR


def _scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    try:
        scan = analyze_project(root, default_registry())
    except InvalidProjectRootError:
        return _error(f"{args.path!r} is not a folder")

    if not args.no_vulnerabilities:
        data_dir = args.data_dir if args.data_dir is not None else default_data_dir()
        try:
            database = open_database(data_dir / DATABASE_NAME)
        except (DatabaseError, OSError) as error:
            message = str(error) if isinstance(error, DatabaseError) else "can't create it"
            return _error(f"the advisory cache couldn't be opened: {message}")
        try:
            scan = check_vulnerabilities(
                scan,
                OsvSource(UrllibTransport()),
                SqliteAdvisoryCache(database),
                offline=args.offline,
            )
        finally:
            database.close()

    for path, render in ((args.json, render_json), (args.html, render_html)):
        if path is None:
            continue
        try:
            path.write_text(render(scan), encoding="utf-8")
        except OSError:
            return _error(f"couldn't write {str(path)!r}")

    if not args.quiet:
        sys.stdout.write(render_text(scan))
        for label, path in (("JSON report", args.json), ("HTML report", args.html)):
            if path is not None:
                print(f"{label}: {path}")
    return exit_code(scan)


def exit_code(scan: ScanResult) -> int:
    report = scan.vulnerabilities
    if report is not None and any(c.status is CheckStatus.AFFECTED for c in report.checks):
        return EXIT_AFFECTED
    incomplete = scan.completion not in (
        CompletionState.COMPLETE,
        CompletionState.NO_SUPPORTED_FILES,
    ) or scan.vulnerability_status in (VulnerabilityStatus.PARTIAL, VulnerabilityStatus.FAILED)
    return EXIT_INCOMPLETE if incomplete else EXIT_CLEAN
