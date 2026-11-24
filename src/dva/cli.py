"""Command-line entry point.

Presentation only: the CLI parses arguments, calls the application layer and
writes output. It contains no analysis logic.

Exit codes of ``dva scan`` and ``dva rescan``:

* 0: finished, nothing affected, and everything was checked.
* 1: at least one package is affected by an advisory.
* 3: nothing affected was found, but the analysis or the check was incomplete.
* 4: the scan couldn't run (for example, the folder doesn't exist).
* 2: invalid command-line arguments (argparse's own code).

``dva rescan --all`` returns the most serious of these over all projects, in
the order 4, 1, 3, 0. ``dva compare`` returns 1 when the newer scan reports
an advisory finding the older one didn't, and 0 otherwise. Other commands
return 0, or 4 on an error.

``--include-private-registries`` lets ``scan`` and ``rescan`` look up packages
from registries other than PyPI or the npm registry; by default their names
are kept private and they are listed as not checked.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, date, datetime
from pathlib import Path

from dva import __version__
from dva.application.acceptance import (
    AcceptanceFileError,
    apply_acceptances,
    read_acceptance_file,
    unaccepted,
)
from dva.application.analyze import InvalidProjectRootError, analyze_project
from dva.application.history import (
    ProjectRootError,
    compare_scans,
    find_package,
    register_project,
    rescan_project,
    set_project_excludes,
)
from dva.application.vulnerabilities import check_vulnerabilities
from dva.contracts.history import HistoryError
from dva.domain.acceptance import Acceptance
from dva.domain.deserialization import ReportFormatError, loads_scan
from dva.domain.history import Project
from dva.domain.scan import CompletionState, ScanResult
from dva.domain.vulnerability import VulnerabilityStatus
from dva.ecosystems.registry import default_registry
from dva.intelligence.http import UrllibTransport
from dva.intelligence.osv.source import OsvSource
from dva.reporting.history import (
    render_comparison,
    render_history,
    render_projects,
    render_search,
    summary_line,
)
from dva.reporting.html import render_html
from dva.reporting.json_report import render_json
from dva.reporting.overview import clean_text
from dva.reporting.style import Style, colour_wanted
from dva.reporting.text import render_brief, render_text
from dva.storage.advisory_cache import SqliteAdvisoryCache
from dva.storage.advisory_cache import clear as clear_cache
from dva.storage.advisory_cache import summarize as summarize_cache
from dva.storage.database import DatabaseError, open_database
from dva.storage.history import SqliteHistoryStore
from dva.storage.locations import DATABASE_NAME, default_data_dir

EXIT_CLEAN = 0
EXIT_AFFECTED = 1
EXIT_INCOMPLETE = 3
EXIT_ERROR = 4

#: ``rescan --all`` reports the most serious outcome first in this order.
_SEVERITY = (EXIT_ERROR, EXIT_AFFECTED, EXIT_INCOMPLETE, EXIT_CLEAN)

_DESCRIPTION = (
    "DVA (Dependency Vulnerability Analysis): find a project's dependencies and check "
    "them against public vulnerability advisories. Nothing from the project is run "
    "or uploaded."
)


class _Failure(Exception):
    """A command can't continue; the message is shown to the user."""


def _data_dir_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--data-dir",
        metavar="DIR",
        type=Path,
        help="where DVA keeps its database (default: your user data folder, or DVA_DATA_DIR)",
    )


def _exclude_option(parser: argparse.ArgumentParser, help_text: str) -> None:
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATH",
        help=help_text,
    )


def _check_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        metavar="FILE",
        type=Path,
        help="also write a JSON report ('-' prints it instead of the summary)",
    )
    _exclude_option(
        parser,
        "skip this folder or file, relative to the project (repeatable; "
        "* patterns such as */fixtures work too)",
    )
    parser.add_argument("--html", metavar="FILE", type=Path, help="also write an HTML report")
    lookups = parser.add_mutually_exclusive_group()
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
    parser.add_argument(
        "--accept-file",
        metavar="FILE",
        type=Path,
        help="TOML file of accepted risks ([[accept]] advisory, reason, package, until); "
        "they stay listed but don't fail the exit code",
    )
    parser.add_argument(
        "--include-private-registries",
        action="store_true",
        help="also look up packages from registries other than PyPI or the npm registry "
        "(their names are sent to OSV)",
    )
    _data_dir_option(parser)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--quiet", action="store_true", help="don't print the summary")
    output.add_argument("--brief", action="store_true", help="print one line per affected package")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="colour the summary (default: auto, only on a terminal and unless NO_COLOR is set)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dva", description=_DESCRIPTION)
    parser.add_argument("--version", action="version", version=f"dva {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    scan = commands.add_parser(
        "scan",
        help="scan a project folder",
        description="Scan a project folder and check its dependencies against OSV. "
        "Nothing is saved; use 'dva project add' and 'dva rescan' to keep a history.",
    )
    scan.add_argument("path", nargs="?", default=".", help="project folder (default: current)")
    _check_options(scan)

    project = commands.add_parser(
        "project",
        help="register, list or remove projects",
        description="Manage the projects DVA keeps a scan history for.",
    )
    actions = project.add_subparsers(dest="action", metavar="<action>", required=True)
    add = actions.add_parser("add", help="register a project folder")
    add.add_argument("path", help="the project folder")
    add.add_argument("--name", help="name to use for it (default: the folder's name)")
    _exclude_option(add, "skip this folder or file on every rescan (repeatable)")
    _data_dir_option(add)
    listing = actions.add_parser("list", help="list registered projects")
    _data_dir_option(listing)
    accept = actions.add_parser(
        "accept",
        help="accept a reviewed risk for a project, or list or remove accepted risks",
        description="Accepted findings stay in every report, marked as accepted, but no "
        "longer fail the exit code. An advisory can be named by its id or any alias "
        "(such as a CVE id). With --until, the acceptance ends after that day.",
    )
    accept.add_argument("name", help="the project's name")
    accept.add_argument("advisory", nargs="?", help="advisory id or alias, e.g. CVE-2021-23337")
    accept.add_argument("--reason", help="why the risk is accepted (required to accept)")
    accept.add_argument("--package", help="only for this package")
    accept.add_argument("--until", metavar="YYYY-MM-DD", help="last day the acceptance holds")
    accept.add_argument("--list", action="store_true", help="list the project's accepted risks")
    accept.add_argument("--remove", action="store_true", help="remove the acceptance instead")
    _data_dir_option(accept)
    exclude = actions.add_parser(
        "exclude",
        help="show or change what a project's rescans skip",
        description="With no paths, show what a project's rescans skip. With paths, add "
        "them; with --clear, start from an empty list.",
    )
    exclude.add_argument("name", help="the project's name")
    exclude.add_argument("paths", nargs="*", metavar="PATH", help="folders, files or patterns")
    exclude.add_argument("--clear", action="store_true", help="remove the saved exclusions first")
    _data_dir_option(exclude)
    remove = actions.add_parser("remove", help="unregister a project and delete its scans")
    remove.add_argument("name", help="the project's name")
    remove.add_argument(
        "--yes", action="store_true", help="confirm deleting the project's saved scans"
    )
    _data_dir_option(remove)

    rescan = commands.add_parser(
        "rescan",
        help="scan a registered project again and save the result",
        description="Scan a registered project again, save the result in its history, "
        "and show what changed since the previous scan. Project files are only read.",
    )
    target = rescan.add_mutually_exclusive_group(required=True)
    target.add_argument("name", nargs="?", help="the project's name")
    target.add_argument("--all", action="store_true", help="rescan every registered project")
    _check_options(rescan)

    history = commands.add_parser(
        "history",
        help="list a project's saved scans, export one, or prune old ones",
        description="List a project's saved scans, newest first; export one as JSON or "
        "HTML; or delete old ones.",
    )
    history.add_argument("name", help="the project's name")
    history.add_argument("--limit", type=int, metavar="N", help="show at most N scans")
    history.add_argument(
        "--show",
        type=int,
        metavar="ID",
        help="export saved scan ID (as JSON to --json FILE or the screen, or to --html FILE)",
    )
    history.add_argument("--json", metavar="FILE", type=Path, help="JSON file for --show")
    history.add_argument("--html", metavar="FILE", type=Path, help="HTML file for --show")
    history.add_argument(
        "--prune",
        type=int,
        metavar="KEEP",
        help="delete all but the newest KEEP saved scans (needs --yes)",
    )
    history.add_argument("--yes", action="store_true", help="confirm --prune")
    _data_dir_option(history)

    search = commands.add_parser(
        "search",
        help="find which registered projects use a package",
        description="List the registered projects whose latest saved scan includes a "
        "package, with the versions found and their status.",
    )
    search.add_argument("package", help="package name, for example requests or @babel/core")
    _data_dir_option(search)

    compare = commands.add_parser(
        "compare",
        help="compare two saved scans of a project",
        description="Compare two saved scans. With no scan numbers, the latest is compared "
        "with the one before it; with one, that scan is compared with the latest.",
    )
    compare.add_argument("name", help="the project's name")
    compare.add_argument("old", type=int, nargs="?", metavar="OLD", help="the older scan")
    compare.add_argument("new", type=int, nargs="?", metavar="NEW", help="the newer scan")
    _data_dir_option(compare)

    cache = commands.add_parser(
        "cache",
        help="show or clear cached advisory data",
        description="Show how much advisory data is cached and how old it is, or clear it. "
        "Online scans always ask OSV for the current advisory list; the cache is what "
        "offline scans, and scans where OSV can't be reached, fall back to.",
    )
    cache_actions = cache.add_subparsers(dest="action", metavar="<action>", required=True)
    info = cache_actions.add_parser("info", help="show what is cached")
    _data_dir_option(info)
    clear = cache_actions.add_parser("clear", help="delete all cached advisory data")
    clear.add_argument("--yes", action="store_true", help="confirm deleting the cache")
    _data_dir_option(clear)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    commands: dict[str, Callable[[argparse.Namespace], int]] = {
        "scan": _scan,
        "project": _project,
        "rescan": _rescan,
        "history": _history,
        "compare": _compare,
        "cache": _cache,
        "search": _search,
    }
    command = commands.get(args.command)
    if command is None:
        parser.print_help()
        return EXIT_CLEAN
    if args.command == "rescan" and args.all and (args.json or args.html):
        parser.error("--json and --html can't be used with --all")
    if args.command == "history":
        if (args.json is not None or args.html is not None) and args.show is None:
            parser.error("--json and --html need --show ID")
        if args.show is not None and args.prune is not None:
            parser.error("--show and --prune can't be used together")
        if args.limit is not None and args.limit < 1:
            parser.error("--limit must be at least 1")
        if args.prune is not None and args.prune < 1:
            parser.error("--prune must keep at least 1 scan")
    _safe_stdout()
    try:
        return command(args)
    except _Failure as failure:
        return _error(str(failure))


def _safe_stdout() -> None:
    """Never crash on a package name the console's encoding can't show."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")


def _error(message: str) -> int:
    print(f"dva: error: {message}", file=sys.stderr)
    return EXIT_ERROR


@contextmanager
def _database(args: argparse.Namespace, purpose: str) -> Iterator[sqlite3.Connection]:
    data_dir = args.data_dir if args.data_dir is not None else default_data_dir()
    try:
        database = open_database(data_dir / DATABASE_NAME)
    except (DatabaseError, OSError) as error:
        message = str(error) if isinstance(error, DatabaseError) else "can't create it"
        raise _Failure(f"the {purpose} couldn't be opened: {message}") from None
    try:
        yield database
    except HistoryError as error:
        raise _Failure(str(error)) from None
    except sqlite3.Error:
        raise _Failure(
            f"the {purpose} couldn't be used: it may be in use by another DVA command, or damaged"
        ) from None
    finally:
        database.close()


def _checker(
    args: argparse.Namespace, database: sqlite3.Connection
) -> Callable[[ScanResult], ScanResult] | None:
    if args.no_vulnerabilities:
        return None
    source = OsvSource(UrllibTransport())
    cache = SqliteAdvisoryCache(database)

    def check(scan: ScanResult) -> ScanResult:
        _progress(args, scan)
        return check_vulnerabilities(
            scan,
            source,
            cache,
            offline=args.offline,
            other_registries=args.include_private_registries,
        )

    return check


def _progress(args: argparse.Namespace, scan: ScanResult) -> None:
    """Say what DVA is waiting on, when someone is watching the terminal."""
    isatty = getattr(sys.stderr, "isatty", None)
    if args.quiet or args.offline or isatty is None or not isatty():
        return
    identities = [p.identity for m in scan.manifests for p in m.packages]
    identities += [r.identity for m in scan.manifests for r in m.requirements]
    names = {(i.ecosystem, i.namespace, i.name) for i in identities}
    if names:
        print(f"Looking up {len(names)} package(s) in OSV...", file=sys.stderr, flush=True)


def _to_stdout(path: Path | None) -> bool:
    return path is not None and str(path) == "-"


def _write_reports(args: argparse.Namespace, scan: ScanResult) -> None:
    for path, render in ((args.json, render_json), (args.html, render_html)):
        if path is None:
            continue
        if _to_stdout(path):
            # Escape non-ASCII on the screen, as for saved reports: same JSON data.
            text = json.dumps(json.loads(render(scan)), ensure_ascii=True, indent=2)
            sys.stdout.write(text + "\n")
            continue
        try:
            path.write_text(render(scan), encoding="utf-8")
        except OSError:
            raise _Failure(f"couldn't write {str(path)!r}") from None


def _print_summary(args: argparse.Namespace, scan: ScanResult) -> None:
    if _to_stdout(args.json):
        return  # The JSON report is the output.
    style = Style(colour_wanted(args.color))
    sys.stdout.write(render_brief(scan, style) if args.brief else render_text(scan, style))
    for label, path in (("JSON report", args.json), ("HTML report", args.html)):
        if path is not None:
            print(f"{label}: {path}")


def _scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    try:
        scan = analyze_project(root, default_registry(), exclude=args.exclude)
    except InvalidProjectRootError:
        return _error(f"{args.path!r} is not a folder")
    except ValueError as error:
        return _error(str(error))
    try:
        acceptances = _file_acceptances(args)
    except _Failure as failure:
        return _error(str(failure))

    if not args.no_vulnerabilities:
        with _database(args, "advisory cache") as database:
            check = _checker(args, database)
            if check is not None:
                scan = apply_acceptances(check(scan), acceptances, _today())

    _write_reports(args, scan)
    if not args.quiet:
        _print_summary(args, scan)
    return exit_code(scan)


def _store(database: sqlite3.Connection) -> SqliteHistoryStore:
    return SqliteHistoryStore(database)


def _find(store: SqliteHistoryStore, name: str) -> Project:
    project = store.project(name)
    if project is None:
        raise _Failure(f"no project is registered as {clean_text(name)!r} (see: dva project list)")
    return project


def _project(args: argparse.Namespace) -> int:
    with _database(args, "DVA database") as database:
        store = _store(database)
        if args.action == "add":
            try:
                project = register_project(store, Path(args.path), args.name, excludes=args.exclude)
            except ProjectRootError as error:
                raise _Failure(f"{args.path!r}: {error}") from None
            except ValueError as error:
                raise _Failure(str(error)) from None
            print(f"Registered {clean_text(project.name)!r} ({clean_text(str(project.root))}).")
            if project.excludes:
                print(f"Rescans skip: {', '.join(clean_text(p) for p in project.excludes)}")
            print(f"Scan it with: dva rescan {clean_text(project.name)}")
        elif args.action == "accept":
            _accept(args, store, _find(store, args.name))
        elif args.action == "exclude":
            project = _find(store, args.name)
            if args.paths or args.clear:
                kept = () if args.clear else project.excludes
                try:
                    project = set_project_excludes(store, project, (*kept, *args.paths))
                except ValueError as error:
                    raise _Failure(str(error)) from None
            name = clean_text(project.name)
            if project.excludes:
                skipped = ", ".join(clean_text(p) for p in project.excludes)
                print(f"Rescans of {name!r} skip: {skipped}")
            else:
                print(f"Rescans of {name!r} skip nothing beyond DVA's usual folders.")
        elif args.action == "list":
            rows = []
            for project in store.projects():
                latest = store.scans(project.id, limit=1)
                rows.append((project, latest[0] if latest else None))
            sys.stdout.write(render_projects(rows))
        else:
            project = _find(store, args.name)
            count = len(store.scans(project.id))
            name = clean_text(project.name)
            if not args.yes:
                raise _Failure(
                    f"this would unregister {name!r} and delete its {count} saved scan(s); "
                    "run again with --yes to do it"
                )
            store.remove_project(project.id)
            print(f"Removed {name!r} and its {count} saved scan(s). Its folder wasn't touched.")
    return EXIT_CLEAN


def _accept(args: argparse.Namespace, store: SqliteHistoryStore, project: Project) -> None:
    name = clean_text(project.name)
    if args.list or args.advisory is None:
        accepted = store.acceptances(project.id)
        if not accepted:
            print(f"{name!r} has no accepted risks.")
        for item in accepted:
            scope = f" for {clean_text(item.package)}" if item.package else ""
            ends = f", until {item.until}" if item.until else ""
            print(f"  {clean_text(item.advisory)}{scope}{ends}: {clean_text(item.reason)}")
        return
    if args.remove:
        removed = store.unaccept(project.id, args.advisory, args.package)
        print(f"Removed {removed} accepted risk(s) from {name!r}.")
        return
    if not args.reason:
        raise _Failure("accepting a risk needs --reason")
    try:
        until = date.fromisoformat(args.until) if args.until else None
        acceptance = Acceptance(args.advisory, args.reason, args.package, until)
    except ValueError as error:
        raise _Failure(f"can't accept that: {error}") from None
    store.accept(project.id, acceptance, datetime.now(UTC))
    print(f"Accepted {clean_text(acceptance.advisory)} for {name!r}; rescans will mark it.")


def _file_acceptances(args: argparse.Namespace) -> tuple[Acceptance, ...]:
    if args.accept_file is None:
        return ()
    try:
        return read_acceptance_file(args.accept_file)
    except AcceptanceFileError as error:
        raise _Failure(f"{str(args.accept_file)!r}: {error}") from None


def _today() -> date:
    return datetime.now(UTC).date()


def _with_acceptances(
    check: Callable[[ScanResult], ScanResult] | None, accepted: Sequence[Acceptance]
) -> Callable[[ScanResult], ScanResult] | None:
    """The vulnerability check followed by marking accepted risks."""
    if check is None or not accepted:
        return check
    inner = check
    return lambda scan: apply_acceptances(inner(scan), accepted, _today())


def _rescan(args: argparse.Namespace) -> int:
    with _database(args, "DVA database") as database:
        store = _store(database)
        projects = store.projects() if args.all else (_find(store, args.name),)
        if not projects:
            raise _Failure("no projects are registered (see: dva project add)")
        check = _checker(args, database)
        from_file = _file_acceptances(args)
        codes = []
        for project in projects:
            if args.all and not args.quiet:
                print(f"=== {clean_text(project.name)} ===")
            accepted = (*store.acceptances(project.id), *from_file)
            checked = _with_acceptances(check, accepted)
            codes.append(_rescan_one(args, store, project, checked))
            if args.all and not args.quiet:
                print()
    return next(code for code in _SEVERITY if code in codes)


def _rescan_one(
    args: argparse.Namespace,
    store: SqliteHistoryStore,
    project: Project,
    check: Callable[[ScanResult], ScanResult] | None,
) -> int:
    try:
        result = rescan_project(
            store,
            project,
            default_registry(),
            render_report=render_json,
            check=check,
            extra_excludes=args.exclude,
        )
    except InvalidProjectRootError:
        return _error(
            f"the folder registered for {clean_text(project.name)!r} can't be read "
            f"({clean_text(str(project.root))}); it may have been moved or deleted"
        )
    except ValueError as error:  # An unusable --exclude pattern.
        return _error(str(error))
    _write_reports(args, result.scan)
    if not args.quiet:
        _print_summary(args, result.scan)
        # With --json -, standard output holds only the JSON report.
        notes = sys.stderr if _to_stdout(args.json) else sys.stdout
        print(f"Saved as scan #{result.record.id} of {clean_text(project.name)!r}.", file=notes)
        if result.comparison is not None:
            print(summary_line(project, result.comparison), file=notes)
    return exit_code(result.scan)


def _history(args: argparse.Namespace) -> int:
    with _database(args, "DVA database") as database:
        store = _store(database)
        project = _find(store, args.name)
        if args.prune is not None:
            return _prune(args, store, project)
        if args.show is None:
            sys.stdout.write(render_history(project, store.scans(project.id, args.limit)))
            return EXIT_CLEAN
        report = store.report(project.id, args.show)
    if report is None:
        raise _Failure(f"{clean_text(project.name)!r} has no saved scan #{args.show}")
    saved = _saved_scan(report, args.show)  # Refuse a damaged report before exporting it.
    if args.json is None and args.html is None:
        # On the screen, escape everything outside ASCII as \u sequences, so text
        # from a scanned file or an advisory can't carry terminal control codes.
        # It's the same JSON data; files get the saved report byte for byte.
        sys.stdout.write(json.dumps(json.loads(report), ensure_ascii=True, indent=2) + "\n")
        return EXIT_CLEAN
    outputs: list[tuple[str, Path, Callable[[], str]]] = []
    if args.json is not None:
        outputs.append(("JSON", args.json, lambda: report))
    if args.html is not None:
        outputs.append(("HTML", args.html, lambda: render_html(saved)))
    for label, path, render in outputs:
        try:
            path.write_text(render(), encoding="utf-8")
        except OSError:
            raise _Failure(f"couldn't write {str(path)!r}") from None
        print(f"{label} report of scan #{args.show}: {path}")
    return EXIT_CLEAN


def _saved_scan(report: str, scan_id: int) -> ScanResult:
    try:
        return loads_scan(report)
    except ReportFormatError:
        raise _Failure(f"saved scan #{scan_id} is damaged and can't be read") from None


def _prune(args: argparse.Namespace, store: SqliteHistoryStore, project: Project) -> int:
    count = len(store.scans(project.id))
    doomed = max(0, count - args.prune)
    name = clean_text(project.name)
    if doomed and not args.yes:
        raise _Failure(
            f"this would delete {doomed} of {name!r}'s {count} saved scan(s), keeping the "
            f"newest {args.prune}; run again with --yes to do it"
        )
    deleted = store.prune(project.id, args.prune)
    print(f"Deleted {deleted} saved scan(s) of {name!r}; {count - deleted} kept.")
    return EXIT_CLEAN


def _search(args: argparse.Namespace) -> int:
    with _database(args, "DVA database") as database:
        found = find_package(_store(database), args.package)
    sys.stdout.write(render_search(args.package, found))
    return EXIT_CLEAN


def _compare(args: argparse.Namespace) -> int:
    with _database(args, "DVA database") as database:
        store = _store(database)
        project = _find(store, args.name)
        comparison = compare_scans(store, project, args.old, args.new)
    sys.stdout.write(render_comparison(project, comparison))
    return EXIT_AFFECTED if comparison.reports_more else EXIT_CLEAN


def _cache(args: argparse.Namespace) -> int:
    with _database(args, "advisory cache") as database:
        if args.action == "info":
            summary = summarize_cache(database)
            print(
                f"Cached advisory data: {summary.packages} package lookup(s), "
                f"{summary.advisories} advisory record(s)."
            )
            if summary.oldest is not None and summary.newest is not None:
                print(f"Oldest lookup: {_when(summary.oldest)}")
                print(f"Newest lookup: {_when(summary.newest)}")
            return EXIT_CLEAN
        if not args.yes:
            raise _Failure("this would delete all cached advisory data; run again with --yes")
        before = clear_cache(database)
    print(
        f"Deleted {before.packages} package lookup(s) and {before.advisories} advisory "
        "record(s). Saved scans were kept. Offline scans have no data until the next "
        "online scan."
    )
    return EXIT_CLEAN


def _when(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC")


def exit_code(scan: ScanResult) -> int:
    report = scan.vulnerabilities
    if report is not None and any(unaccepted(c) for c in report.checks):
        return EXIT_AFFECTED
    incomplete = scan.completion not in (
        CompletionState.COMPLETE,
        CompletionState.NO_SUPPORTED_FILES,
    ) or scan.vulnerability_status in (VulnerabilityStatus.PARTIAL, VulnerabilityStatus.FAILED)
    return EXIT_INCOMPLETE if incomplete else EXIT_CLEAN
