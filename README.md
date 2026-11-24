# DVA: Dependency Vulnerability Analysis

DVA is an open-source tool that reads a project's dependency files, works out
which packages and versions the project uses, and checks them against public
vulnerability advisories. Everything runs on your own machine.

## Status

DVA is in early development. The engine can find and read a project's Python
dependency files (`requirements.txt` files, `pyproject.toml`, `uv.lock` and
`poetry.lock`) and npm dependency files (`package.json`, `package-lock.json`
and `npm-shrinkwrap.json`), including the full dependency tree from a
lockfile. It checks the exact versions it finds against
[OSV](https://osv.dev), keeps the advisory data in a local cache, and falls
back to that cache when you're offline. Results come as a terminal summary,
a JSON report and an HTML report with an interactive dependency graph.
Projects can be registered and rescanned, with every scan kept in a local
history that can be compared. See
[Supported formats](docs/SUPPORTED_FORMATS.md) for exactly what is read.

## Install

You need Python 3.12 or newer. DVA isn't on PyPI yet (when it is, the package
will be called `dvanalysis`, since `dva` is taken), so install it straight
from GitHub with [uv](https://docs.astral.sh/uv/) or
[pipx](https://pipx.pypa.io/), which put the `dva` command on your PATH in
its own environment:

```powershell
uv tool install git+https://github.com/nthin9/DVA
# or
pipx install git+https://github.com/nthin9/DVA
```

To install a particular release instead of the latest code, add its tag,
for example `git+https://github.com/nthin9/DVA@v0.0.1`. Each release on
GitHub also has a wheel file attached, which `uv tool install` or
`pipx install` can install directly.

Check that it works with `dva --version`. If the command isn't found, the
tool folder isn't on your PATH yet: run `uv tool update-shell` (or
`pipx ensurepath`) and open a new terminal.

To update later, run `uv tool upgrade dvanalysis` (or
`pipx upgrade dvanalysis`). To remove it, run `uv tool uninstall dvanalysis`
(or `pipx uninstall dvanalysis`). Your registered projects, scan history and
advisory cache stay in your data folder (`%LOCALAPPDATA%\DVA` on Windows)
until you delete that folder.

## Usage

```powershell
dva scan                       # scan the current folder
dva scan C:\code\myapp        # scan another folder
dva scan --html report.html --json report.json
dva scan --json - > report.json  # print the JSON report instead of the summary
dva scan --brief               # one line per affected package, most severe first
dva scan --offline             # use only advisory data cached by earlier scans
dva scan --no-vulnerabilities  # list dependencies without checking advisories
dva scan --exclude tests/fixtures  # skip a folder (repeatable; */examples works too)
dva cache info                 # how much advisory data is cached, and how old
dva cache clear --yes          # delete the cached advisory data
```

Packages from a private or alternative registry aren't looked up by default,
because their names may be private; add `--include-private-registries` to
check them too.

The summary lists every affected package, most severe first by the
database's own rating, with the advisory's ID, aliases (such as the CVE),
severity as published, and the fixed version when the advisory gives one. It
also lists every package that couldn't be checked, and why. For each
affected package it suggests the lowest fixed version that clears every
advisory OSV lists for it (only versions the advisories name), and for an
indirect dependency it shows which direct dependency pulls it in. On a terminal the
summary is coloured; `--color never` (or the `NO_COLOR` environment variable)
turns that off. The HTML report is a single file that works offline. The JSON report
is described in [Report format](docs/REPORT_FORMAT.md).

The exit code tells scripts what happened:

| Code | Meaning |
|---|---|
| 0 | Nothing affected, and everything was checked |
| 1 | At least one package is affected (accepted risks don't count) |
| 3 | Nothing affected was found, but something couldn't be read or checked |
| 4 | The scan couldn't run, for example because the folder doesn't exist |
| 2 | Invalid command-line arguments |

To follow a project over time, register it once and rescan it whenever you
like. Each rescan is saved, and `dva compare` shows what changed between two
scans: packages added, removed or upgraded, and advisories that appeared or
are no longer reported. See [Projects and scan history](docs/HISTORY.md).

```powershell
dva project add C:\code\myapp
dva rescan myapp
dva compare myapp
```

Advisory data and scan history are kept in `%LOCALAPPDATA%\DVA` on Windows (elsewhere, see
[Architecture](docs/ARCHITECTURE.md#storage)). Use `--data-dir` or the
`DVA_DATA_DIR` environment variable to put them somewhere else.

## What it will do

The first release is aimed at Python and npm projects on Windows (Linux and
macOS should work too, but Windows is the main target).

- Find the dependency files in a project, such as `requirements.txt`,
  `pyproject.toml`, `package.json` and `package-lock.json`. The exact list of
  supported formats is in [Supported formats](docs/SUPPORTED_FORMATS.md) and
  grows as each one is implemented and tested.
- Tell apart the dependencies you declared yourself from the ones they pull in,
  and show the path that leads to each one.
- Look up the exact versions in [OSV](https://osv.dev), keep a local cache, and
  fall back to that cache when you're offline.
- Show what each advisory says: its ID and aliases (CVE when there is one),
  which versions are affected, severity, references, and a fixed version if the
  advisory gives one.
- Keep a history of scans in a local SQLite database so you can compare a
  project over time.
- Export a JSON report and a standalone HTML dependency graph that works offline.

## What it won't do

- Run anything from the project it scans. No install scripts, no build steps,
  no `pip install` or `npm install`.
- Upload your code. The only thing sent to OSV is the ecosystem and name of
  each package being looked up. Not even the version is sent: DVA fetches the
  advisories for a package and checks the version on your machine. Packages
  from private registries aren't looked up unless you ask.
- Collect telemetry.
- Change your dependency files or upgrade packages for you.
- Tell you a project is "safe". A scan reports what it found, what it couldn't
  check, and how old its data is. If no advisory matches, that means OSV had
  nothing on that version at the time, not that the package has no problems.

## Documentation

- [Architecture](docs/ARCHITECTURE.md): how the code is organised and how a scan works
- [Supported formats](docs/SUPPORTED_FORMATS.md): which dependency files DVA reads, and how fully
- [Report format](docs/REPORT_FORMAT.md): the fields of the JSON report
- [Projects and scan history](docs/HISTORY.md): registering, rescanning and comparing
- [Roadmap](docs/ROADMAP.md): what's planned and in what order
- [Threat model](docs/THREAT_MODEL.md): what DVA defends against and its known limits
- [Limitations](docs/LIMITATIONS.md): everything DVA doesn't do yet, in one place
- [Design decisions](docs/DECISIONS.md): the main choices and why they were made

## Development setup

You need Python 3.12 or newer and [uv](https://docs.astral.sh/uv/).

```powershell
uv sync              # create .venv and install the locked dev tools
uv run pytest        # run the tests (offline)
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run dva --version
uv run dva scan .
```

If you installed uv with `pip install --user uv` and it isn't on your PATH,
use `python -m uv` instead of `uv`.

Tests that talk to real online services are skipped by default. Run them with
`uv run pytest -m live`.

## License

Apache License 2.0. See [LICENSE](LICENSE).
