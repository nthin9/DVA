# DVA: Dependency Vulnerability Analysis

DVA is an open-source tool that reads a project's dependency files, works out
which packages and versions the project uses, and checks them against public
vulnerability advisories. Everything runs on your own machine.

## Status

DVA is in early development. The engine can find and read a project's Python
dependency files (`requirements.txt` files, `pyproject.toml`, `uv.lock` and
`poetry.lock`) and npm dependency files (`package.json`, `package-lock.json`
and `npm-shrinkwrap.json`), including the full dependency tree from a
lockfile. It doesn't look up vulnerabilities yet. See [Supported formats](docs/SUPPORTED_FORMATS.md) for exactly what is
read. The CLI only prints its version (`dva --version`) for now.

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
- Upload your code. The only thing sent to OSV is the package name, ecosystem
  and version being looked up.
- Collect telemetry.
- Change your dependency files or upgrade packages for you.
- Tell you a project is "safe". A scan reports what it found, what it couldn't
  check, and how old its data is. If no advisory matches, that means OSV had
  nothing on that version at the time, not that the package has no problems.

## Documentation

- [Architecture](docs/ARCHITECTURE.md): how the code is organised and how a scan works
- [Supported formats](docs/SUPPORTED_FORMATS.md): which dependency files DVA reads, and how fully
- [Roadmap](docs/ROADMAP.md): what's planned and in what order
- [Threat model](docs/THREAT_MODEL.md): what DVA defends against and its known limits
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
```

If you installed uv with `pip install --user uv` and it isn't on your PATH,
use `python -m uv` instead of `uv`.

Tests that talk to real online services are skipped by default. Run them with
`uv run pytest -m live`.

## License

Apache License 2.0. See [LICENSE](LICENSE).
