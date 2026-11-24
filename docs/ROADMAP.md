# Roadmap

DVA is built in three stages:

1. **v1.0: a finished command-line tool** for Python and JavaScript projects.
   Everything before it (the 0.x releases) works towards that.
2. **v1.x: more ecosystems**, starting with Java.
3. **v2.0 and v3.0: desktop applications.** v2.0 is a basic graphical front
   end for the same engine. v3.0 is a complete graphical application.

Every milestone below has a list of goals and a definition of done. A
milestone is finished when all of its goals are met, its tests pass on CI,
and the documentation describes what was built.

## Releases

- Until v1.0, each milestone is published as a GitHub pre-release (v0.1.0,
  v0.2.0, ...), with the wheel and source archive attached and checked before
  upload. Nothing is published to PyPI before v1.0.
- Whether v1.0 is also published to PyPI is decided when v1.0 is released.
  The package name would be `dvanalysis`.
- From v1.0 on, version numbers follow semantic versioning. After a command,
  option, exit code or report field is changed or removed, the old form keeps
  working with a warning for one minor version.

## Done

These are on `main`; v0.0.1 was published as a pre-release on GitHub.

- **Engine.** The data model, the adapter interface and registry, safe
  discovery of dependency files (limits on depth, file count and size; no
  symlinks), and deterministic JSON output.
- **Python and npm.** `requirements*.txt` files (with `-r` includes and `-c`
  constraints), `pyproject.toml` (standard tables and Poetry's), `uv.lock`,
  `poetry.lock`, `package.json`, `package-lock.json` and
  `npm-shrinkwrap.json`. Details in [Supported formats](SUPPORTED_FORMATS.md).
- **Vulnerability checks.** OSV lookups by package name, parallel downloads,
  a local cache with offline use, and version matching with each ecosystem's
  own rules. Packages from private registries aren't looked up unless allowed.
- **Reports.** A terminal summary ordered by severity, a brief mode, colour,
  a versioned JSON report and a standalone HTML report with a dependency
  graph. Each affected package gets an upgrade suggestion taken from the
  advisories, and indirect packages show what pulls them in.
- **Projects and history.** Registered projects, rescans, saved snapshots,
  comparisons, search across projects, exclusions and accepted risks.
- **CI use.** Exit codes, `--fail-on` severity thresholds, `--json -` for
  piping, accepted-risk files.
- **Release checks.** A security review, and CI that builds and audits the
  wheel and source archive and runs the installed command on Windows and
  Linux.

## v0.1: CLI polish

Make day-to-day use of the command line smooth.

- **A settings file.** Defaults for options such as `--color`, `--fail-on`,
  `--exclude` and `--accept-file`, read from a `config.toml` in DVA's data
  folder or from a file passed with `--config`. Options on the command line
  override it. DVA never reads settings from the scanned project.
- **Shell completion.** `dva completion powershell|bash|zsh` prints a
  completion script for commands, options and registered project names.
- **Help with examples.** Every command's `--help` ends with two or three
  examples. Errors say what to do next; for example, an unknown project name
  suggests the closest registered names.
- **Data age policy.** Cached advisory data older than 7 days is flagged in
  every report. `--max-age DAYS` treats older cached data as missing, so that
  package is reported as not checked instead of being checked against old
  data.
- **Comparisons and accepted risks.** Saved scans record which findings were
  accepted, and `dva compare` shows findings that became accepted or whose
  acceptance expired between two scans.
- **Large projects.** The summary stays readable with 1,000 or more
  packages: lists are grouped and capped, and `--show-all` prints everything.
  Analysing a lockfile with 5,000 packages, not counting network time, takes
  under 5 seconds on a typical laptop. A benchmark test checks this.

**Done when:** every item above is implemented and tested, the README and the
other docs show the new options, and v0.1.0 is published on GitHub.

## v0.2: Private registries, target environments and monorepos

Make results match how the project is really installed.

- **Registry settings.** Read where packages come from in
  `.npmrc` (including per-scope registries such as `@corp:registry=`),
  `pip.conf` / `pip.ini`, `[tool.uv.index]` and PDM's `[[tool.pdm.source]]`.
  Packages from a private registry are then kept private like those found
  today. `--extra-index-url`, which mixes PyPI with another index, is
  reported as ambiguous instead of being treated as PyPI. Credentials in
  these files are never stored, printed or sent.
- **Target environment.** `--python 3.12 --platform windows|linux|macos`
  evaluates platform conditions (PEP 508 markers, and npm's `os` and `cpu`
  fields). Dependencies that wouldn't be installed on that target are listed
  as "not installed on this target" instead of being checked. Without these
  options, behaviour stays as it is today.
- **Monorepos.** Results are grouped per workspace member for npm workspaces
  and uv workspaces, in the terminal summary and the reports.

**Done when:** each settings file and workspace layout has test fixtures,
including hostile ones; a test shows that private package names are never
sent to OSV by default; and v0.2.0 is published on GitHub.

## v0.3: Complete Python and JavaScript lockfiles

Read every lockfile that is listed today as "recognised, not read".

- `Pipfile.lock` and `pylock.toml` (PEP 751) for Python.
- `yarn.lock` (Yarn 1 and Yarn 2 and later), `pnpm-lock.yaml` (lockfile
  versions 6 to 9) and `bun.lock` (the text format) for JavaScript.
- `pnpm-lock.yaml` needs a YAML parser. A safe one is chosen and reviewed as
  a new dependency before this work starts.
- Still not read, on purpose: `bun.lockb` (a binary format Bun has replaced),
  `setup.py` (a program) and `setup.cfg`.

**Done when:** each format is moved to "read" in
[Supported formats](SUPPORTED_FORMATS.md), each has fixtures including
malformed and hostile files, and v0.3.0 is published on GitHub.

## v0.4: Full offline mode

Allow complete scans on machines without internet access.

- `dva data download [ECOSYSTEM ...]` downloads OSV's bulk export for each
  ecosystem over HTTPS, with size limits, and checks it before use.
  `dva data status` shows what is downloaded and how old it is.
- `--offline` then works even on a machine that has never run an online
  scan, and reports show the age of the downloaded data.

**Done when:** an offline scan of the test projects using downloaded data
gives the same results as an online scan of the same data, and v0.4.0 is
published on GitHub.

## v1.0: Stable command-line tool

Turn the 0.x releases into a tool people can rely on in scripts and CI.

- **Stable interface.** Commands, options, exit codes and the
  `dva.report/1` JSON format are declared stable. A JSON Schema for the
  report is published, and tests check that every report matches it.
- **Security.** A new review of the whole tool, and fuzz tests for every
  file parser.
- **Platforms.** CI runs the full test suite on Windows, Linux and macOS.
- **User guide.** One page for each common task: first scan, CI setup,
  private registries, accepted risks, offline use and history.

**Done when:** there are no open high-severity issues, all of the above is
in place, v1.0.0 is published on GitHub, and the decision on PyPI publishing
has been made.

## v1.1: Java (Maven and Gradle)

The first new ecosystem, also covering Java libraries published by vendors
such as Oracle as ordinary Maven packages.

- `pom.xml`, parsed without resolving external entities or DTDs. Properties
  defined in the file are filled in. Parent POMs are followed only when they
  are inside the project; a parent that would have to be downloaded is
  reported as unresolved instead.
- `gradle.lockfile` and Gradle version catalogs (`libs.versions.toml`).
  `build.gradle` and `build.gradle.kts` are programs and are never run, so
  they are listed as unsupported.
- Maven's own version ordering rules, with their own tests.

**Done when:** these formats are read with fixtures including hostile files,
version matching is tested against real Maven advisories, and v1.1.0 is
published on GitHub. After v1.1 the next ecosystem is chosen from Go
modules, Rust (Cargo) and NuGet, based on what Java support taught us, and
the choice is recorded in [Design decisions](DECISIONS.md).

## v2.0: Desktop front end

A basic graphical program, similar in spirit to Zenmap for Nmap: a window
around the same engine the command line uses.

- Choose a folder or a registered project, pick a scan profile (a saved set
  of options such as offline, exclusions, `--fail-on` and accepted risks),
  run the scan and follow its progress.
- See the results as tables (affected, not checked, all packages) with the
  same upgrade suggestions as the terminal, and the dependency graph.
- Browse a project's history and compare two scans.
- Ships as a standalone Windows installer that doesn't need Python.

The UI toolkit hasn't been chosen. It will be chosen with a small prototype
at the start of this milestone. The requirements it must meet are: a Windows
installer without a separate Python install; it works fully offline; its
licence is compatible with Apache-2.0; it can call DVA's Python engine
directly; and it supports keyboard use and screen readers.

**Done when:** everything above works on Windows, the engine code is shared
with the command line rather than copied, and v2.0.0 is published.

## v3.0: Full graphical application

The complete desktop application, built on what v2.0 shows people need.

- A dashboard across all registered projects: which have open findings,
  which packages are affected most often, and how that changes over time.
- Guided fixing: the upgrade suggestions for a project in one place, with the
  accepted risks and their expiry dates.
- A notice when a rescan finds an advisory that wasn't there before.
- A signed installer, and full keyboard and screen-reader support.

**Done when:** all of the above is in place and v3.0.0 is published.

## Not planned

- Changing project files or upgrading packages automatically.
- Running package managers or build tools to resolve dependencies.
- Cloud sync, accounts, or a hosted service.
- Telemetry of any kind.
- AI-written vulnerability summaries.
- A VS Code extension.
