# Roadmap

This is the order the work is planned in. Plans change as the project
develops, so treat it as a guide, not a schedule.

## Done

**Project setup.** The repository, Python packaging, test and lint tooling,
and CI on Windows and Linux.

**The core engine.** The data model for packages, dependencies, dependency
files and scans; the interface ecosystem adapters implement and the registry
they're listed in; safe discovery of dependency files with limits on depth,
file count and file size; and stable JSON output, so the same scan always
produces the same result. Tests show that a new adapter can be plugged in
without changing the engine.

**Python and npm support.** Parsers for Python's `requirements.txt` files,
`pyproject.toml`, `uv.lock` and `poetry.lock`, and for npm's `package.json`,
`package-lock.json` and `npm-shrinkwrap.json`, including direct and transitive
dependencies. Each format has its own test files, including malformed and
deliberately hostile ones. The details are in
[Supported formats](SUPPORTED_FORMATS.md).

**Vulnerability lookups.** The data model for advisories and findings,
designed against real OSV records; looking packages up in OSV by name;
caching advisories in SQLite and working offline from the cache; and matching
installed versions against affected ranges using each ecosystem's own version
rules.

**Output.** The `dva scan` command with a terminal summary and exit codes for
scripts, a versioned JSON report, and a standalone HTML report with an
interactive dependency graph.

**Projects and history.** Registering projects, rescanning them, keeping every
scan as a snapshot in SQLite, listing a project's history, and comparing two
scans. Described in [Projects and scan history](HISTORY.md).

**Release preparation.** A security review of the whole tool, CI that builds
the wheel and source archive on Windows and Linux, checks their contents and
runs the installed command, install instructions, and one page listing the
[limitations](LIMITATIONS.md).

## Next

**First release.** Tagging and publishing a release from the prepared code.
Publishing to PyPI comes later.

## After the first release

**A desktop application.** A graphical app that becomes the main way to use
DVA: register projects, run scans, browse results and the dependency graph,
and compare scans, without a terminal. It will ship as a standalone Windows
application with its own installer, so it doesn't need Python or a package
manager installed. It calls the same engine as the command line, which stays
available for scripts and CI. The UI toolkit and packaging tool will be chosen
when this work starts.

**More ecosystems.** Maven and Gradle first, which also covers Java libraries
published by vendors such as Oracle. Then others based on demand: Rust
(Cargo), Go modules, NuGet, C/C++ package managers such as Conan and vcpkg,
and LuaRocks.

## Later

- Downloading vulnerability data in bulk for fully offline use.
- More lockfiles for the ecosystems already supported: Yarn, pnpm and Bun for
  JavaScript, and `Pipfile.lock` and `pylock.toml` for Python.
- Better handling of monorepos and optional or platform-specific dependencies.
- Possibly a VS Code extension.

Some things aren't planned: changing project files automatically, cloud sync,
and AI-written vulnerability summaries.
